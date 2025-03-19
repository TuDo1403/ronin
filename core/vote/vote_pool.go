package vote

import (
	"container/heap"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
)

const (
	maxFutureVoteAmountPerBlock = 64
	maxFutureVotePerPeer        = 25
	voteBufferForPut            = 256
	// votes in the range (currentBlockNum-256,currentBlockNum+11] will be stored
	lowerLimitOfVoteBlockNumber = 256
	upperLimitOfVoteBlockNumber = 11 // refer to fetcher.maxUncleDist
	chainHeadChanSize           = 10 // chainHeadChanSize is the size of channel listening to ChainHeadEvent.

	fetchCheckFrequency = 1 * time.Millisecond
	fetchRetry          = 500
)

var (
	localCurVotesPqGauge    = metrics.NewRegisteredGauge("curVotesPq/local", nil)
	localFutureVotesPqGauge = metrics.NewRegisteredGauge("futureVotesPq/local", nil)
)

type VoteBox struct {
	blockNumber  uint64
	voteMessages []*voteWithPeer
}

type peerDropFn func(id string)

// voteWithPeer is a wrapper around VoteEnvelop to include peer information
type voteWithPeer struct {
	vote *types.VoteEnvelope
	peer string
}

type VotePool struct {
	chain *core.BlockChain
	mu    sync.RWMutex

	votesFeed event.Feed
	scope     event.SubscriptionScope

	curVotes    map[common.Hash]*VoteBox
	futureVotes map[common.Hash]*VoteBox

	curVotesPq    *votesPriorityQueue
	futureVotesPq *votesPriorityQueue

	chainHeadCh  chan core.ChainHeadEvent
	chainHeadSub event.Subscription

	votesCh chan *voteWithPeer

	engine                   consensus.FastFinalityPoSA
	maxCurVoteAmountPerBlock int

	numFutureVotePerPeer map[string]uint64      // number of queued votes per peer
	lastFutureVoteBlock  map[string]uint64      // last block that peer has future vote
	originatedFrom       map[common.Hash]string // mapping from vote hash to the sender
	justifiedBlockNumber uint64

	dropPeer peerDropFn
}

type votesPriorityQueue []*types.VoteData

func NewVotePool(
	chain *core.BlockChain,
	engine consensus.FastFinalityPoSA,
	maxCurVoteAmountPerBlock int,
	dropPeer peerDropFn,
) *VotePool {
	votePool := &VotePool{
		chain:                    chain,
		curVotes:                 make(map[common.Hash]*VoteBox),
		futureVotes:              make(map[common.Hash]*VoteBox),
		curVotesPq:               &votesPriorityQueue{},
		futureVotesPq:            &votesPriorityQueue{},
		chainHeadCh:              make(chan core.ChainHeadEvent, chainHeadChanSize),
		votesCh:                  make(chan *voteWithPeer, voteBufferForPut),
		engine:                   engine,
		maxCurVoteAmountPerBlock: maxCurVoteAmountPerBlock,
		numFutureVotePerPeer:     make(map[string]uint64),
		lastFutureVoteBlock:      make(map[string]uint64),
		originatedFrom:           make(map[common.Hash]string),
	}

	// Subscribe events from blockchain and start the main event loop.
	votePool.chainHeadSub = votePool.chain.SubscribeChainHeadEvent(votePool.chainHeadCh)

	go votePool.loop()
	return votePool
}

// loop is the vote pool's main even loop, waiting for and reacting to outside blockchain events and votes channel event.
func (pool *VotePool) loop() {
	for {
		select {
		// Handle ChainHeadEvent.
		case ev := <-pool.chainHeadCh:
			if ev.Block != nil {
				latestBlockNumber := ev.Block.NumberU64()
				justifiedBlockNumber, _ := pool.engine.GetJustifiedBlock(pool.chain, ev.Block.NumberU64(), ev.Block.Hash())

				pool.mu.Lock()
				pool.justifiedBlockNumber = justifiedBlockNumber
				pool.prune(latestBlockNumber)
				pool.transferVotesFromFutureToCur(ev.Block.Header())
				pool.mu.Unlock()
			}
		case <-pool.chainHeadSub.Err():
			return

		// Handle votes channel and put the vote into vote pool.
		case vote := <-pool.votesCh:
			if !pool.putIntoVotePool(vote) && pool.dropPeer != nil {
				log.Debug("Invalid finality vote, drop peer", "peer", vote.peer)
				pool.dropPeer(vote.peer)
			}
		}
	}
}

func (pool *VotePool) PutVote(peer string, vote *types.VoteEnvelope) {
	pool.votesCh <- &voteWithPeer{vote: vote, peer: peer}
}

// putIntoVotePool returns false when the vote fails critical verification
// that we need to drop the peer broadcasts the vote
func (pool *VotePool) putIntoVotePool(voteWithPeerInfo *voteWithPeer) bool {
	vote := voteWithPeerInfo.vote
	peer := voteWithPeerInfo.peer

	targetNumber := vote.Data.TargetNumber
	targetHash := vote.Data.TargetHash
	header := pool.chain.CurrentBlock().Header()
	headNumber := header.Number.Uint64()

	// Make sure in the range (currentHeight-lowerLimitOfVoteBlockNumber, currentHeight+upperLimitOfVoteBlockNumber].
	if targetNumber+lowerLimitOfVoteBlockNumber-1 < headNumber || targetNumber > headNumber+upperLimitOfVoteBlockNumber {
		log.Debug("BlockNumber of vote is outside the range of header-256~header+11, will be discarded")
		// The node may be slow to catch up, keep peer connection
		return true
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()

	if targetNumber <= pool.justifiedBlockNumber {
		log.Debug("BlockNumber of vote is older than justified block number")
		// The node may be slow to catch up, keep peer connection
		return true
	}

	voteHash := vote.Hash()
	isFutureVote := false
	if _, ok := pool.originatedFrom[voteHash]; ok {
		log.Debug("Vote pool already contained the same vote", "voteHash", voteHash)
		// We have received the vote from other node,
		// so just keep connection for this peer
		return true
	}

	voteData := &types.VoteData{
		TargetNumber: targetNumber,
		TargetHash:   targetHash,
	}

	var votes map[common.Hash]*VoteBox
	var votesPq *votesPriorityQueue

	voteBlock := pool.chain.GetHeaderByHash(targetHash)
	if voteBlock == nil {
		votes = pool.futureVotes
		votesPq = pool.futureVotesPq
		isFutureVote = true
	} else {
		votes = pool.curVotes
		votesPq = pool.curVotesPq

		// Verify if the vote target number is the same as the vote block number
		if voteBlock.Number != nil && voteBlock.Number.Uint64() != targetNumber {
			return false
		}
	}

	if isFutureVote {
		// As we cannot fully verify the future vote, we need to set a limit of
		// future votes per peer to void be DOSed by peer.
		if pool.numFutureVotePerPeer[peer] >= maxFutureVotePerPeer {
			return false
		}
	}

	if ok := pool.basicVerify(vote, headNumber, votes, isFutureVote, voteHash); !ok {
		return false
	}

	if !isFutureVote {
		// Verify if the vote comes from valid validators based on voteAddress (BLSPublicKey), only verify curVotes here, will verify futureVotes in transfer process.
		if pool.engine.VerifyVote(pool.chain, vote) != nil {
			return false
		}

		// Send vote for handler usage of broadcasting to peers.
		voteEv := core.NewVoteEvent{Vote: vote}
		pool.votesFeed.Send(voteEv)
	}

	pool.putVote(votes, votesPq, voteWithPeerInfo, voteData, voteHash, isFutureVote)
	pool.originatedFrom[voteHash] = peer
	// Update the peer feature vote counter, and its last block for pruning
	if isFutureVote {
		pool.numFutureVotePerPeer[peer]++
		lastBlock := pool.lastFutureVoteBlock[peer]
		if lastBlock < targetNumber {
			pool.lastFutureVoteBlock[peer] = targetNumber
		}
	}
	return true
}

func (pool *VotePool) SubscribeNewVoteEvent(ch chan<- core.NewVoteEvent) event.Subscription {
	return pool.scope.Track(pool.votesFeed.Subscribe(ch))
}

// The vote pool's mutex must already be acquired when calling this function
func (pool *VotePool) putVote(
	m map[common.Hash]*VoteBox,
	votesPq *votesPriorityQueue,
	vote *voteWithPeer,
	voteData *types.VoteData,
	voteHash common.Hash,
	isFutureVote bool,
) {
	targetHash := vote.vote.Data.TargetHash
	targetNumber := vote.vote.Data.TargetNumber

	log.Debug("The vote info to put is:", "voteBlockNumber", targetNumber, "voteBlockHash", targetHash)

	if _, ok := m[targetHash]; !ok {
		// Push into votes priorityQueue if not exist in corresponding votes Map.
		// To be noted: will not put into priorityQueue if exists in map to avoid duplicate element with the same voteData.
		heap.Push(votesPq, voteData)
		voteBox := &VoteBox{
			blockNumber:  targetNumber,
			voteMessages: make([]*voteWithPeer, 0, maxFutureVoteAmountPerBlock),
		}
		m[targetHash] = voteBox

		if isFutureVote {
			localFutureVotesPqGauge.Update(int64(votesPq.Len()))
		} else {
			localCurVotesPqGauge.Update(int64(votesPq.Len()))
		}
	}

	// Put into corresponding votes map.
	m[targetHash].voteMessages = append(m[targetHash].voteMessages, vote)
	log.Debug("VoteHash put into votepool is:", "voteHash", voteHash)
}

// The caller must hold the pool mutex
func (pool *VotePool) transferVotesFromFutureToCur(latestBlockHeader *types.Header) {
	futurePq := pool.futureVotesPq
	latestBlockNumber := latestBlockHeader.Number.Uint64()

	// For vote in the range [,latestBlockNumber-11), transfer to cur if valid.
	for futurePq.Len() > 0 && futurePq.Peek().TargetNumber+upperLimitOfVoteBlockNumber < latestBlockNumber {
		blockHash := futurePq.Peek().TargetHash
		pool.transfer(blockHash)
	}

	// For vote in the range [latestBlockNumber-11,latestBlockNumber], only transfer the vote inside the local fork.
	futurePqBuffer := make([]*types.VoteData, 0)
	for futurePq.Len() > 0 && futurePq.Peek().TargetNumber <= latestBlockNumber {
		blockHash := futurePq.Peek().TargetHash
		header := pool.chain.GetHeaderByHash(blockHash)
		if header == nil {
			// Put into pq buffer used for later put again into futurePq
			futurePqBuffer = append(futurePqBuffer, heap.Pop(futurePq).(*types.VoteData))
			continue
		}
		pool.transfer(blockHash)
	}

	for _, voteData := range futurePqBuffer {
		heap.Push(futurePq, voteData)
	}
}

// The vote pool's mutex must already be acquired when calling this function
func (pool *VotePool) transfer(blockHash common.Hash) {
	curPq, futurePq := pool.curVotesPq, pool.futureVotesPq
	curVotes, futureVotes := pool.curVotes, pool.futureVotes
	voteData := heap.Pop(futurePq)

	defer localFutureVotesPqGauge.Update(int64(futurePq.Len()))

	voteBox, ok := futureVotes[blockHash]
	if !ok {
		return
	}

	validVotes := make([]*voteWithPeer, 0, len(voteBox.voteMessages))
	for _, vote := range voteBox.voteMessages {
		// Verify if the vote comes from valid validators based on voteAddress (BLSPublicKey).
		if pool.engine.VerifyVote(pool.chain, vote.vote) != nil {
			if pool.dropPeer != nil {
				pool.dropPeer(vote.peer)
			}
			continue
		}

		// In the process of transfer, send valid vote to votes channel for handler usage
		voteEv := core.NewVoteEvent{Vote: vote.vote}
		pool.votesFeed.Send(voteEv)
		validVotes = append(validVotes, vote)
	}

	// may len(curVotes[blockHash].voteMessages) extra maxCurVoteAmountPerBlock, but it doesn't matter
	if _, ok := curVotes[blockHash]; !ok {
		heap.Push(curPq, voteData)
		curVotes[blockHash] = &VoteBox{voteBox.blockNumber, validVotes}
		localCurVotesPqGauge.Update(int64(curPq.Len()))
	} else {
		curVotes[blockHash].voteMessages = append(curVotes[blockHash].voteMessages, validVotes...)
	}

	for _, vote := range futureVotes[blockHash].voteMessages {
		peer, ok := pool.originatedFrom[vote.vote.Hash()]
		if !ok {
			log.Debug("Cannot find the sender of vote", "voteHash", vote.vote.Hash())
			continue
		}
		pool.numFutureVotePerPeer[peer]--
	}
	delete(futureVotes, blockHash)
}

func (pool *VotePool) pruneVote(
	latestBlockNumber uint64,
	voteMap map[common.Hash]*VoteBox,
	voteQueue *votesPriorityQueue,
	isFuture bool,
) {
	// delete votes older than or equal to latestBlockNumber-lowerLimitOfVoteBlockNumber or justified block number
	for voteQueue.Len() > 0 {
		vote := voteQueue.Peek()
		if vote.TargetNumber+lowerLimitOfVoteBlockNumber-1 < latestBlockNumber || vote.TargetNumber <= pool.justifiedBlockNumber {
			blockHash := heap.Pop(voteQueue).(*types.VoteData).TargetHash

			if isFuture {
				localFutureVotesPqGauge.Update(int64(voteQueue.Len()))
			} else {
				localCurVotesPqGauge.Update(int64(voteQueue.Len()))
			}

			if voteBox, ok := voteMap[blockHash]; ok {
				voteMessages := voteBox.voteMessages
				for _, voteMessage := range voteMessages {
					voteHash := voteMessage.vote.Hash()
					if peer := pool.originatedFrom[voteHash]; peer != "" && isFuture {
						pool.numFutureVotePerPeer[peer]--
					}
					delete(pool.originatedFrom, voteHash)
				}
				delete(voteMap, blockHash)
			}
		} else {
			break
		}
	}
}

func (pool *VotePool) pruneFutureVoteCounter(latestBlockNumber uint64) {
	// Only keep track of couter for peer has future vote > currentBlockNum-lowerLimitOfVoteBlockNumber
	thresholdBlock := max(int64(latestBlockNumber)-lowerLimitOfVoteBlockNumber, 0)
	for peer, lastBlock := range pool.lastFutureVoteBlock {
		if lastBlock <= uint64(thresholdBlock) {
			log.Debug("Prune future vote counter for peer", "peer", peer,
				"lastBlock", lastBlock, "thresholdBlock", thresholdBlock, "currentBlock", latestBlockNumber)
			delete(pool.numFutureVotePerPeer, peer)
			delete(pool.lastFutureVoteBlock, peer)
		}
	}
}

// Prune old data of curVotes and futureVotes
// The caller must hold the pool mutex
func (pool *VotePool) prune(latestBlockNumber uint64) {
	pool.pruneVote(latestBlockNumber, pool.curVotes, pool.curVotesPq, false)
	pool.pruneVote(latestBlockNumber, pool.futureVotes, pool.futureVotesPq, true)
	pool.pruneFutureVoteCounter(latestBlockNumber)
}

// GetVotes as batch.
func (pool *VotePool) GetVotes() []*types.VoteEnvelope {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	votesRes := make([]*types.VoteEnvelope, 0)
	curVotes := pool.curVotes
	for _, voteBox := range curVotes {
		for _, vote := range voteBox.voteMessages {
			votesRes = append(votesRes, vote.vote)
		}
	}
	return votesRes
}

// FetchVoteByBlockHash reads the finality votes for the provided block hash, the concurrent
// writers may block this function from acquiring the read lock. This function does not sleep
// and wait for acquiring the lock but keep polling the lock fetchRetry times and returns nil
// if it still cannot acquire the lock. This mechanism helps to make this function safer
// because we cannot control the writers and we don't want this function to block the caller.
func (pool *VotePool) FetchVoteByBlockHash(blockHash common.Hash) []*types.VoteEnvelope {
	var retry int
	for retry = 0; retry < fetchRetry; retry++ {
		if !pool.mu.TryRLock() {
			time.Sleep(fetchCheckFrequency)
		} else {
			break
		}
	}

	// We try to acquire read lock fetchRetry times
	// but can not do it, so just return nil here
	if retry == fetchRetry {
		return nil
	}

	// We successfully acquire the read lock, read
	// the vote and remember to release the lock
	defer pool.mu.RUnlock()
	if voteBox, ok := pool.curVotes[blockHash]; ok {
		votes := make([]*types.VoteEnvelope, 0, len(voteBox.voteMessages))
		for _, vote := range voteBox.voteMessages {
			votes = append(votes, vote.vote)
		}

		return votes
	} else {
		return nil
	}
}

func (pool *VotePool) basicVerify(vote *types.VoteEnvelope, headNumber uint64, m map[common.Hash]*VoteBox, isFutureVote bool, voteHash common.Hash) bool {
	targetHash := vote.Data.TargetHash

	// To prevent DOS attacks, make sure no more than 21 votes per blockHash if not futureVotes
	// and no more than 50 votes per blockHash if futureVotes.
	maxVoteAmountPerBlock := pool.maxCurVoteAmountPerBlock
	if isFutureVote {
		maxVoteAmountPerBlock = maxFutureVoteAmountPerBlock
	}
	if voteBox, ok := m[targetHash]; ok {
		if len(voteBox.voteMessages) >= maxVoteAmountPerBlock {
			return false
		}
	}

	// Verify bls signature.
	if err := vote.Verify(); err != nil {
		log.Error("Failed to verify voteMessage", "err", err)
		return false
	}

	return true
}

// stats returns the vote pool's
// - number of current votes
// - length of current vote queue
// - number of future votes
// - length of future vote queue
func (pool *VotePool) stats() (int, int, int, int) {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	return len(pool.curVotes), pool.curVotesPq.Len(), len(pool.futureVotes), pool.futureVotesPq.Len()
}

func (pool *VotePool) peerTrackStats() (int, int) {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	return len(pool.numFutureVotePerPeer), len(pool.lastFutureVoteBlock)
}

func (pool *VotePool) getNumberOfFutureVoteByPeer(peer string) uint64 {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	return pool.numFutureVotePerPeer[peer]
}

func (pq votesPriorityQueue) Less(i, j int) bool {
	return pq[i].TargetNumber < pq[j].TargetNumber
}

func (pq votesPriorityQueue) Len() int {
	return len(pq)
}

func (pq votesPriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *votesPriorityQueue) Push(vote interface{}) {
	curVote := vote.(*types.VoteData)
	*pq = append(*pq, curVote)
}

func (pq *votesPriorityQueue) Pop() interface{} {
	tmp := *pq
	l := len(tmp)
	var res interface{} = tmp[l-1]
	*pq = tmp[:l-1]
	return res
}

func (pq *votesPriorityQueue) Peek() *types.VoteData {
	if pq.Len() == 0 {
		return nil
	}
	return (*pq)[0]
}
