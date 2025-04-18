// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package discover implements the Node Discovery Protocol.
//
// The Node Discovery protocol provides a way to find RLPx nodes that
// can be connected to. It uses a Kademlia-like protocol to maintain a
// distributed database of the IDs and endpoints of all listening
// nodes.
package discover

import (
	"fmt"
	"net"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

const (
	alpha                  = 3               // Kademlia concurrency factor
	bucketSize             = 16              // Kademlia bucket size
	maxReplacements        = 10              // Size of per-bucket replacement list
	maxWorkerTask          = 90              // Maximum number of worker tasks
	timeoutWorkerTaskClose = 1 * time.Second // Timeout for waiting workerPoolTask is refill full
	// We keep buckets for the upper 1/15 of distances because
	// it's very unlikely we'll ever encounter a node that's closer.
	hashBits          = len(common.Hash{}) * 8
	nBuckets          = hashBits / 15       // Number of buckets
	bucketMinDistance = hashBits - nBuckets // Log distance of closest bucket

	// IP address limits.
	bucketIPLimit, bucketSubnet = 2, 24 // at most 2 addresses from the same /24
	tableIPLimit, tableSubnet   = 10, 24

	revalidateInterval = 10 * time.Second
	copyNodesInterval  = 30 * time.Second
	seedMinTableTime   = 5 * time.Minute
	seedCount          = 30
	seedMaxAge         = 5 * 24 * time.Hour
)

// Table is the 'node table', a Kademlia-like index of neighbor nodes. The table keeps
// itself up-to-date by verifying the liveness of neighbors and requesting their node
// records when announcements of a new record version are received.
type Table struct {
	mutex        sync.Mutex        // protects buckets, bucket content, nursery, rand
	buckets      [nBuckets]*bucket // index of known nodes by distance
	nursery      []*node           // bootstrap nodes
	rand         reseedingRandom   // source of randomness, periodically reseeded
	ips          netutil.DistinctNetSet
	revalidation tableRevalidation

	log log.Logger
	db  *enode.DB // database of known nodes
	net transport
	cfg Config

	// loop channels
	refreshReq      chan chan struct{}
	revalResponseCh chan revalidationResponse
	addNodeCh       chan addNodeOp
	addNodeHandled  chan bool
	trackRequestCh  chan trackRequestOp
	initDone        chan struct{}
	closeReq        chan struct{}
	closed          chan struct{}
	workerPoolTask  chan struct{}

	nodeAddedHook   func(*bucket, *node)
	nodeRemovedHook func(*bucket, *node)
	enrFilter       NodeFilterFunc
}

// transport is implemented by the UDP transports.
type transport interface {
	Self() *enode.Node
	RequestENR(*enode.Node) (*enode.Node, error)
	lookupRandom() []*enode.Node
	lookupSelf() []*enode.Node
	ping(*enode.Node) (seq uint64, err error)
}

// bucket contains nodes, ordered by their last activity. the entry
// that was most recently active is the first element in entries.
type bucket struct {
	entries      []*node // live entries, sorted by time of last contact
	replacements []*node // recently seen nodes to be used if revalidation fails
	ips          netutil.DistinctNetSet
	index        int
}

type addNodeOp struct {
	node          *node
	isInbound     bool
	syncExecution bool // if true, the operation is executed synchronously, only for Testing.
}

type trackRequestOp struct {
	node       *node
	foundNodes []*node
	success    bool
}

func newTable(t transport, db *enode.DB, cfg Config) (*Table, error) {
	cfg = cfg.withDefaults()
	tab := &Table{
		net:             t,
		db:              db,
		cfg:             cfg,
		log:             cfg.Log,
		refreshReq:      make(chan chan struct{}),
		revalResponseCh: make(chan revalidationResponse),
		addNodeCh:       make(chan addNodeOp),
		addNodeHandled:  make(chan bool),
		trackRequestCh:  make(chan trackRequestOp),
		initDone:        make(chan struct{}),
		closeReq:        make(chan struct{}),
		closed:          make(chan struct{}),
		workerPoolTask:  make(chan struct{}, maxWorkerTask),
		ips:             netutil.DistinctNetSet{Subnet: tableSubnet, Limit: tableIPLimit},
		enrFilter:       cfg.FilterFunction,
	}
	for i := range tab.buckets {
		tab.buckets[i] = &bucket{
			index: i,
			ips:   netutil.DistinctNetSet{Subnet: bucketSubnet, Limit: bucketIPLimit},
		}
	}
	for i := 0; i < maxWorkerTask; i++ {
		tab.workerPoolTask <- struct{}{}
	}

	tab.rand.seed()
	tab.revalidation.init(&cfg)

	// initial table content
	if err := tab.setFallbackNodes(cfg.Bootnodes); err != nil {
		return nil, err
	}
	tab.loadSeedNodes()

	return tab, nil
}

func newMeteredTable(t transport, db *enode.DB, cfg Config) (*Table, error) {
	tab, err := newTable(t, db, cfg)
	if err != nil {
		return nil, err
	}
	if metrics.Enabled {
		tab.nodeAddedHook = func(b *bucket, n *node) {
			bucketsCounter[b.index].Inc(1)
		}
		tab.nodeRemovedHook = func(b *bucket, n *node) {
			bucketsCounter[b.index].Dec(1)
		}
	}
	return tab, nil
}

func (tab *Table) self() *enode.Node {
	return tab.net.Self()
}

// getNode returns the node with the given ID or nil if it isn't in the table.
func (tab *Table) getNode(id enode.ID) *enode.Node {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	b := tab.bucket(id)
	for _, e := range b.entries {
		if e.ID() == id {
			return e.Node
		}
	}
	return nil
}

func (tab *Table) closeWorkerTask() {
	waitTicker := time.NewTicker(1 * time.Millisecond)
	defer waitTicker.Stop()
	timeoutChan := time.After(timeoutWorkerTaskClose)
	for {
		select {
		case <-waitTicker.C:
			if len(tab.workerPoolTask) == cap(tab.workerPoolTask) {
				log.Info("workerPoolTask is refill full, closing channel.")
				return
			}

		case <-timeoutChan:
			log.Warn("Timeout waiting for workerPoolTask is refill full , force exit it.")
			return
		}
	}
}

// close terminates the network listener and flushes the node database.
func (tab *Table) close() {
	close(tab.closeReq)
	<-tab.closed
}

// setFallbackNodes sets the initial points of contact. These nodes
// are used to connect to the network if the table is empty and there
// are no known nodes in the database.
func (tab *Table) setFallbackNodes(nodes []*enode.Node) error {
	nursery := make([]*node, 0, len(nodes))
	for _, n := range nodes {
		if err := n.ValidateComplete(); err != nil {
			return fmt.Errorf("bad bootstrap node %q: %v", n, err)
		}
		if tab.cfg.NetRestrict != nil && !tab.cfg.NetRestrict.Contains(n.IP()) {
			tab.log.Error("Bootstrap node filtered by netrestrict", "id", n.ID(), "ip", n.IP())
			continue
		}
		nursery = append(nursery, wrapNode(n))
	}
	tab.nursery = nursery
	return nil
}

// isInitDone returns whether the table's initial seeding procedure has completed.
func (tab *Table) isInitDone() bool {
	select {
	case <-tab.initDone:
		return true
	default:
		return false
	}
}

func (tab *Table) refresh() <-chan struct{} {
	done := make(chan struct{})
	select {
	case tab.refreshReq <- done:
	case <-tab.closeReq:
		close(done)
	}
	return done
}

func (tab *Table) trackRequest(n *node, success bool, foundNodes []*node) {
	op := trackRequestOp{n, foundNodes, success}
	select {
	case tab.trackRequestCh <- op:
	case <-tab.closeReq:
	}
}

// loop schedules runs of doRefresh, doRevalidate and copyLiveNodes.
func (tab *Table) loop() {
	var (
		refresh         = time.NewTimer(tab.nextRefreshTime())
		refreshDone     = make(chan struct{})           // where doRefresh reports completion
		waiting         = []chan struct{}{tab.initDone} // holds waiting callers while doRefresh runs
		revalTimer      = mclock.NewAlarm(tab.cfg.Clock)
		reseedRandTimer = time.NewTicker(10 * time.Minute)
	)
	defer refresh.Stop()

	// Start initial refresh.
	go tab.doRefresh(refreshDone)

loop:
	for {
		nextTime := tab.revalidation.run(tab, tab.cfg.Clock.Now())
		revalTimer.Schedule(nextTime)

		select {
		case <-reseedRandTimer.C:
			tab.rand.seed()

		case <-revalTimer.C():

		case r := <-tab.revalResponseCh:
			tab.revalidation.handleResponse(tab, r)

		case op := <-tab.addNodeCh:
			// only for testing, syncExecution is true.
			if op.syncExecution {
				ok := tab.handleAddNode(op)
				tab.addNodeHandled <- ok
			} else {
				select {
				case <-tab.workerPoolTask:
					go tab.handleAddNode(op)
				default:
					tab.log.Debug("Worker pool task is full, dropping node", "id", op.node.ID(), "addr", op.node.addr())
				}
			}

		case op := <-tab.trackRequestCh:
			tab.handleTrackRequest(op)

		case <-refresh.C:
			if refreshDone == nil {
				refreshDone = make(chan struct{})
				go tab.doRefresh(refreshDone)
			}

		case req := <-tab.refreshReq:
			waiting = append(waiting, req)
			if refreshDone == nil {
				refreshDone = make(chan struct{})
				go tab.doRefresh(refreshDone)
			}

		case <-refreshDone:
			for _, ch := range waiting {
				close(ch)
			}
			waiting, refreshDone = nil, nil
			refresh.Reset(tab.nextRefreshTime())

		case <-tab.closeReq:
			break loop
		}
	}

	if refreshDone != nil {
		<-refreshDone
	}
	for _, ch := range waiting {
		close(ch)
	}

	tab.closeWorkerTask()
	close(tab.closed)
}

// doRefresh performs a lookup for a random target to keep buckets full. seed nodes are
// inserted if the table is empty (initial bootstrap or discarded faulty peers).
func (tab *Table) doRefresh(done chan struct{}) {
	defer close(done)

	// Load nodes from the database and insert
	// them. This should yield a few previously seen nodes that are
	// (hopefully) still alive.
	tab.loadSeedNodes()

	// Run self lookup to discover new neighbor nodes.
	tab.net.lookupSelf()

	// The Kademlia paper specifies that the bucket refresh should
	// perform a lookup in the least recently used bucket. We cannot
	// adhere to this because the findnode target is a 512bit value
	// (not hash-sized) and it is not easily possible to generate a
	// sha3 preimage that falls into a chosen bucket.
	// We perform a few lookups with a random target instead.
	for i := 0; i < 3; i++ {
		tab.net.lookupRandom()
	}
}

func (tab *Table) loadSeedNodes() {
	seeds := wrapNodes(tab.db.QuerySeeds(seedCount, seedMaxAge))
	seeds = append(seeds, tab.nursery...)
	for i := range seeds {
		seed := seeds[i]
		age := time.Since(tab.db.LastPongReceived(seed.ID(), seed.IP()))
		tab.log.Trace("Found seed node in database", "id", seed.ID(), "addr", seed.addr(), "age", age)

		select {
		case <-tab.workerPoolTask:
			go tab.handleAddNode(addNodeOp{node: seed, isInbound: false})
		default:
			tab.log.Debug("Worker pool task is full, dropping node", "id", seed.ID(), "addr", seed.addr())
		}
	}
}

// findnodeByID returns the n nodes in the table that are closest to the given id.
// This is used by the FINDNODE/v4 handler.
//
// The preferLive parameter says whether the caller wants liveness-checked results. If
// preferLive is true and the table contains any verified nodes, the result will not
// contain unverified nodes. However, if there are no verified nodes at all, the result
// will contain unverified nodes.
func (tab *Table) findnodeByID(target enode.ID, nresults int, preferLive bool) *nodesByDistance {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	// Scan all buckets. There might be a better way to do this, but there aren't that many
	// buckets, so this solution should be fine. The worst-case complexity of this loop
	// is O(tab.len() * nresults).
	nodes := &nodesByDistance{target: target}
	liveNodes := &nodesByDistance{target: target}
	for _, b := range &tab.buckets {
		for _, n := range b.entries {
			nodes.push(n, nresults)
			if preferLive && n.livenessChecks > 0 {
				liveNodes.push(n, nresults)
			}
		}
	}

	if preferLive && len(liveNodes.entries) > 0 {
		return liveNodes
	}
	return nodes
}

// len returns the number of nodes in the table.
func (tab *Table) len() (n int) {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	for _, b := range &tab.buckets {
		n += len(b.entries)
	}
	return n
}

// bucketLen returns the number of nodes in the bucket for the given ID.
func (tab *Table) bucketLen(id enode.ID) int {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	return len(tab.bucket(id).entries)
}

// bucket returns the bucket for the given node ID hash.
func (tab *Table) bucket(id enode.ID) *bucket {
	d := enode.LogDist(tab.self().ID(), id)
	return tab.bucketAtDistance(d)
}

func (tab *Table) bucketAtDistance(d int) *bucket {
	if d <= bucketMinDistance {
		return tab.buckets[0]
	}
	return tab.buckets[d-bucketMinDistance-1]
}

func (tab *Table) filterNode(n *node) bool {
	if tab.enrFilter == nil {
		return false
	}
	if node, err := tab.net.RequestENR(unwrapNode(n)); err != nil {
		tab.log.Debug("ENR request failed", "id", n.ID(), "addr", n.addr(), "err", err)
		return true
	} else if !tab.enrFilter(node.Record()) {
		tab.log.Trace("ENR record filter out", "id", n.ID(), "addr", n.addr())
		return true
	}
	return false
}

func (tab *Table) addIP(b *bucket, ip net.IP) bool {
	if len(ip) == 0 {
		return false // Nodes without IP cannot be added.
	}
	if netutil.IsLAN(ip) {
		return true
	}
	if !tab.ips.Add(ip) {
		tab.log.Debug("IP exceeds table limit", "ip", ip)
		return false
	}
	if !b.ips.Add(ip) {
		tab.log.Debug("IP exceeds bucket limit", "ip", ip)
		tab.ips.Remove(ip)
		return false
	}
	return true
}

func (tab *Table) removeIP(b *bucket, ip net.IP) {
	if netutil.IsLAN(ip) {
		return
	}
	tab.ips.Remove(ip)
	b.ips.Remove(ip)
}

// addFoundNode adds a node which may not be live. If the bucket has space available,
// adding the node succeeds immediately. Otherwise, the node is added to the replacements
// list.
//
// The caller must not hold tab.mutex. For Testing purpose mostly.
func (tab *Table) addFoundNode(n *node) bool {
	op := addNodeOp{node: n, isInbound: false, syncExecution: true}
	select {
	case tab.addNodeCh <- op:
		return <-tab.addNodeHandled
	case <-tab.closeReq:
		return false
	}
}

// addInboundNode adds a node from an inbound contact. If the bucket has no space, the
// node is added to the replacements list.
//
// There is an additional safety measure: if the table is still initializing the node is
// not added. This prevents an attack where the table could be filled by just sending ping
// repeatedly.
//
// The caller must not hold tab.mutex.
func (tab *Table) addInboundNode(n *node) {
	op := addNodeOp{node: n, isInbound: true}
	select {
	case tab.addNodeCh <- op:
		return
	case <-tab.closeReq:
		return
	}
}

// Only for Testing purpose with syncExecution.
func (tab *Table) addInboundNodeSync(n *node) bool {
	op := addNodeOp{node: n, isInbound: true, syncExecution: true}
	select {
	case tab.addNodeCh <- op:
		return <-tab.addNodeHandled
	case <-tab.closeReq:
		return false
	}
}

// handleAddNode adds the node in the request to the table, if there is space.
// The caller must hold tab.mutex.
func (tab *Table) handleAddNode(req addNodeOp) bool {
	defer func() {
		select {
		case tab.workerPoolTask <- struct{}{}:
		default:
			tab.log.Debug("Worker pool task is full, no need to release worker task.")
		}
	}()

	if req.node.ID() == tab.self().ID() {
		return false
	}

	filterEnrTotalCounter.Inc(1)
	// Filter node if ENR not match.
	if tab.filterNode(req.node) {
		filterEnrSuccessCounter.Inc(1)
		return false
	}

	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	// For nodes from inbound contact, there is an additional safety measure: if the table
	// is still initializing the node is not added.
	if req.isInbound && !tab.isInitDone() {
		return false
	}

	b := tab.bucket(req.node.ID())
	n, _ := tab.bumpInBucket(b, req.node.Node, req.isInbound)
	if n != nil {
		// Already in bucket.
		return false
	}
	if len(b.entries) >= bucketSize {
		// Bucket full, maybe add as replacement.
		tab.addReplacement(b, req.node)
		return false
	}
	if !tab.addIP(b, req.node.IP()) {
		// Can't add: IP limit reached.
		return false
	}

	// Add to bucket.
	b.entries = append(b.entries, req.node)
	b.replacements = deleteNode(b.replacements, req.node)
	tab.nodeAdded(b, req.node)
	return true
}

// addReplacement adds n to the replacement cache of bucket b.
func (tab *Table) addReplacement(b *bucket, n *node) {
	if contains(b.replacements, n.ID()) {
		// TODO: update ENR
		return
	}
	if !tab.addIP(b, n.IP()) {
		return
	}

	n.addedToTable = time.Now()
	var removed *node
	b.replacements, removed = pushNode(b.replacements, n, maxReplacements)
	if removed != nil {
		tab.removeIP(b, removed.IP())
	}
}

func (tab *Table) nodeAdded(b *bucket, n *node) {
	if n.addedToTable == (time.Time{}) {
		n.addedToTable = time.Now()
	}
	n.addedToBucket = time.Now()
	tab.revalidation.nodeAdded(tab, n)
	if tab.nodeAddedHook != nil {
		tab.nodeAddedHook(b, n)
	}
	if metrics.Enabled {
		bucketsCounter[b.index].Inc(1)
	}
}

func (tab *Table) nodeRemoved(b *bucket, n *node) {
	tab.revalidation.nodeRemoved(n)
	if tab.nodeRemovedHook != nil {
		tab.nodeRemovedHook(b, n)
	}
	if metrics.Enabled {
		bucketsCounter[b.index].Dec(1)
	}
}

// deleteInBucket removes node n from the table.
// If there are replacement nodes in the bucket, the node is replaced.
func (tab *Table) deleteInBucket(b *bucket, id enode.ID) *node {
	index := slices.IndexFunc(b.entries, func(e *node) bool { return e.ID() == id })
	if index == -1 {
		// Entry has been removed already.
		return nil
	}

	// Remove the node.
	n := b.entries[index]
	b.entries = slices.Delete(b.entries, index, index+1)
	tab.removeIP(b, n.IP())
	tab.nodeRemoved(b, n)

	// Add replacement.
	if len(b.replacements) == 0 {
		tab.log.Debug("Removed dead node", "b", b.index, "id", n.ID(), "ip", n.IP())
		return nil
	}
	rindex := tab.rand.Intn(len(b.replacements))
	rep := b.replacements[rindex]
	b.replacements = slices.Delete(b.replacements, rindex, rindex+1)
	b.entries = append(b.entries, rep)
	tab.nodeAdded(b, rep)
	tab.log.Debug("Replaced dead node", "b", b.index, "id", n.ID(), "ip", n.IP(), "r", rep.ID(), "rip", rep.IP())
	return rep
}

// bumpInBucket updates a node record if it exists in the bucket.
// The second return value reports whether the node's endpoint (IP/port) was updated.
func (tab *Table) bumpInBucket(b *bucket, newRecord *enode.Node, isInbound bool) (n *node, endpointChanged bool) {
	i := slices.IndexFunc(b.entries, func(elem *node) bool {
		return elem.ID() == newRecord.ID()
	})
	if i == -1 {
		return nil, false // not in bucket
	}
	n = b.entries[i]

	// For inbound updates (from the node itself) we accept any change, even if it sets
	// back the sequence number. For found nodes (!isInbound), seq has to advance. Note
	// this check also ensures found discv4 nodes (which always have seq=0) can't be
	// updated.
	if newRecord.Seq() <= n.Seq() && !isInbound {
		return n, false
	}

	// Check endpoint update against IP limits.
	ipchanged := !(net.IP.Equal(newRecord.IP(), n.IP()))
	portchanged := newRecord.UDP() != n.UDP()
	if ipchanged {
		tab.removeIP(b, n.IP())
		if !tab.addIP(b, newRecord.IP()) {
			// It doesn't fit with the limit, put the previous record back.
			tab.addIP(b, n.IP())
			return n, false
		}
	}

	// Apply update.
	n.Node = newRecord
	if ipchanged || portchanged {
		// Ensure node is revalidated quickly for endpoint changes.
		tab.revalidation.nodeEndpointChanged(tab, n)
		return n, true
	}
	return n, false
}

func (tab *Table) handleTrackRequest(op trackRequestOp) {
	var fails int
	if op.success {
		// Reset failure counter because it counts _consecutive_ failures.
		tab.db.UpdateFindFails(op.node.ID(), op.node.IP(), 0)
	} else {
		fails = tab.db.FindFails(op.node.ID(), op.node.IP())
		fails++
		tab.db.UpdateFindFails(op.node.ID(), op.node.IP(), fails)
	}

	tab.mutex.Lock()

	b := tab.bucket(op.node.ID())
	// Remove the node from the local table if it fails to return anything useful too
	// many times, but only if there are enough other nodes in the bucket. This latter
	// condition specifically exists to make bootstrapping in smaller test networks more
	// reliable.
	if fails >= maxFindnodeFailures && len(b.entries) >= bucketSize/4 {
		tab.deleteInBucket(b, op.node.ID())
	}

	// We already hold lock in handleAddNode, so need to unlock it here for avoiding hold lock so much when running handleAddNode.
	tab.mutex.Unlock()

	// Add found nodes.
	for _, n := range op.foundNodes {
		select {
		case <-tab.workerPoolTask:
			go tab.handleAddNode(addNodeOp{n, false, false})
		default:
			tab.log.Debug("Worker pool task is full, dropping node", "id", n.ID(), "addr", n.addr())
		}
	}
}

func (tab *Table) nextRefreshTime() time.Duration {
	half := tab.cfg.RefreshInterval / 2
	return half + time.Duration(tab.rand.Int63n(int64(half)))
}

func contains(ns []*node, id enode.ID) bool {
	for _, n := range ns {
		if n.ID() == id {
			return true
		}
	}
	return false
}

// pushNode adds n to the front of list, keeping at most max items.
func pushNode(list []*node, n *node, max int) ([]*node, *node) {
	if len(list) < max {
		list = append(list, nil)
	}
	removed := list[len(list)-1]
	copy(list[1:], list)
	list[0] = n
	return list, removed
}

// deleteNode removes n from list.
func deleteNode(list []*node, n *node) []*node {
	for i := range list {
		if list[i].ID() == n.ID() {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

// nodesByDistance is a list of nodes, ordered by distance to target.
type nodesByDistance struct {
	entries []*node
	target  enode.ID
}

// push adds the given node to the list, keeping the total size below maxElems.
func (h *nodesByDistance) push(n *node, maxElems int) {
	ix := sort.Search(len(h.entries), func(i int) bool {
		return enode.DistCmp(h.target, h.entries[i].ID(), n.ID()) > 0
	})

	end := len(h.entries)
	if len(h.entries) < maxElems {
		h.entries = append(h.entries, n)
	}
	if ix < end {
		// Slide existing entries down to make room.
		// This will overwrite the entry we just appended.
		copy(h.entries[ix+1:], h.entries[ix:])
		h.entries[ix] = n
	}
}
