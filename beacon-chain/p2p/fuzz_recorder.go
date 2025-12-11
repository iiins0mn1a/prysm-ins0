package p2p

import (
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// RecordedMessage captures the minimal information required to
// later re-use or mutate an outgoing message to a peer.
type RecordedMessage struct {
	PeerID peer.ID
	// Category is a logical label for the message type, aligned with
	// the groupings defined in LOKI-POS.md (e.g. BeaconBlocksByRangeReqMsgs,
	// AttestationsMsgs, BlobSidecarMsgs, etc.).
	Category string
	// Topic is the low-level RPC or gossip topic (for RPC it is the
	// baseTopic, for gossip it is the pubsub topic string).
	Topic     string
	Message   interface{}
	Timestamp time.Time
}

// peerMessageBuffer is a fixed-size ring buffer for messages
// associated with a single peer.
type peerMessageBuffer struct {
	mu      sync.RWMutex
	buf     []RecordedMessage
	cap     int
	nextIdx int
	full    bool
}

func newPeerMessageBuffer(capacity int) *peerMessageBuffer {
	return &peerMessageBuffer{
		buf: make([]RecordedMessage, capacity),
		cap: capacity,
	}
}

func (b *peerMessageBuffer) append(msg RecordedMessage) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.buf[b.nextIdx] = msg
	b.nextIdx++
	if b.nextIdx >= b.cap {
		b.nextIdx = 0
		b.full = true
	}
}

func (b *peerMessageBuffer) snapshot() []RecordedMessage {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if !b.full {
		out := make([]RecordedMessage, b.nextIdx)
		copy(out, b.buf[:b.nextIdx])
		return out
	}

	out := make([]RecordedMessage, b.cap)
	// Oldest element is at nextIdx when buffer is full.
	copy(out, b.buf[b.nextIdx:])
	copy(out[b.cap-b.nextIdx:], b.buf[:b.nextIdx])
	return out
}

// PeerMessageRecorder maintains a per-peer rolling window of recent
// outgoing messages. It is intentionally lightweight to avoid
// impacting normal RPC latency.
type PeerMessageRecorder struct {
	mu       sync.RWMutex
	perPeer  map[peer.ID]*peerMessageBuffer
	perPeerN int
}

// NewPeerMessageRecorder creates a new recorder that keeps at most
// perPeerCapacity messages for each peer.
func NewPeerMessageRecorder() *PeerMessageRecorder {
	// 64 messages per peer is a reasonable default that provides a
	// useful seed corpus without consuming excessive memory.
	const perPeerCapacity = 64
	return &PeerMessageRecorder{
		perPeer:  make(map[peer.ID]*peerMessageBuffer),
		perPeerN: perPeerCapacity,
	}
}

// RecordOutgoing records an outgoing message to a peer. The message
// is stored as-is; callers should avoid mutating the message after
// calling this function if they rely on it for fuzzing.
func (r *PeerMessageRecorder) RecordOutgoing(pid peer.ID, category, topic string, msg interface{}) {
	if r == nil {
		return
	}

	r.mu.Lock()
	buf, ok := r.perPeer[pid]
	if !ok {
		buf = newPeerMessageBuffer(r.perPeerN)
		r.perPeer[pid] = buf
	}
	r.mu.Unlock()

	buf.append(RecordedMessage{
		PeerID:    pid,
		Category:  category,
		Topic:     topic,
		Message:   msg,
		Timestamp: time.Now(),
	})
}

// RecentMessages returns a snapshot of the recent messages sent to
// the given peer. The returned slice is ordered from oldest to newest.
func (r *PeerMessageRecorder) RecentMessages(pid peer.ID) []RecordedMessage {
	if r == nil {
		return nil
	}

	r.mu.RLock()
	buf, ok := r.perPeer[pid]
	r.mu.RUnlock()
	if !ok {
		return nil
	}
	return buf.snapshot()
}
