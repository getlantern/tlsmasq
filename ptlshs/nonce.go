package ptlshs

import (
	"container/heap"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// Nonce format:
//
// +-------------------------------------------------------------------------+
// | 8-byte timestamp: nanoseconds since UTC epoch | 24 bytes of random data |
// +-------------------------------------------------------------------------+

// A nonce used in proxied TLS handshakes. This is used to ensure that the completion signal (sent
// by the client after a completed handshake) is not replayable.
type nonce [32]byte

func newNonce(ttl time.Duration) (*nonce, error) {
	n := nonce{}
	binary.LittleEndian.PutUint64(n[:], uint64(time.Now().Add(ttl).UnixNano()))
	if _, err := rand.Read(n[8:]); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return &n, nil
}

func (n nonce) expiration() time.Time {
	return time.Unix(0, int64(binary.LittleEndian.Uint64(n[:])))
}

type nonceCache struct {
	// We sort nonces we've seen into buckets using their expiration timestamps. Each bucket has a
	// a beginning, relative to startTime, and a span, equal to bucketSpan. All nonces in a bucket
	// with beginning b will have an expiration >= b and < b + bucketSpan.
	//
	// When the nonce cache is created (in newNonceCache), we start an eviction routine which will
	// periodically wake up and delete a bucket. When we create a new bucket, we register it with
	// the evictor using the evictions channel.

	startTime  time.Time
	bucketSpan time.Duration

	evictions   chan time.Duration
	buckets     map[time.Duration]map[nonce]bool
	bucketsLock sync.Mutex

	done      chan struct{}
	closeOnce sync.Once
}

func newNonceCache(sweepEvery time.Duration) *nonceCache {
	nc := nonceCache{
		time.Now(), sweepEvery, make(chan time.Duration),
		map[time.Duration]map[nonce]bool{}, sync.Mutex{}, make(chan struct{}), sync.Once{},
	}
	go nc.startEvictor()
	return &nc
}

func (nc *nonceCache) isValid(n nonce) bool {
	expiration := n.expiration()
	if time.Now().After(expiration) {
		return false
	}
	bucket := nc.getBucket(expiration)

	nc.bucketsLock.Lock()
	defer nc.bucketsLock.Unlock()
	if bucket[n] {
		return false
	}
	bucket[n] = true
	return true
}

func (nc *nonceCache) getBucket(exp time.Time) map[nonce]bool {
	diff := exp.Sub(nc.startTime)
	bucketStart := diff - (diff % nc.bucketSpan)

	nc.bucketsLock.Lock()
	bucket, ok := nc.buckets[bucketStart]
	if !ok {
		bucket = map[nonce]bool{}
		nc.buckets[bucketStart] = bucket
	}
	nc.bucketsLock.Unlock()
	if !ok {
		nc.evictions <- bucketStart
	}
	return bucket
}

func (nc *nonceCache) startEvictor() {
	pendingEvictions := new(durationHeap)
	timer := time.NewTimer(nc.bucketSpan)
	for {
		select {
		case newEviction := <-nc.evictions:
			heap.Push(pendingEvictions, newEviction)
			if !timer.Stop() {
				<-timer.C
			}
			nextEviction := pendingEvictions.Peek().(time.Duration) + nc.bucketSpan
			timer.Reset(time.Until(nc.startTime.Add(nextEviction)))
		case <-timer.C:
			if pendingEvictions.Len() > 0 {
				evicting := heap.Pop(pendingEvictions).(time.Duration)
				nc.bucketsLock.Lock()
				delete(nc.buckets, evicting)
				nc.bucketsLock.Unlock()
			}
		case <-nc.done:
			timer.Stop()
			return
		}
	}
}

func (nc *nonceCache) close() {
	nc.closeOnce.Do(func() { close(nc.done) })
}

// Adapted from https://golang.org/src/container/heap/example_intheap_test.go. Not concurrency-safe.
type durationHeap []time.Duration

func (h durationHeap) Len() int           { return len(h) }
func (h durationHeap) Less(i, j int) bool { return h[i] < h[j] }
func (h durationHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *durationHeap) Push(i interface{}) {
	*h = append(*h, i.(time.Duration))
}

func (h *durationHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

func (h *durationHeap) Peek() interface{} {
	popped := heap.Pop(h)
	heap.Push(h, popped)
	return popped
}
