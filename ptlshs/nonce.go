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
	// The nonces we've seen are kept in buckets. Each bucket is assigned a timestamp and each nonce
	// in the bucket expires before this timestamp. Further, each nonce in the bucket expires no
	// earlier than bucketDiff before the timestamp. Thus, every nonce can logically only belong to
	// one bucket. startTime determines the start of the first bucket's span.
	//
	// When the nonce cache is created (in newNonceCache), we start an eviction routine which will
	// periodically wake up and delete a bucket. When we create a new bucket, we register it with
	// the evictor using the evictions channel.

	startTime  time.Time
	bucketDiff time.Duration

	evictions   chan time.Time
	buckets     map[time.Time]map[nonce]bool
	bucketsLock sync.Mutex

	done      chan struct{}
	closeOnce sync.Once
}

func newNonceCache(sweepEvery time.Duration) *nonceCache {
	nc := nonceCache{
		time.Now(), sweepEvery, make(chan time.Time),
		map[time.Time]map[nonce]bool{}, sync.Mutex{}, make(chan struct{}), sync.Once{},
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
	bucketTime := nc.startTime.Add(diff - (diff % nc.bucketDiff) + nc.bucketDiff)

	nc.bucketsLock.Lock()
	bucket, ok := nc.buckets[bucketTime]
	if !ok {
		bucket = map[nonce]bool{}
		nc.buckets[bucketTime] = bucket
	}
	nc.bucketsLock.Unlock()
	if !ok {
		nc.evictions <- bucketTime
	}
	return bucket
}

func (nc *nonceCache) startEvictor() {
	pendingEvictions := new(timeHeap)
	timer := time.NewTimer(nc.bucketDiff)
	for {
		select {
		case newEviction := <-nc.evictions:
			heap.Push(pendingEvictions, newEviction)
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(time.Until(pendingEvictions.Peek().(time.Time)))
		case <-timer.C:
			if pendingEvictions.Len() > 0 {
				evicting := heap.Pop(pendingEvictions).(time.Time)
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
type timeHeap []time.Time

func (h timeHeap) Len() int           { return len(h) }
func (h timeHeap) Less(i, j int) bool { return h[i].Before(h[j]) }
func (h timeHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *timeHeap) Push(i interface{}) {
	*h = append(*h, i.(time.Time))
}

func (h *timeHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

func (h *timeHeap) Peek() interface{} {
	popped := heap.Pop(h)
	heap.Push(h, popped)
	return popped
}
