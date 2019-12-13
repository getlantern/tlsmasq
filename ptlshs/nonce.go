package ptlshs

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

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
	// When the nonce cache is created (in the NonceCache function), we start an eviction routine
	// which will periodically wake up and delete a bucket. When we create a new bucket, we register
	// it with the evictor using the evictions channel.

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
	expTime := n.expiration()
	if time.Now().After(expTime) {
		return false
	}
	bucket := nc.getBucket(expTime)

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
	pendingEvictions := sortedTimes{}
	timer := time.NewTimer(nc.bucketDiff)
	for {
		select {
		case newEviction := <-nc.evictions:
			pendingEvictions.insert(newEviction)
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(time.Until(pendingEvictions.first.t))
		case <-timer.C:
			if pendingEvictions.first != nil {
				evicting := pendingEvictions.popHead()
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

type timeNode struct {
	t    time.Time
	next *timeNode
}

type sortedTimes struct {
	first *timeNode
}

func (st *sortedTimes) insert(t time.Time) {
	newNode := timeNode{t, nil}
	if st.first == nil {
		st.first = &newNode
		return
	}
	current := st.first
	for current.next != nil && current.t.Before(t) {
		current = current.next
	}
	newNode.next = current.next
	current.next = &newNode
}

// Returns time.Time{} if the list is empty.
func (st *sortedTimes) popHead() time.Time {
	if st.first == nil {
		return time.Time{}
	}
	head := st.first
	st.first = head.next
	return head.t
}
