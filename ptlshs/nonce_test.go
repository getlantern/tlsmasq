package ptlshs

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNonceCache(t *testing.T) {
	t.Parallel()

	const (
		sweepEvery = 200 * time.Millisecond
		perBatch   = 100
	)

	// For the first batch, use an expiration such that all will be evicted in the first sweep.
	firstExpiration := time.Now().Add(sweepEvery / 2)
	firstBatch := []nonce{}
	for i := 0; i < perBatch; i++ {
		n, err := newNonce(time.Until(firstExpiration))
		require.NoError(t, err)
		firstBatch = append(firstBatch, *n)
	}

	// We will have a second batch with a much later expiration.
	secondExpiration := time.Now().Add(sweepEvery * 10)
	secondBatch := []nonce{}
	for i := 0; i < perBatch; i++ {
		n, err := newNonce(time.Until(secondExpiration))
		require.NoError(t, err)
		secondBatch = append(secondBatch, *n)
	}

	nc := newNonceCache(sweepEvery)
	defer nc.close()

	for _, nonce := range concat(firstBatch, secondBatch) {
		require.True(t, nc.isValid(nonce))
	}
	require.Equal(t, perBatch*2, nc.count())
	for _, nonce := range concat(firstBatch, secondBatch) {
		require.False(t, nc.isValid(nonce))
	}
	require.Equal(t, perBatch*2, nc.count())

	// Wait for the first batch to expire, plus a sweep interval to ensure the evicter has time.
	time.Sleep(time.Until(firstExpiration.Add(sweepEvery)))

	// Sanity check that we didn't oversleep (in case values change).
	require.True(t, time.Now().Before(secondExpiration))

	require.Equal(t, perBatch, nc.count())
	for _, nonce := range concat(firstBatch, secondBatch) {
		require.False(t, nc.isValid(nonce))
	}
}

func (nc *nonceCache) count() int {
	nc.bucketsLock.Lock()
	defer nc.bucketsLock.Unlock()

	count := 0
	for _, bucket := range nc.buckets {
		count += len(bucket)
	}
	return count
}

func concat(n ...[]nonce) []nonce {
	result := []nonce{}
	for _, a := range n {
		result = append(result, a...)
	}
	return result
}
