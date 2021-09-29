package ptlshs

import (
	cryptoRand "crypto/rand"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNonceCache(t *testing.T) {
	t.Parallel()

	const (
		sweepEvery = time.Second

		perBatch = 100
	)

	t.Run("valid only once", func(t *testing.T) {
		batch := []nonce{}
		for i := 0; i < perBatch; i++ {
			batch = append(batch, newNonceWithExpiration(t, time.Now().Add(time.Minute)))
		}

		nc := newNonceCache(sweepEvery)
		defer nc.close()

		for i := 0; i < perBatch; i++ {
			require.True(t, nc.isValid(batch[i]))
		}
		require.Equal(t, perBatch, nc.count())
		for i := 0; i < perBatch; i++ {
			require.False(t, nc.isValid(batch[i]))
		}
		require.Equal(t, perBatch, nc.count())
	})

	t.Run("eviction", func(t *testing.T) {
		var (
			firstExpiration  = time.Now().Add(-5 * sweepEvery)
			secondExpiration = time.Now().Add(5 * sweepEvery)
		)

		firstBatch, secondBatch := []nonce{}, []nonce{}
		for i := 0; i < perBatch; i++ {
			firstBatch = append(firstBatch, newNonceWithExpiration(t, firstExpiration))
			secondBatch = append(secondBatch, newNonceWithExpiration(t, secondExpiration))
		}

		nc := newNonceCache(sweepEvery)
		defer nc.close()

		for i := 0; i < perBatch; i++ {
			require.False(t, nc.isValid(firstBatch[i]))
		}
		require.Equal(t, 0, nc.count())
		for i := 0; i < perBatch; i++ {
			require.True(t, nc.isValid(secondBatch[i]))
		}
		require.Equal(t, perBatch, nc.count())
	})
}

func newNonceWithExpiration(t *testing.T, exp time.Time) nonce {
	t.Helper()
	// this TTL does not matter; we're about to overwrite the expiration
	n, err := newNonce(cryptoRand.Reader, time.Hour)
	require.NoError(t, err)
	binary.LittleEndian.PutUint64(n[:], uint64(exp.UnixNano()))
	return *n
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
