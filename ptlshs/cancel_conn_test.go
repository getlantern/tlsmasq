package ptlshs

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCancelConn(t *testing.T) {
	t.Parallel()

	const parallelism = 10

	a, b := net.Pipe()
	rx, tx := newCancelConn(a), newCancelConn(b)

	readGroup := new(sync.WaitGroup)
	errs := make(chan error, parallelism)
	for i := 0; i < parallelism; i++ {
		readGroup.Add(1)
		go func() {
			readGroup.Done()
			_, err := rx.Read(make([]byte, 10))
			errs <- err
		}()
	}

	readGroup.Wait()
	time.Sleep(10 * time.Millisecond)
	require.NoError(t, rx.cancelIO())

	for i := 0; i < parallelism; i++ {
		require.True(t, errors.Is(<-errs, errorCancelledIO))
	}

	// Connection should still be usable.

	msg := []byte("message")
	writeErr := make(chan error, 1)
	go func() {
		_, err := tx.Write(msg)
		writeErr <- err
	}()

	buf := make([]byte, len(msg))
	n, err := rx.Read(buf)
	require.NoError(t, err)
	require.NoError(t, <-writeErr)
	require.Equal(t, msg, buf[:n])
}
