package ptlshs

import (
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCancelConn(t *testing.T) {
	t.Parallel()

	const parallelism = 10

	var (
		readGroup = new(sync.WaitGroup)
		errs      = make(chan error, parallelism)
		_a, b     = net.Pipe()

		// Every time a Read is invoked on 'a', we decrement the readGroup counter. This lets us
		// know when we have the expected number of blocked Read calls.
		a      = onReadConn{_a, func() { readGroup.Done() }}
		rx, tx = newCancelConn(a), newCancelConn(b)
	)
	for i := 0; i < parallelism; i++ {
		readGroup.Add(1)
		go func() {
			_, err := rx.Read(make([]byte, 10))
			errs <- err
		}()
	}

	readGroup.Wait()
	require.NoError(t, rx.cancelIO())

	for i := 0; i < parallelism; i++ {
		require.True(t, errors.As(<-errs, new(cancelledIOError)))
	}

	// Connection should still be usable.

	msg := []byte("message")
	writeErr := make(chan error, 1)
	go func() {
		_, err := tx.Write(msg)
		writeErr <- err
	}()

	// The Read call below will invoke readGroup.Done(). This will trigger a 'negative WaitGroup
	// counter' panic unless we increment the readGroup counter here.
	readGroup.Add(1)

	buf := make([]byte, len(msg))
	n, err := rx.Read(buf)
	require.NoError(t, err)
	require.NoError(t, <-writeErr)
	require.Equal(t, msg, buf[:n])
}

type onReadConn struct {
	net.Conn
	onRead func()
}

func (conn onReadConn) Read(b []byte) (n int, err error) {
	conn.onRead()
	return conn.Conn.Read(b)
}
