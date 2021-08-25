// Package testutil provides shared utilities for testing.
package testutil

import (
	"io"
	"net"
	"sync"
)

// BufferedPipe is like net.Pipe(), but with internal buffering on writes. In practice, our
// connections are generally TCP connections, for which writes will not block.
//
// Buffered writes may not be fully flushed to the peer when this connection is closed. Thus this
// pipe may not be suitable for tests which require strict adherence to the net.Conn contract.
//
// Should probably be replaced with the standard library implementation if this happens:
// https://github.com/golang/go/issues/34502
func BufferedPipe() (net.Conn, net.Conn) {
	rx, tx := net.Pipe()
	return newBufferedConn(rx, 10), newBufferedConn(tx, 10)
}

// A network connection with buffered writes. Only necessary because we use synchronous connections
// created by net.Pipe().
type bufferedConn struct {
	net.Conn
	writes    chan []byte
	closedErr error // set to an error if and when the underlying connection is closed
	closed    bool
	mu        sync.Mutex
}

func newBufferedConn(conn net.Conn, bufferedWrites int) *bufferedConn {
	bc := bufferedConn{conn, make(chan []byte, bufferedWrites), nil, false, sync.Mutex{}}
	go bc.flushWrites()
	return &bc
}

func (conn *bufferedConn) flushWrites() {
	for b := range conn.writes {
		if _, err := conn.Conn.Write(b); err == io.EOF || err == io.ErrClosedPipe {
			conn.mu.Lock()
			conn.closedErr = err
			conn.mu.Unlock()
		}
	}
}

func (conn *bufferedConn) Write(b []byte) (n int, err error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.closedErr != nil {
		return 0, conn.closedErr
	}
	if conn.closed {
		return 0, io.ErrClosedPipe
	}
	copyB := make([]byte, len(b))
	n = copy(copyB, b)
	conn.writes <- copyB
	return
}

func (conn *bufferedConn) Close() error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if !conn.closed {
		close(conn.writes)
	}
	conn.closed = true
	return conn.Conn.Close()
}
