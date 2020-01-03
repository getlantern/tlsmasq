// Package testutil provides shared utilities for testing.
package testutil

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// BufferedPipe is like net.Pipe(), but with internal buffering on writes. In practice, our
// connections are generally TCP connections, for which writes will not block.
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
	closedErr atomic.Value // set to an error if and when the underlying connection is closed
	closeOnce sync.Once
}

func newBufferedConn(conn net.Conn, bufferedWrites int) *bufferedConn {
	bc := bufferedConn{conn, make(chan []byte, bufferedWrites), atomic.Value{}, sync.Once{}}
	go bc.flushWrites()
	return &bc
}

func (conn *bufferedConn) flushWrites() {
	for b := range conn.writes {
		if _, err := conn.Conn.Write(b); err == io.EOF || err == io.ErrClosedPipe {
			conn.closedErr.Store(err)
		}
	}
}

func (conn *bufferedConn) Write(b []byte) (n int, err error) {
	if closedErr := conn.closedErr.Load(); closedErr != nil {
		return 0, closedErr.(error)
	}
	conn.writes <- b
	return len(b), nil
}

func (conn *bufferedConn) Close() error {
	conn.closeOnce.Do(func() { close(conn.writes) })
	return conn.Conn.Close()
}
