// Package util provides general utilities for tlsmasq and subpackages.
package util

import (
	"context"
	"crypto/tls"
	"time"
)

// TimeoutError implements net.Error.
type TimeoutError string

func (err TimeoutError) Error() string { return string(err) }

// Timeout returns true.
func (err TimeoutError) Timeout() bool { return true }

// Temporary returns false.
func (err TimeoutError) Temporary() bool { return false }

// HandshakeContext attempts to execute a TLS handshake using the connection. If the handshake is
// not completed by the context deadline, a timeoutError is returned and the connection is closed.
func HandshakeContext(ctx context.Context, tlsConn *tls.Conn) error {
	// Adapted from net/http.persistConn.addTLS.
	dl, ok := ctx.Deadline()
	if !ok {
		return tlsConn.Handshake()
	}

	timer := time.NewTimer(dl.Sub(time.Now()))
	errc := make(chan error, 1)
	go func() {
		errc <- tlsConn.Handshake()
		timer.Stop()
	}()
	select {
	case err := <-errc:
		return err
	case <-timer.C:
		tlsConn.Close()
		return TimeoutError("timed out during TLS handshake")
	}
}
