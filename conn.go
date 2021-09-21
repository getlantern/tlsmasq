package tlsmasq

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	"github.com/getlantern/tlsmasq/ptlshs"
)

type conn struct {
	// A ptlshs.Conn until the handshake has occurred, then just a net.Conn.
	net.Conn

	cfg          *tls.Config
	isClient     bool
	preshared    ptlshs.Secret
	shakeOnce    sync.Once
	handshakeErr error
}

func newTlsmasqConn(c ptlshs.Conn, cfg *tls.Config, isClient bool, preshared ptlshs.Secret) *conn {
	return &conn{c, cfg, isClient, preshared, sync.Once{}, nil}
}

func (c *conn) Read(b []byte) (n int, err error) {
	if err := c.Handshake(); err != nil {
		return 0, fmt.Errorf("handshake failed: %w", err)
	}
	return c.Conn.Read(b)
}

func (c *conn) Write(b []byte) (n int, err error) {
	if err := c.Handshake(); err != nil {
		return 0, fmt.Errorf("handshake failed: %w", err)
	}
	return c.Conn.Write(b)
}

// Handshake executes the tlsmasq handshake protocol, if it has not yet been
// performed. Note that, per the protocol, the connection will proxy all data
// until the completion signal. Thus, if this connection comes from an active
// probe, this handshake function may not return until the probe closes the
// connection on its end. As a result, this function should be treated as one
// which may be long-running or never return.
func (c *conn) Handshake() error {
	c.shakeOnce.Do(func() {
		hijacked, err := hijack(c.Conn.(ptlshs.Conn), c.cfg, c.preshared, c.isClient)
		if err != nil {
			c.handshakeErr = err
			return
		}
		// We're writing to a concurrently accessed field, but handshake() is
		// protected by c.shakeOnce.
		c.Conn = hijacked
	})
	return c.handshakeErr
}
