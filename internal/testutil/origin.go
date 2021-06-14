package testutil

import (
	"context"
	"crypto/tls"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// TLSOrigin serves as a TLS origin, useful for proxying handshakes. Closes when the test completes.
type TLSOrigin struct {
	net.Listener
}

// StartOrigin starts a TLSOrigin. There is no need to call Close on the returned origin.
func StartOrigin(t *testing.T, cfg *tls.Config) TLSOrigin {
	t.Helper()

	l, err := tls.Listen("tcp", "localhost:0", cfg)
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })

	logger := NewSafeLogger(t)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			logger.Logf("origin accept error: %v", err)
			return
		}
		if err := conn.(*tls.Conn).Handshake(); err != nil {
			logger.Logf("origin handshake error: %v", err)
			return
		}
	}()

	return TLSOrigin{l}
}

// DialContext dials the origin.
func (o TLSOrigin) DialContext(ctx context.Context) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", o.Addr().String())
}
