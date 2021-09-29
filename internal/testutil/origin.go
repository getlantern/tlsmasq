package testutil

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"

	"github.com/getlantern/tlsmasq/fuzz"
	"github.com/stretchr/testify/require"
)

// TLSOrigin serves as a TLS origin, useful for proxying handshakes. Closes when the test completes.
type TLSOrigin struct {
	net.Listener
	logger        *SafeTestLogger
	t             *testing.T
	postHandshake func(net.Conn) error
	sync.Mutex
	cfg      *tls.Config
	fuzzData []byte
}

// StartOrigin starts a TLSOrigin. There is no need to call Close on the returned origin.
func StartOrigin(t *testing.T, cfg *tls.Config, originFuzzData []byte) *TLSOrigin {
	t.Helper()

	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })

	o := &TLSOrigin{l, NewSafeLogger(t), t, nil, sync.Mutex{}, cfg, originFuzzData}
	go o.listenAndServe()
	return o
}

// DialContext dials the origin.
func (o *TLSOrigin) DialContext(ctx context.Context) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", o.Addr().String())
}

// DoPostHandshake can be used to configure post-handshake behavior.
func (o *TLSOrigin) DoPostHandshake(f func(conn net.Conn) error) {
	o.Lock()
	o.postHandshake = f
	o.Unlock()
}

func (o *TLSOrigin) getPostHandshake() func(net.Conn) error {
	o.Lock()
	defer o.Unlock()
	return o.postHandshake
}

func (o *TLSOrigin) listenAndServe() {
	for {
		connections := 0
		c, err := o.Accept()
		connections++
		if err != nil {
			o.logger.Logf("origin accept error for connection %d: %v", connections, err)
			return
		}
		c = tls.Server(fuzz.NewEchoConn("origin", c, o.fuzzData), o.cfg)
		o.t.Cleanup(func() { c.Close() })
		go func(conn net.Conn, number int) {
			if err := conn.(*tls.Conn).Handshake(); err != nil {
				o.logger.Logf("origin handshake error for connection %d: %v", number, err)
				return
			}
			postHandshake := o.getPostHandshake()
			if postHandshake == nil {
				return
			}
			if err := postHandshake(conn); err != nil {
				o.logger.Logf("origin post-handshake error for connection %d: %v", number, err)
				return
			}
		}(c, connections)
	}
}
