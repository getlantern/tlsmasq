package testutil

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
)

// TLSOrigin serves as a TLS origin, useful for proxying handshakes. Closes when the test completes.
type TLSOrigin struct {
	net.Listener
	postHandshake func(net.Conn) error
	sync.Mutex
}

// StartOrigin starts a TLSOrigin. There is no need to call Close on the returned origin.
func StartOrigin(cfg *tls.Config) (*TLSOrigin, error) {
	l, err := tls.Listen("tcp", "localhost:0", cfg)
	if err != nil {
		return nil, err
	}

	o := &TLSOrigin{l, nil, sync.Mutex{}}
	go o.listenAndServe()
	return o, nil
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
			switch {
			// This happens normally when the listener is closed
			case strings.Contains(err.Error(), "use of closed network connection"):
				return
			default:
				panic(fmt.Sprintf("origin accept error for connection %d: %v\n", connections, err))
			}
		}
		go func(conn net.Conn, number int) {
			if err := conn.(*tls.Conn).Handshake(); err != nil {
				panic(fmt.Sprintf("origin handshake error for connection %d: %v\n", number, err))
			}
			postHandshake := o.getPostHandshake()
			if postHandshake == nil {
				return
			}
			if err := postHandshake(conn); err != nil {
				panic(fmt.Sprintf("origin post-handshake error for connection %d: %v\n", number, err))
			}
			c.Close()
		}(c, connections)
	}
}
