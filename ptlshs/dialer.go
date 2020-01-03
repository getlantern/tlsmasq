package ptlshs

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

type dialer struct {
	Dialer
	DialerOpts
}

func (d dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// Respect any timeout or deadline on the wrapped dialer.
	if netDialer, ok := d.Dialer.(*net.Dialer); ok {
		if deadline := earliestDeadline(netDialer); !deadline.IsZero() {
			var cancel func()
			ctx, cancel = context.WithDeadline(ctx, deadline)
			defer cancel()
		}
	}
	conn, err := d.Dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return Client(conn, d.TLSConfig, d.Secret, d.NonceTTL), nil
}

type mitmConn struct {
	net.Conn
	onRead, onWrite func([]byte)
	closedByPeer    chan struct{}
}

// Sets up a MITM'd connection. Callbacks will be invoked synchronously. Either callback may be nil.
func mitm(conn net.Conn, onRead, onWrite func([]byte)) mitmConn {
	if onRead == nil {
		onRead = func(_ []byte) {}
	}
	if onWrite == nil {
		onWrite = func(_ []byte) {}
	}
	return mitmConn{conn, onRead, onWrite, make(chan struct{})}
}

func (c mitmConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		c.onRead(b[:n])
	}
	if err == io.EOF {
		// This is an unexported error indicating that the connection is closed.
		// See https://golang.org/pkg/internal/poll/#pkg-variables
		close(c.closedByPeer)
	}
	return
}

func (c mitmConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		c.onWrite(b[:n])
	}
	if err != nil && strings.Contains(err.Error(), "use of closed network connection") {
		// This is an unexported error indicating that the connection is closed.
		// See https://golang.org/pkg/internal/poll/#pkg-variables
		close(c.closedByPeer)
	}
	return
}

// Returns the earliest of:
//   - time.Now()+Timeout
//   - d.Deadline
// Or zero, if neither Timeout nor Deadline are set.
func earliestDeadline(d *net.Dialer) time.Time {
	if d.Timeout == 0 && d.Deadline.IsZero() {
		return time.Time{}
	}
	if d.Timeout == 0 {
		return d.Deadline
	}
	timeoutExpiration := time.Now().Add(d.Timeout)
	if d.Deadline.IsZero() || timeoutExpiration.Before(d.Deadline) {
		return timeoutExpiration
	}
	return d.Deadline
}

func deriveSeqAndIV(serverRandom []byte) (seq [8]byte, iv [16]byte, err error) {
	if len(serverRandom) < len(seq)+len(iv) {
		return seq, iv, fmt.Errorf(
			"expected larger server random (should be 32 bytes, got %d)", len(serverRandom))
	}
	copy(seq[:], serverRandom)
	copy(iv[:], serverRandom[len(seq):])
	return seq, iv, nil
}

func padWithRandom(b []byte, totalLen int) ([]byte, error) {
	if len(b) >= totalLen {
		return b, nil
	}
	padded := make([]byte, totalLen)
	if _, err := rand.Read(padded[len(b):]); err != nil {
		return nil, err
	}
	copy(padded, b)
	return padded, nil
}
