package ptlshs

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/getlantern/tlsmasq/internal/reptls"
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

	var (
		serverRandom    []byte
		serverRandomErr error
	)
	onClientRead := func(b []byte) {
		if serverRandom != nil || serverRandomErr != nil {
			return
		}

		serverHello, err := reptls.ParseServerHello(b)
		if err != nil {
			serverRandomErr = err
			return
		}
		serverRandom = serverHello.Random
	}

	mitmConn := mitm(conn, onClientRead, nil)
	tlsConn := tls.Client(mitmConn, d.TLSConfig)
	if err := handshakeContext(ctx, tlsConn); err != nil {
		return nil, err
	}
	if serverRandomErr != nil {
		return nil, fmt.Errorf("failed to parse server hello: %w", serverRandomErr)
	}
	if serverRandom == nil {
		return nil, fmt.Errorf("never saw server hello")
	}
	seq, iv, err := deriveSeqAndIV(serverRandom)
	if err != nil {
		return nil, fmt.Errorf("failed to derive sequence and IV: %w", err)
	}
	if err := d.signalComplete(tlsConn, conn, seq, iv); err != nil {
		return nil, fmt.Errorf("failed to signal completion of fake handshake: %w", err)
	}
	cs := tlsConn.ConnectionState()
	return &Conn{conn, cs.Version, cs.CipherSuite, seq, iv, sync.Mutex{}}, nil
}

func (d dialer) signalComplete(tlsConn *tls.Conn, serverConn net.Conn, seq [8]byte, iv [16]byte) error {
	connState, err := reptls.GetState(tlsConn, seq)
	if err != nil {
		return fmt.Errorf("failed to read connection state: %w", err)
	}
	signal, err := newCompletionSignal(d.NonceTTL)
	if err != nil {
		return fmt.Errorf("failed to create completion signal: %w", err)
	}
	_, err = reptls.WriteRecord(serverConn, signal[:], connState, d.Secret, iv)
	if err != nil {
		return err
	}
	return nil
}

// timeoutError implements net.Error.
type timeoutError string

func (err timeoutError) Error() string   { return string(err) }
func (err timeoutError) Timeout() bool   { return true }
func (err timeoutError) Temporary() bool { return false }

// Attempts to execute a TLS handshake using the connection. If the handshake is not completed by
// the context deadline, a timeoutError is returned and the connection is closed.
//
// Adapted from net/http.persistConn.addTLS.
func handshakeContext(ctx context.Context, tlsConn *tls.Conn) error {
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
		return timeoutError("timed out during TLS handshake")
	}
}

type mitmConn struct {
	net.Conn
	onRead, onWrite func([]byte)
	closedByPeer    chan struct{}
}

// Sets up a MITM'd connection. Callbacks will be called synchronously. Either callback may be nil.
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
