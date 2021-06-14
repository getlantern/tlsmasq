package ptlshs

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/tlsmasq/internal/testutil"
	"github.com/getlantern/tlsutil"
)

func TestListenAndDial(t *testing.T) {
	t.Parallel()

	var (
		secret               [52]byte
		clientMsg, serverMsg = "hello from the client", "hello from the server"
	)
	_, err := rand.Read(secret[:])
	require.NoError(t, err)

	origin := testutil.StartOrigin(t, &tls.Config{Certificates: []tls.Certificate{cert}})

	dialerCfg := DialerConfig{
		Handshaker: StdLibHandshaker{
			Config: &tls.Config{InsecureSkipVerify: true},
		},
		Secret: secret,
	}
	listenerCfg := ListenerConfig{DialOrigin: origin.DialContext, Secret: secret}

	l, err := Listen("tcp", "localhost:0", listenerCfg)
	require.NoError(t, err)
	defer l.Close()

	rcvdClientMsg := make(chan string, 1)
	listenerErr := make(chan error, 1)
	go func() {
		listenerErr <- func() error {
			conn, err := l.Accept()
			if err != nil {
				return fmt.Errorf("accept error: %w", err)
			}
			defer conn.Close()

			b := make([]byte, len(clientMsg))
			n, err := conn.Read(b)
			if err != nil {
				return fmt.Errorf("read error: %w", err)
			}
			rcvdClientMsg <- string(b[:n])

			if _, err = conn.Write([]byte(serverMsg)); err != nil {
				return fmt.Errorf("write error: %w", err)
			}
			return nil
		}()
	}()

	rcvdServerMsg, dialErr := func() (string, error) {
		conn, err := Dial("tcp", l.Addr().String(), dialerCfg)
		if err != nil {
			return "", fmt.Errorf("dial error: %w", err)
		}
		defer conn.Close()

		if _, err := conn.Write([]byte(clientMsg)); err != nil {
			return "", fmt.Errorf("write error: %w", err)
		}

		b := make([]byte, len(serverMsg))
		n, err := conn.Read(b)
		if err != nil {
			return "", fmt.Errorf("read error: %w", err)
		}
		return string(b[:n]), nil
	}()

	if allPassed(
		assert.NoError(t, dialErr),
		assert.NoError(t, <-listenerErr),
	) {
		assert.Equal(t, clientMsg, <-rcvdClientMsg)
		assert.Equal(t, serverMsg, rcvdServerMsg)
	}
}

// TestSessionResumption ensures that ptlshs is compatible with TLS session resumption.
func TestSessionResumption(t *testing.T) {
	t.Parallel()

	var secret [52]byte
	_, err := rand.Read(secret[:])
	require.NoError(t, err)

	origin := testutil.StartOrigin(t, &tls.Config{Certificates: []tls.Certificate{cert}})
	handshaker := &resumptionCheckingHandshaker{
		Config: &tls.Config{
			InsecureSkipVerify: true,
			ClientSessionCache: tls.NewLRUClientSessionCache(10),
			MaxVersion:         tls.VersionTLS12,
		},
	}
	dialerCfg := DialerConfig{secret, handshaker, 0}
	listenerCfg := ListenerConfig{DialOrigin: origin.DialContext, Secret: secret}

	l, err := Listen("tcp", "localhost:0", listenerCfg)
	require.NoError(t, err)
	defer l.Close()

	listenerErr := make(chan error, 1)
	go func() {
		listenerErr <- func() error {
			for i := 0; i < 2; i++ {
				conn, err := l.Accept()
				if err != nil {
					return fmt.Errorf("accept error for connection %d: %w", i, err)
				}
				defer conn.Close()

				if err := conn.(Conn).Handshake(); err != nil {
					return fmt.Errorf("handshake error for connection %d: %w", i, err)
				}
			}
			return nil
		}()
	}()

	dialErr := func() error {
		conn, err := Dial("tcp", l.Addr().String(), dialerCfg)
		if err != nil {
			return fmt.Errorf("dial error for connection 1: %w", err)
		}
		defer conn.Close()

		if err := conn.(Conn).Handshake(); err != nil {
			return fmt.Errorf("handshake error for connection 1: %w", err)
		}
		if err := conn.Close(); err != nil {
			return fmt.Errorf("close error for connection 1: %w", err)
		}

		// Dial a new connection with the same config. This should resume our session.
		conn, err = Dial("tcp", l.Addr().String(), dialerCfg)
		if err != nil {
			return fmt.Errorf("dial error for connection 2: %w", err)
		}
		defer conn.Close()

		if err := conn.(Conn).Handshake(); err != nil {
			return fmt.Errorf("handshake error for connection 2: %w", err)
		}
		return nil
	}()

	if allPassed(
		assert.NoError(t, dialErr),
		assert.NoError(t, <-listenerErr),
	) {
		require.True(t, handshaker.resumedLastHandshake)
	}
}

func TestSignalReplay(t *testing.T) {
	t.Parallel()

	var (
		secret               [52]byte
		serverMsg, originMsg = "hello from the real server", "hello from the origin"
	)

	_, err := rand.Read(secret[:])
	require.NoError(t, err)

	origin := testutil.StartOrigin(t, &tls.Config{Certificates: []tls.Certificate{cert}})
	origin.DoPostHandshake(func(conn net.Conn) error {
		if _, err := conn.Write([]byte(originMsg)); err != nil {
			return fmt.Errorf("write error %v", err)
		}
		return nil
	})

	// We capture the encrypted signal by watching the bytes going in and out of the server. We use
	// some knowledge of the protocol and secret to identify the signal, but this could conceivably
	// be done without this information.
	var (
		encryptedSignalChan = make(chan []byte, 1)
		serverHello         *tlsutil.ServerHello
		serverHelloMu       sync.Mutex // only necessary to appease the race detector
	)
	onServerWrite := func(b []byte) error {
		serverHelloMu.Lock()
		defer serverHelloMu.Unlock()
		if serverHello != nil {
			return nil
		}
		var err error
		serverHello, err = tlsutil.ParseServerHello(b)
		if err != nil {
			return fmt.Errorf("failure parsing server hello in onServerWrite: %w", err)
		}
		return nil
	}
	onServerRead := func(b []byte) error {
		serverHelloMu.Lock()
		defer serverHelloMu.Unlock()
		if serverHello == nil {
			return nil
		}

		seq, iv, err := deriveSeqAndIV(serverHello.Random)
		if err != nil {
			return fmt.Errorf("failed to dervice seq and IV in onServerRead: %w", err)
		}

		connState, err := tlsutil.NewConnectionState(
			serverHello.Version, serverHello.Suite, secret, iv, seq)
		if err != nil {
			return fmt.Errorf("failed to create new connection state in onServerRead: %w", err)
		}

		r := bytes.NewReader(b)
		unprocessedBuf := new(bufferList)
		for r.Len() > 0 || unprocessedBuf.len() > 0 {
			signalStart := len(b) - r.Len() - unprocessedBuf.len()
			record, unprocessed, err := tlsutil.ReadRecord(io.MultiReader(unprocessedBuf, r), connState)
			if unprocessed != nil {
				unprocessedBuf.prepend(unprocessed)
			}
			if err != nil {
				// Assume this wasn't the signal.
				continue
			}
			if _, err := parseClientSignal(record); err != nil {
				// Assume this wasn't the signal.
				continue
			}
			signalEnd := len(b) - r.Len() - unprocessedBuf.len()
			encryptedSignalChan <- b[signalStart:signalEnd]
		}
		return nil
	}

	_l, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	listenerCfg := ListenerConfig{DialOrigin: origin.DialContext, Secret: secret}
	l := WrapListener(mitmListener{_l, onServerRead, onServerWrite}, listenerCfg)
	defer l.Close()

	listenerErr := make(chan error, 1)
	go func() {
		listenerErr <- func() error {
			for i := 0; i < 2; i++ {
				conn, err := l.Accept()
				if err != nil {
					return fmt.Errorf("accept error for connection %d: %w", i, err)
				}
				// Ensure blocked I/O is cleaned up.
				t.Cleanup(func() { conn.Close() })
				go func() {
					// Try to write, but don't check for write errors. This message will only make it to
					// the client if our replay detection is broken. We would see it in a check below.
					conn.Write([]byte(serverMsg))
					conn.Close()
				}()
			}
			return nil
		}()
	}()

	rcvdFromOrigin, dialErr := func() (string, error) {
		// Dial once so that our callbacks pick up the signal.
		dialerCfg := DialerConfig{
			Handshaker: StdLibHandshaker{&tls.Config{InsecureSkipVerify: true}},
			Secret:     secret,
		}
		conn, err := Dial("tcp", l.Addr().String(), dialerCfg)
		if err != nil {
			return "", fmt.Errorf("dial error for first connection: %w", err)
		}
		if err := conn.(Conn).Handshake(); err != nil {
			return "", fmt.Errorf("handshake error for first connection: %w", err)
		}
		defer conn.Close()

		encryptedSignal := <-encryptedSignalChan

		// Now we dial again, but with a standard TLS dialer. This should get proxied through to the
		// TLS listener.
		conn, err = tls.DialWithDialer(
			&net.Dialer{},
			"tcp", l.Addr().String(),
			&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return "", fmt.Errorf("dial error for second connection: %w", err)
		}

		// Now the server should be waiting for the completion signal. We replay the signal from before
		// and see how the server responds.
		if _, err := conn.Write(encryptedSignal); err != nil {
			return "", fmt.Errorf("write error for second connection: %w", err)
		}

		b := make([]byte, len(originMsg))
		n, err := conn.Read(b)
		if err != nil {
			return "", fmt.Errorf("read error for second connection: %w", err)
		}
		return string(b[:n]), nil
	}()

	if allPassed(
		assert.NoError(t, dialErr),
		assert.NoError(t, <-listenerErr),
	) {
		require.Equal(t, originMsg, rcvdFromOrigin)
	}
}

// TestPostHandshakeData ensures that tlsmasq connections are resilient to origins sending data
// after the handshake has completed. This data should not make it to the client as this would
// constitute unexpected data and could disrupt the next phase of the connection.
func TestPostHandshakeData(t *testing.T) {
	t.Parallel()

	var (
		secret               [52]byte
		clientMsg, serverMsg = "hello from the client", "hello from the server"
	)
	_, err := rand.Read(secret[:])
	require.NoError(t, err)

	origin := testutil.StartOrigin(t, &tls.Config{Certificates: []tls.Certificate{cert}})
	origin.DoPostHandshake(func(conn net.Conn) error {
		if _, err := conn.Write([]byte("some nonsense from the origin")); err != nil {
			return fmt.Errorf("write error: %w", err)
		}
		return nil
	})

	dialerCfg := DialerConfig{
		Handshaker: StdLibHandshaker{
			Config: &tls.Config{
				InsecureSkipVerify: true,
				Renegotiation:      tls.RenegotiateFreelyAsClient,
			},
		},
		Secret: secret,
	}
	listenerCfg := ListenerConfig{DialOrigin: origin.DialContext, Secret: secret}

	l, err := Listen("tcp", "localhost:0", listenerCfg)
	require.NoError(t, err)
	defer l.Close()

	rcvdFromClient := make(chan string, 1)
	listenerErr := make(chan error, 1)
	go func() {
		listenerErr <- func() error {
			conn, err := l.Accept()
			if err != nil {
				return fmt.Errorf("accept error: %w", err)
			}
			defer conn.Close()

			b := make([]byte, len(clientMsg))
			n, err := conn.Read(b)
			if err != nil {
				return fmt.Errorf("read error: %w", err)
			}
			rcvdFromClient <- string(b[:n])

			if _, err := conn.Write([]byte(serverMsg)); err != nil {
				return fmt.Errorf("write error: %w", err)
			}
			return nil
		}()
	}()

	rcvdFromServer, dialErr := func() (string, error) {
		conn, err := Dial("tcp", l.Addr().String(), dialerCfg)
		if err != nil {
			return "", fmt.Errorf("dial error: %w", err)
		}
		defer conn.Close()

		if _, err := conn.Write([]byte(clientMsg)); err != nil {
			return "", fmt.Errorf("write error: %w", err)
		}

		b := make([]byte, len(serverMsg))
		n, err := conn.Read(b)
		if err != nil {
			return "", fmt.Errorf("read error: %w", err)
		}
		return string(b[:n]), nil
	}()

	if allPassed(
		assert.NoError(t, dialErr),
		assert.NoError(t, <-listenerErr),
	) {
		assert.Equal(t, clientMsg, <-rcvdFromClient)
		// This is where we would see the unexpected data from the origin (wrapped in a TLS record).
		assert.Equal(t, serverMsg, rcvdFromServer)
	}
}

// TestPostHandshakeInjection ensures that the connection is closed if garbage data is injected
// between the origin's ServerFinished messaged and the server's completion signal. Otherwise, a bad
// actor could inject such garbage data to determine whether a connection is a tlsmasq connection.
func TestPostHandshakeInjection(t *testing.T) {
	t.Parallel()

	// We will set up a connection between a client, a server, and a masqueraded origin. We will
	// inject garbage data into the server-to-client connection, between the origin's ServerFinished
	// message and the server's completion signal. This should cause the client and server to have
	// different transcripts and the client should notice this when it checks the MAC in the
	// server's completion signal.

	// Not the theoretical maximum, but the maximum allowed by all ciphers supported by tlsutil.
	const maxTLSPayloadSize = 1150
	var (
		secret         [52]byte
		injectorSecret [52]byte
		injectorIV     [16]byte
		injectorSeq    [8]byte
	)
	for _, b := range [][]byte{secret[:], injectorSecret[:], injectorIV[:], injectorSeq[:]} {
		_, err := rand.Read(b)
		require.NoError(t, err)
	}
	injectorState, err := tlsutil.NewConnectionState(
		tls.VersionTLS12, tls.TLS_CHACHA20_POLY1305_SHA256, injectorSecret, injectorIV, injectorSeq)
	require.NoError(t, err)

	origin := testutil.StartOrigin(t, &tls.Config{Certificates: []tls.Certificate{cert}})
	dialerCfg := DialerConfig{
		Handshaker: StdLibHandshaker{
			Config: &tls.Config{InsecureSkipVerify: true},
		},
		Secret: secret,
	}
	listenerCfg := ListenerConfig{DialOrigin: origin.DialContext, Secret: secret}

	_client, _server := testutil.BufferedPipe()

	// When we see the client signal, we block the server's read and inject garbage into the client
	// side of the connection.
	var (
		serverHello   *tlsutil.ServerHello
		serverHelloMu sync.Mutex // only necessary to appease the race detector

		serverReadBuf = new(bufferList)
	)
	onServerWrite := func(b []byte) error {
		serverHelloMu.Lock()
		defer serverHelloMu.Unlock()
		if serverHello != nil {
			return nil
		}
		var err error
		serverHello, err = tlsutil.ParseServerHello(b)
		if err != nil {
			return fmt.Errorf("failure parsing server hello in onServerWrite: %w", err)
		}
		return nil
	}
	onServerRead := func(b []byte) error {
		serverHelloMu.Lock()
		defer serverHelloMu.Unlock()
		if serverHello == nil {
			return nil
		}

		seq, iv, err := deriveSeqAndIV(serverHello.Random)
		if err != nil {
			return fmt.Errorf("failed to dervice seq and IV in onServerRead: %w", err)
		}

		connState, err := tlsutil.NewConnectionState(
			serverHello.Version, serverHello.Suite, secret, iv, seq)
		if err != nil {
			return fmt.Errorf("failed to create new connection state in onServerRead: %w", err)
		}

		r := bytes.NewReader(b)
		totalUnprocessed := r.Len() + serverReadBuf.len()
		for r.Len() > 0 || serverReadBuf.len() > 0 {
			record, unprocessed, err := tlsutil.ReadRecord(io.MultiReader(serverReadBuf, r), connState)
			if unprocessed != nil {
				serverReadBuf.prepend(unprocessed)
			}
			if r.Len()+serverReadBuf.len() == totalUnprocessed {
				// The input slice does not contain a full record. Wait for the next read.
				return nil
			}
			totalUnprocessed = r.Len() + serverReadBuf.len()
			if err != nil {
				// Assume this wasn't the signal.
				continue
			}
			if _, err := parseClientSignal(record); err != nil {
				// Assume this wasn't the signal.
				continue
			}

			// Now we know that the current read contains the client signal. Inject our garbage data
			// before the server can send its own signal. If the garbage data is not in a TLS
			// record, the client connection may hang (as it awaits the rest of the data in the
			// "record"). This is acceptable as far as we're concerned, but makes testing harder.
			// So we send the garbage data in a record encrypted with a different set of parameters.
			// The client will still get the garbage data, but not hang.
			_, err = tlsutil.WriteRecord(_server, randomData(t, maxTLSPayloadSize), injectorState)
			if err != nil {
				return fmt.Errorf("failed to write record in onServerRead: %w", err)
			}
		}
		return nil
	}

	client := Client(_client, dialerCfg)
	server := Server(mitm(_server, onServerRead, onServerWrite), listenerCfg)
	defer server.Close()
	defer client.Close()

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Handshake() }()

	assert.Error(t, client.Handshake())
	assert.NoError(t, <-serverErr)
}

// TestProgressionToProxy ensures that the proxied connection continues if the client never sends
// the completion signal. We test with a TCP listener as well to ensure that we are mirroring
// behavior of the origin server even when clients start a connection with something other than a
// TLS ClientHello.
func TestProgressionToProxy(t *testing.T) {
	listenTLS := func() (net.Listener, error) {
		return tls.Listen("tcp", "localhost:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	}
	dialTLS := func(network, address string) (net.Conn, error) {
		return tls.Dial(network, address, &tls.Config{InsecureSkipVerify: true})
	}
	listenTCP := func() (net.Listener, error) { return net.Listen("tcp", "localhost:0") }

	t.Run("client closes TLS", func(t *testing.T) { progressionToProxyHelper(t, listenTLS, dialTLS, true) })
	t.Run("server closes TLS", func(t *testing.T) { progressionToProxyHelper(t, listenTLS, dialTLS, false) })
	t.Run("client closes TCP", func(t *testing.T) { progressionToProxyHelper(t, listenTCP, net.Dial, true) })
	t.Run("server closes TCP", func(t *testing.T) { progressionToProxyHelper(t, listenTCP, net.Dial, false) })
}

func progressionToProxyHelper(t *testing.T, listen func() (net.Listener, error),
	dial func(network, address string) (net.Conn, error), clientCloses bool) {

	t.Helper()
	t.Parallel()

	var (
		secret               [52]byte
		clientMsg, serverMsg = "hello from the client", "hello from the server"
	)

	_, err := rand.Read(secret[:])
	require.NoError(t, err)

	origin, err := listen()
	require.NoError(t, err)
	dialOrigin := func(context.Context) (net.Conn, error) {
		return net.Dial("tcp", origin.Addr().String())
	}

	rcvdFromClient := make(chan string, 1)
	originErr := make(chan error, 1)
	go func() {
		originErr <- func() error {
			conn, err := origin.Accept()
			if err != nil {
				return fmt.Errorf("accept error: %w", err)
			}
			if clientCloses {
				t.Cleanup(func() { conn.Close() })
			} else {
				defer conn.Close()
			}

			b := make([]byte, len(clientMsg))
			n, err := conn.Read(b)
			if err != nil {
				return fmt.Errorf("read error: %w", err)
			}
			rcvdFromClient <- string(b[:n])

			if _, err := conn.Write([]byte(serverMsg)); err != nil {
				return fmt.Errorf("write error: %w", err)
			}
			return nil
		}()
	}()

	listenerCfg := ListenerConfig{DialOrigin: dialOrigin, Secret: secret}
	l, err := Listen("tcp", "localhost:0", listenerCfg)
	require.NoError(t, err)
	defer l.Close()

	// We expect the Handshake function to run for the duration of the test as it is serving as a
	// proxy to the origin.
	logger := testutil.NewSafeLogger(t)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			logger.Logf("listener accept error: %v", err)
			return
		}
		if err := conn.(Conn).Handshake(); err != nil {
			logger.Logf("listener handshake error: %v", err)
			return
		}
	}()

	rcvdFromServer, dialErr := func() (string, error) {
		conn, err := dial(l.Addr().Network(), l.Addr().String())
		if err != nil {
			return "", fmt.Errorf("dial error: %w", err)
		}
		if clientCloses {
			defer conn.Close()
		} else {
			t.Cleanup(func() { conn.Close() })
		}

		if _, err := conn.Write([]byte(clientMsg)); err != nil {
			return "", fmt.Errorf("write error: %w", err)
		}

		b := make([]byte, len(serverMsg))
		n, err := conn.Read(b)
		if err != nil {
			return "", fmt.Errorf("read error: %w", err)
		}
		return string(b[:n]), nil
	}()

	if allPassed(
		assert.NoError(t, dialErr),
		assert.NoError(t, <-originErr),
	) {
		assert.Equal(t, clientMsg, <-rcvdFromClient)
		assert.Equal(t, serverMsg, rcvdFromServer)
	}
}

type mitmListener struct {
	net.Listener
	onRead, onWrite func([]byte) error
}

func (l mitmListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return mitm(conn, l.onRead, l.onWrite), nil
}

type resumptionCheckingHandshaker struct {
	Config               *tls.Config
	resumedLastHandshake bool
}

func (h *resumptionCheckingHandshaker) Handshake(conn net.Conn) (*HandshakeResult, error) {
	tlsConn := tls.Client(conn, h.Config)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	h.resumedLastHandshake = tlsConn.ConnectionState().DidResume
	return &HandshakeResult{
		tlsConn.ConnectionState().Version, tlsConn.ConnectionState().CipherSuite,
	}, nil
}

// Intended to be used with testify/assert. For example:
//	if allPassed(
// 	  assert.NoError(t, foo()),
// 	  assert.NoError(t, bar()),
//   ) {
// 	  assert.NoError(t, onlyValidAfterFooBar())
//   }
func allPassed(bools ...bool) bool {
	for _, b := range bools {
		if !b {
			return false
		}
	}
	return true
}

func randomData(t *testing.T, len int) []byte {
	t.Helper()
	b := make([]byte, len)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}
