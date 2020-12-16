package ptlshs

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"io"
	mathrand "math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/getlantern/tlsmasq/internal/testutil"
	"github.com/getlantern/tlsutil"
)

func TestListenAndDial(t *testing.T) {
	t.Parallel()

	var (
		secret               [52]byte
		wg                   = new(sync.WaitGroup)
		clientMsg, serverMsg = "hello from the client", "hello from the server"
	)
	_, err := rand.Read(secret[:])
	require.NoError(t, err)

	origin, err := tls.Listen("tcp", "localhost:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	dialOrigin := func() (net.Conn, error) { return net.Dial("tcp", origin.Addr().String()) }

	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := origin.Accept()
		require.NoError(t, err)
		require.NoError(t, conn.(*tls.Conn).Handshake())
	}()

	dialerCfg := DialerConfig{
		Handshaker: StdLibHandshaker{
			Config: &tls.Config{InsecureSkipVerify: true},
		},
		Secret: secret,
	}
	listenerCfg := ListenerConfig{DialOrigin: dialOrigin, Secret: secret}

	l, err := Listen("tcp", "localhost:0", listenerCfg)
	require.NoError(t, err)
	defer l.Close()

	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := l.Accept()
		require.NoError(t, err)
		defer conn.Close()

		b := make([]byte, len(clientMsg))
		n, err := conn.Read(b)
		require.NoError(t, err)
		require.Equal(t, clientMsg, string(b[:n]))

		_, err = conn.Write([]byte(serverMsg))
		require.NoError(t, err)
	}()

	conn, err := Dial("tcp", l.Addr().String(), dialerCfg)
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte(clientMsg))
	require.NoError(t, err)

	b := make([]byte, len(serverMsg))
	n, err := conn.Read(b)
	require.NoError(t, err)
	require.Equal(t, serverMsg, string(b[:n]))

	wg.Wait()
}

// TestSessionResumption ensures that ptlshs is compatible with TLS session resumption.
func TestSessionResumption(t *testing.T) {
	t.Parallel()

	var (
		secret [52]byte
		wg     = new(sync.WaitGroup)
	)
	_, err := rand.Read(secret[:])
	require.NoError(t, err)

	origin, err := tls.Listen("tcp", "localhost:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	dialOrigin := func() (net.Conn, error) { return net.Dial("tcp", origin.Addr().String()) }

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 2; i++ {
			conn, err := origin.Accept()
			require.NoError(t, err)
			require.NoError(t, conn.(*tls.Conn).Handshake())
		}
	}()

	handshaker := &resumptionCheckingHandshaker{
		Config: &tls.Config{
			InsecureSkipVerify: true,
			ClientSessionCache: tls.NewLRUClientSessionCache(10),
			MaxVersion:         tls.VersionTLS12,
		},
	}
	dialerCfg := DialerConfig{secret, handshaker, 0}
	listenerCfg := ListenerConfig{DialOrigin: dialOrigin, Secret: secret}

	l, err := Listen("tcp", "localhost:0", listenerCfg)
	require.NoError(t, err)
	defer l.Close()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 2; i++ {
			conn, err := l.Accept()
			require.NoError(t, err)
			defer conn.Close()

			require.NoError(t, conn.(Conn).Handshake())
		}
	}()

	conn, err := Dial("tcp", l.Addr().String(), dialerCfg)
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.(Conn).Handshake())
	require.NoError(t, conn.Close())

	// Dial a new connection with the same config. This should resume our session.
	conn, err = Dial("tcp", l.Addr().String(), dialerCfg)
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.(Conn).Handshake())
	require.True(t, handshaker.resumedLastHandshake)

	wg.Wait()
}

func TestSignalReplay(t *testing.T) {
	t.Parallel()

	var (
		secret               [52]byte
		serverMsg, originMsg = "hello from the real server", "hello from the origin"
	)

	_, err := rand.Read(secret[:])
	require.NoError(t, err)

	origin, err := tls.Listen("tcp", "localhost:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	dialOrigin := func() (net.Conn, error) { return net.Dial("tcp", origin.Addr().String()) }

	go func() {
		for i := 0; i < 2; i++ {
			conn, err := origin.Accept()
			require.NoError(t, err)

			go func(c net.Conn) {
				require.NoError(t, c.(*tls.Conn).Handshake())
				_, err = c.Write([]byte(originMsg))
				require.NoError(t, err)
			}(conn)
		}
	}()

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
		require.NoError(t, err)
		return nil
	}
	onServerRead := func(b []byte) error {
		serverHelloMu.Lock()
		defer serverHelloMu.Unlock()
		if serverHello == nil {
			return nil
		}

		seq, iv, err := deriveSeqAndIV(serverHello.Random)
		require.NoError(t, err)

		connState, err := tlsutil.NewConnectionState(
			serverHello.Version, serverHello.Suite, secret, iv, seq)
		require.NoError(t, err)

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

	listenerCfg := ListenerConfig{DialOrigin: dialOrigin, Secret: secret}
	l := WrapListener(mitmListener{_l, onServerRead, onServerWrite}, listenerCfg)
	defer l.Close()

	go func() {
		for i := 0; i < 2; i++ {
			conn, err := l.Accept()
			require.NoError(t, err)
			go func() {
				// Try to write, but don't check for write errors. This message will only make it to
				// the client if our replay detection is broken. We would see it in a check below.
				conn.Write([]byte(serverMsg))
			}()
		}
	}()

	// Dial once so that our callbacks pick up the signal.
	dialerCfg := DialerConfig{
		Handshaker: StdLibHandshaker{&tls.Config{InsecureSkipVerify: true}},
		Secret:     secret,
	}
	conn, err := Dial("tcp", l.Addr().String(), dialerCfg)
	require.NoError(t, err)
	require.NoError(t, conn.(Conn).Handshake())
	defer conn.Close()

	encryptedSignal := <-encryptedSignalChan

	// Now we dial again, but with a standard TLS dialer. This should get proxied through to the
	// TLS listener.
	conn, err = tls.DialWithDialer(
		&net.Dialer{},
		"tcp", l.Addr().String(),
		&tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)

	// Now the server should be waiting for the completion signal. We replay the signal from before
	// and see how the server responds.
	_, err = conn.Write(encryptedSignal)
	require.NoError(t, err)

	b := make([]byte, len(originMsg))
	n, err := conn.Read(b)
	require.NoError(t, err)
	require.Equal(t, originMsg, string(b[:n]))
}

// TestPostHandshakeData ensures that tlsmasq connections are resilient to origins sending data
// after the handshake has completed. This data should not make it to the client as this would
// constitute unexpected data and could disrupt the next phase of the connection.
func TestPostHandshakeData(t *testing.T) {
	t.Parallel()

	var (
		wg      = new(sync.WaitGroup)
		timeout = time.Second

		secret               [52]byte
		clientMsg, serverMsg = "hello from the client", "hello from the server"
	)
	_, err := rand.Read(secret[:])
	require.NoError(t, err)

	origin, err := tls.Listen("tcp", "localhost:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	dialOrigin := func() (net.Conn, error) { return net.Dial("tcp", origin.Addr().String()) }

	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := origin.Accept()
		require.NoError(t, err)
		require.NoError(t, conn.(*tls.Conn).Handshake())
		// Immediately send some data.
		_, err = conn.Write([]byte("some nonsense from the origin"))
		require.NoError(t, err)
	}()

	dialerCfg := DialerConfig{
		Handshaker: StdLibHandshaker{
			Config: &tls.Config{InsecureSkipVerify: true},
		},
		Secret: secret,
	}
	listenerCfg := ListenerConfig{DialOrigin: dialOrigin, Secret: secret}

	l, err := Listen("tcp", "localhost:0", listenerCfg)
	require.NoError(t, err)
	defer l.Close()

	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := l.Accept()
		require.NoError(t, err)
		conn.SetDeadline(time.Now().Add(timeout))
		defer conn.Close()

		b := make([]byte, len(clientMsg))
		n, err := conn.Read(b)
		require.NoError(t, err)
		require.Equal(t, clientMsg, string(b[:n]))

		_, err = conn.Write([]byte(serverMsg))
		require.NoError(t, err)
	}()

	conn, err := DialTimeout("tcp", l.Addr().String(), dialerCfg, timeout)
	require.NoError(t, err)
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.Close()

	_, err = conn.Write([]byte(clientMsg))
	require.NoError(t, err)

	b := make([]byte, len(serverMsg))
	n, err := conn.Read(b)
	require.NoError(t, err)
	// This is where we would see the unexpected data from the origin (wrapped in a TLS record).
	require.Equal(t, serverMsg, string(b[:n]))

	wg.Wait()
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

	var (
		wg = new(sync.WaitGroup)

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

	origin, err := tls.Listen("tcp", "localhost:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	dialOrigin := func() (net.Conn, error) { return net.Dial("tcp", origin.Addr().String()) }

	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := origin.Accept()
		require.NoError(t, err)
		require.NoError(t, conn.(*tls.Conn).Handshake())
	}()

	dialerCfg := DialerConfig{
		Handshaker: StdLibHandshaker{
			Config: &tls.Config{InsecureSkipVerify: true},
		},
		Secret: secret,
	}
	listenerCfg := ListenerConfig{DialOrigin: dialOrigin, Secret: secret}

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
		require.NoError(t, err)
		return nil
	}
	onServerRead := func(b []byte) error {
		serverHelloMu.Lock()
		defer serverHelloMu.Unlock()
		if serverHello == nil {
			return nil
		}

		seq, iv, err := deriveSeqAndIV(serverHello.Random)
		require.NoError(t, err)

		connState, err := tlsutil.NewConnectionState(
			serverHello.Version, serverHello.Suite, secret, iv, seq)
		require.NoError(t, err)

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
			_, err = tlsutil.WriteRecord(_server, randomData(t, 1024+mathrand.Intn(31*1024)), injectorState)
			require.NoError(t, err)
		}
		return nil
	}

	client := Client(_client, dialerCfg)
	server := Server(mitm(_server, onServerRead, onServerWrite), listenerCfg)
	defer server.Close()
	defer client.Close()

	wg.Add(1)
	go func() {
		defer wg.Done()
		server.Handshake()
	}()

	require.Error(t, client.Handshake())
	wg.Wait()
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
		wg                   = new(sync.WaitGroup)
		clientMsg, serverMsg = "hello from the client", "hello from the server"
	)

	_, err := rand.Read(secret[:])
	require.NoError(t, err)

	origin, err := listen()
	require.NoError(t, err)
	dialOrigin := func() (net.Conn, error) { return net.Dial("tcp", origin.Addr().String()) }

	wg.Add(1)
	go func() {
		defer wg.Done()

		conn, err := origin.Accept()
		require.NoError(t, err)
		if !clientCloses {
			defer conn.Close()
		}

		b := make([]byte, len(clientMsg))
		n, err := conn.Read(b)
		require.NoError(t, err)
		require.Equal(t, clientMsg, string(b[:n]))

		_, err = conn.Write([]byte(serverMsg))
		require.NoError(t, err)
	}()

	listenerCfg := ListenerConfig{DialOrigin: dialOrigin, Secret: secret}
	l, err := Listen("tcp", "localhost:0", listenerCfg)
	require.NoError(t, err)
	defer l.Close()

	// We expect the Handshake function to run for the duration of the test as it is serving as a
	// proxy to the origin.
	wg.Add(1)
	go func() {
		conn, err := l.Accept()
		require.NoError(t, err)
		conn.(Conn).Handshake()
		wg.Done()
	}()

	conn, err := dial(l.Addr().Network(), l.Addr().String())
	require.NoError(t, err)
	if clientCloses {
		defer conn.Close()
	}

	_, err = conn.Write([]byte(clientMsg))
	require.NoError(t, err)

	b := make([]byte, len(serverMsg))
	n, err := conn.Read(b)
	require.NoError(t, err)
	require.Equal(t, serverMsg, string(b[:n]))
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

func randomData(t *testing.T, len int) []byte {
	t.Helper()
	b := make([]byte, len)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}
