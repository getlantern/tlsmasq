package ptlshs

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/getlantern/tlsutil"
)

func TestListenAndDial(t *testing.T) {
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
	require.Equal(t, serverMsg, string(b[:n]))

	wg.Wait()
}

// TestSessionResumption ensures that ptlshs is compatible with TLS session resumption.
func TestSessionResumption(t *testing.T) {
	t.Parallel()

	var (
		wg      = new(sync.WaitGroup)
		timeout = time.Second

		secret [52]byte
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
			conn.SetDeadline(time.Now().Add(timeout))
			defer conn.Close()

			require.NoError(t, conn.(Conn).Handshake())
		}
	}()

	conn, err := DialTimeout("tcp", l.Addr().String(), dialerCfg, timeout)
	require.NoError(t, err)
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.Close()

	require.NoError(t, conn.(Conn).Handshake())
	require.NoError(t, conn.Close())

	// Dial a new connection with the same config. This should resume our session.
	conn, err = DialTimeout("tcp", l.Addr().String(), dialerCfg, timeout)
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
		timeout              = time.Second
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

		connState, err := tlsutil.NewConnectionState(serverHello.Version, serverHello.Suite, seq)
		require.NoError(t, err)

		lastN := 0
		results := tlsutil.ReadRecords(bytes.NewReader(b), connState, secret, iv)
		for _, result := range results {
			if result.Err != nil {
				// If we can't decrypt, assume this wasn't the signal.
				lastN = result.N
				continue
			}
			_, err := parseCompletionSignal(result.Data)
			if err != nil {
				// Again, assume this wasn't the signal.
				lastN = result.N
				continue
			}
			encryptedSignalChan <- b[lastN:result.N]
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
			go func(c net.Conn, connNumber int) {
				_, err = c.Write([]byte(serverMsg))
				if connNumber == 0 {
					require.NoError(t, err)
				} else {
					// The second one is supposed to fail.
					require.Error(t, err)
				}
			}(conn, i)
		}
	}()

	// Dial once so that our callbacks pick up the signal.
	dialerCfg := DialerConfig{
		Handshaker: StdLibHandshaker{&tls.Config{InsecureSkipVerify: true}},
		Secret:     secret,
	}
	conn, err := DialTimeout("tcp", l.Addr().String(), dialerCfg, timeout)
	require.NoError(t, err)
	require.NoError(t, conn.(Conn).Handshake())
	defer conn.Close()

	var encryptedSignal []byte
	select {
	case encryptedSignal = <-encryptedSignalChan:
	case <-time.After(timeout):
		t.Fatal("timed out waiting for captured signal")
	}

	// Now we dial again, but with a standard TLS dialer. This should get proxied through to the
	// TLS listener.
	conn, err = tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp", l.Addr().String(),
		&tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)
	conn.SetDeadline(time.Now().Add(timeout))

	// Now the server should be waiting for the completion signal. We replay the signal from before
	// and see how the server responds.
	_, err = conn.Write(encryptedSignal)
	require.NoError(t, err)

	b := make([]byte, len(originMsg))
	n, err := conn.Read(b)
	require.NoError(t, err)
	require.Equal(t, originMsg, string(b[:n]))
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
		wg      = new(sync.WaitGroup)
		timeout = time.Second

		secret               [52]byte
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
		conn.SetDeadline(time.Now().Add(timeout))
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
	conn.SetDeadline(time.Now().Add(timeout))
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
