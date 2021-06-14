package ptlshs

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/getlantern/tlsmasq/internal/testutil"
	"github.com/getlantern/tlsutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandshake(t *testing.T) {
	t.Parallel()

	// The choice of version and suite don't matter too much, but we will test with a suite
	// which uses the sequence number as a nonce to ensure that path is tested.
	const version, suite = tls.VersionTLS12, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256

	var (
		// The TLS config must allow for the version and suite we choose in the proxied handshake.
		// For simplicity, we use the same config for the proxied handshake and hijacking.
		tlsCfg = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         version,
			MaxVersion:         version,
			CipherSuites:       []uint16{suite},
			Certificates:       []tls.Certificate{cert},
		}
		secret Secret
	)
	_, err := rand.Read(secret[:])
	require.NoError(t, err)

	serverToOrigin, originToServer := testutil.BufferedPipe()
	proxiedConn := tls.Server(originToServer, tlsCfg)
	go proxiedConn.Handshake()
	defer serverToOrigin.Close()
	defer originToServer.Close()

	clientTransport, serverTransport := testutil.BufferedPipe()
	clientConn := Client(clientTransport, DialerConfig{secret, StdLibHandshaker{tlsCfg}, 0})
	serverConn := Server(serverTransport, ListenerConfig{
		func(_ context.Context) (net.Conn, error) { return serverToOrigin, nil },
		secret, 0, make(chan error),
	})
	defer serverConn.Close()
	defer clientConn.Close()

	serverErr := make(chan error, 1)
	go func() { serverErr <- serverConn.Handshake() }()
	assert.NoError(t, clientConn.Handshake())
	assert.NoError(t, <-serverErr)
}

// Tests the case in which the copy buffer used to read from the client connection is not large
// enough to hold the entire client signal. This was an oversight which created bugs in production.
//
// https://github.com/getlantern/tlsmasq/issues/17
func TestIssue17(t *testing.T) {
	t.Parallel()

	var (
		version          uint16 = tls.VersionTLS12
		suite            uint16 = tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
		secret1, secret2 [52]byte
		iv1, iv2         [16]byte
		seq1, seq2       [8]byte
	)
	for _, b := range [][]byte{secret1[:], secret2[:], iv1[:], iv2[:], seq1[:], seq2[:]} {
		_, err := rand.Read(b)
		require.NoError(t, err)
	}
	writerState, err := tlsutil.NewConnectionState(version, suite, secret2, iv2, seq2)
	require.NoError(t, err)
	readerState, err := tlsutil.NewConnectionState(version, suite, secret2, iv2, seq2)
	require.NoError(t, err)

	sig, err := newClientSignal(time.Hour)
	require.NoError(t, err)

	clientTransport, serverTransport := testutil.BufferedPipe()
	_, err = tlsutil.WriteRecord(clientTransport, *sig, writerState)
	require.NoError(t, err)

	conn := &serverConn{
		Conn:       serverTransport,
		nonceCache: newNonceCache(time.Hour),
	}
	require.NoError(t,
		conn.watchForCompletion(context.Background(), len(*sig)-1, readerState, newDummyOrigin()))
}

// Calling Close on a net.Conn should unblock any Read or Write operations.
func TestCloseUnblock(t *testing.T) {
	t.Run("Client", closeUnblockHelper(true))
	t.Run("Server", closeUnblockHelper(false))
}

func closeUnblockHelper(testClient bool) func(t *testing.T) {
	return func(t *testing.T) {
		t.Parallel()

		// To test whether Close unblocks pending I/O, we initiate a handshake with a peer speaking
		// plain TLS. The ptlshs side of the connection will hang waiting for the peer's completion
		// signal. Since the completion signal is specific to ptlshs, it will never be sent.

		const version, suite = tls.VersionTLS12, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
		var (
			tlsCfg = &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         version,
				MaxVersion:         version,
				CipherSuites:       []uint16{suite},
				Certificates:       []tls.Certificate{cert},
			}
			clientTransport, serverTransport = testutil.BufferedPipe()
			secret                           Secret
			testConn                         net.Conn
			peerConn                         *tls.Conn
		)
		_, err := rand.Read(secret[:])
		require.NoError(t, err)

		if testClient {
			testConn = Client(clientTransport, DialerConfig{secret, StdLibHandshaker{tlsCfg}, 0})
			peerConn = tls.Server(serverTransport, tlsCfg)
		} else {
			o := startOrigin(t, tlsCfg)
			peerConn = tls.Client(clientTransport, tlsCfg)
			testConn = Server(serverTransport, ListenerConfig{
				DialOrigin: o.dialContext, Secret: secret,
			})
		}
		defer testConn.Close()
		defer peerConn.Close()

		peerErrC := make(chan error)
		testErrC := make(chan error)
		go func() { peerErrC <- peerConn.Handshake() }()
		go func() { _, err := testConn.Read(make([]byte, 10)); testErrC <- err }()

		require.NoError(t, <-peerErrC)

		// The TLS handshake is complete, so testConn should hang, waiting for the completion signal.
		select {
		case err := <-testErrC:
			t.Fatalf("expected testConn.Read to be blocked, but got error: %v", err)
		default:
		}

		// Introduce a small, randomized delay in the hopes of catching the server at various points of
		// the ptlshs handshake across test runs.

		time.Sleep(randomDuration(t, 50*time.Millisecond))

		// Calling Close on testConn should cause Read to unblock and return an error.
		testConn.Close()
		require.Error(t, <-testErrC)
	}
}

// Serves as a TLS origin, allowing us to proxy handshakes. Will close when the test completes.
// TODO: replace other manually created origins
type tlsOrigin struct {
	net.Listener
}

func startOrigin(t *testing.T, cfg *tls.Config) tlsOrigin {
	t.Helper()

	l, err := tls.Listen("tcp", "localhost:0", cfg)
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })

	logger := newSafeLogger(t)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			logger.logf("origin accept error: %v", err)
			return
		}
		if err := conn.(*tls.Conn).Handshake(); err != nil {
			logger.logf("origin handshake error: %v", err)
			return
		}
	}()

	return tlsOrigin{l}
}

func (o tlsOrigin) dialContext(ctx context.Context) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", o.Addr().String())
}

// Used by TestIssue17
type dummyOrigin struct {
	closed chan struct{}
}

func newDummyOrigin() *dummyOrigin { return &dummyOrigin{make(chan struct{})} }

func (do *dummyOrigin) Read(_ []byte) (int, error) {
	<-do.closed
	return 0, io.EOF
}

func (do *dummyOrigin) Write(b []byte) (int, error) {
	select {
	case <-do.closed:
		return 0, io.ErrClosedPipe
	default:
		return len(b), nil
	}
}

func (do *dummyOrigin) Close() error {
	close(do.closed)
	return nil
}

func (do *dummyOrigin) LocalAddr() net.Addr                { return nil }
func (do *dummyOrigin) RemoteAddr() net.Addr               { return nil }
func (do *dummyOrigin) SetDeadline(_ time.Time) error      { return nil }
func (do *dummyOrigin) SetReadDeadline(_ time.Time) error  { return nil }
func (do *dummyOrigin) SetWriteDeadline(_ time.Time) error { return nil }

func randomDuration(t *testing.T, max time.Duration) time.Duration {
	t.Helper()
	n, err := randInt(0, int(max))
	require.NoError(t, err)
	return time.Duration(n)
}
