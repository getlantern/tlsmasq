package ptlshs

import (
	"context"
	cryptoRand "crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/getlantern/nettest"
	"github.com/getlantern/tlsmasq/internal/testutil"
	"github.com/getlantern/tlsutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConn(t *testing.T) {
	pm := pipeMaker{
		t:            t,
		originConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	t.Run("ClientFirst", func(t *testing.T) { nettest.TestConn(t, pm.clientFirstPipe) })
	t.Run("ServerFirst", func(t *testing.T) { nettest.TestConn(t, pm.serverFirstPipe) })
}

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
	_, err := cryptoRand.Read(secret[:])
	require.NoError(t, err)

	origin := testutil.StartOrigin(t, tlsCfg, nil)
	clientTransport, serverTransport := testutil.BufferedPipe()
	clientConn := Client(clientTransport, DialerConfig{secret, StdLibHandshaker{tlsCfg}, 0, false, nil, cryptoRand.Reader})
	serverConn := Server(serverTransport, ListenerConfig{
		DialOrigin: origin.DialContext,
		Secret:     secret,
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
		_, err := cryptoRand.Read(b)
		require.NoError(t, err)
	}
	writerState, err := tlsutil.NewConnectionState(version, suite, secret2, iv2, seq2, cryptoRand.Reader)
	require.NoError(t, err)
	readerState, err := tlsutil.NewConnectionState(version, suite, secret2, iv2, seq2, cryptoRand.Reader)
	require.NoError(t, err)

	sig, err := newClientSignal(cryptoRand.Reader, time.Hour)
	require.NoError(t, err)

	clientTransport, serverTransport := testutil.BufferedPipe()
	_, err = tlsutil.WriteRecord(clientTransport, *sig, writerState)
	require.NoError(t, err)

	conn := &serverConn{
		wrapped:    serverTransport,
		nonceCache: newNonceCache(time.Hour),
	}
	require.NoError(t,
		conn.watchForCompletion(context.Background(), len(*sig)-1, readerState, newDummyOrigin()))
}

// Ensures that timeouts and calls to Close cause Read and Write calls to unblock.
func TestUnblock(t *testing.T) {
	t.Run("ClientClose", testUnblockHelper(true, true))
	t.Run("ServerClose", testUnblockHelper(false, true))
	t.Run("ClientTimeout", testUnblockHelper(true, false))
	t.Run("ServerTimeout", testUnblockHelper(false, false))
}

// testClient == false => test server-side
// testClose == false => test timeout
func testUnblockHelper(testClient, testClose bool) func(t *testing.T) {
	var inThePast = time.Now().Add(-1 * time.Hour)

	return func(t *testing.T) {
		t.Parallel()

		// To test whether we can unblock pending I/O, we initiate a handshake with a peer speaking
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
		_, err := cryptoRand.Read(secret[:])
		require.NoError(t, err)

		if testClient {
			testConn = Client(clientTransport, DialerConfig{secret, StdLibHandshaker{tlsCfg}, 0, false, nil, cryptoRand.Reader})
			peerConn = tls.Server(serverTransport, tlsCfg)
		} else {
			origin := testutil.StartOrigin(t, tlsCfg, nil)
			peerConn = tls.Client(clientTransport, tlsCfg)
			testConn = Server(serverTransport, ListenerConfig{origin.DialContext, secret, 0, nil, false, nil, cryptoRand.Reader})
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

		// Introduce a small, randomized delay in the hopes of catching the server at various points
		// of the ptlshs handshake across test runs.

		time.Sleep(randomDuration(t, 50*time.Millisecond))

		if testClose {
			testConn.Close()
			require.ErrorIs(t, <-testErrC, net.ErrClosed)
		} else {
			testConn.SetDeadline(inThePast)
			require.ErrorIs(t, <-testErrC, os.ErrDeadlineExceeded)
		}
	}
}

type pipeMaker struct {
	t            *testing.T
	originConfig *tls.Config
}

// Implements nettest.MakePipe.
func (pm pipeMaker) makePipe() (client, server net.Conn, stop func(), err error) {
	var secret Secret
	if _, err := cryptoRand.Read(secret[:]); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate secret: %w", err)
	}

	origin := testutil.StartOrigin(pm.t, pm.originConfig.Clone(), nil)
	dCfg := DialerConfig{secret, StdLibHandshaker{Config: &tls.Config{InsecureSkipVerify: true}}, 0, false, nil, cryptoRand.Reader}
	lCfg := ListenerConfig{origin.DialContext, secret, 0, nil, false, nil, cryptoRand.Reader}

	clientTransport, serverTransport := net.Pipe()
	client = Client(clientTransport, dCfg)
	server = Server(serverTransport, lCfg)
	stop = func() { client.Close(); server.Close() }

	// We execute the handshake before returning the piped connections. Ideally the tests defined in
	// nettest.TestConn would pass without this step. However, making this happen would require
	// significant additional complexity which is probably not useful in practice. A pipe of
	// tls.Conn instances would suffer from the same issues (and more), so we are in good company.

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.(Conn).Handshake() }()
	if err := client.(Conn).Handshake(); err != nil {
		stop()
		return nil, nil, nil, fmt.Errorf("client handshake error: %w", err)
	}
	if err := <-serverErr; err != nil {
		stop()
		return nil, nil, nil, fmt.Errorf("server handshake error: %w", err)
	}

	return client, server, stop, nil
}

// nettest.TestConn focuses on the first connection of the pair. We want to test both the client-
// side and server-side connections, so we have separate make-pipe functions for each purpose.

func (pm pipeMaker) clientFirstPipe() (client, server net.Conn, stop func(), err error) {
	return pm.makePipe()
}

func (pm pipeMaker) serverFirstPipe() (server, client net.Conn, stop func(), err error) {
	client, server, stop, err = pm.clientFirstPipe()
	return
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
	n, err := randInt(cryptoRand.Reader, 0, int(max))
	require.NoError(t, err)
	return time.Duration(n)
}
