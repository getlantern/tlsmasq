package ptlshs

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/getlantern/tlsmasq/internal/testutil"
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

	done := make(chan struct{})
	go func() {
		defer close(done)
		require.NoError(t, serverConn.Handshake())
	}()

	require.NoError(t, clientConn.Handshake())
	<-done
}

// Calling Close on a net.Conn should unblock any Read or Write operations.
func TestCloseUnblock(t *testing.T) {
	t.Parallel()

	const version, suite = tls.VersionTLS12, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
	var (
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

	// Rather than connecting to an actual ptlshs server, we connect a client to a plain TLS server.
	// The client will get the ServerHello, then hang waiting for the server's completion signal
	// (since the completion signal is specific to ptlshs, it will never be sent).
	clientTransport, serverTransport := testutil.BufferedPipe()
	clientConn := Client(clientTransport, DialerConfig{secret, StdLibHandshaker{tlsCfg}, 0})
	serverConn := tls.Server(serverTransport, tlsCfg)
	defer serverConn.Close()
	defer clientConn.Close()

	serverErrC := make(chan error)
	readErrC := make(chan error)
	go func() {
		serverErrC <- serverConn.Handshake()
	}()
	go func() {
		// n.b. Calling Read will initiate a ptlshs handshake from the client.
		_, err := clientConn.Read(make([]byte, 10))
		readErrC <- err
	}()

	require.NoError(t, <-serverErrC)
	// Introduce a small delay to ensure the client begins waiting for the completion signal.
	time.Sleep(50 * time.Millisecond)
	clientConn.Close()

	// Calling Close on clientConn should have caused Read to unblock and return an error.
	require.Error(t, <-readErrC)
}
