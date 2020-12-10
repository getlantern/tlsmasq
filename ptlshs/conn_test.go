package ptlshs

import (
	"crypto/rand"
	"crypto/tls"
	mathrand "math/rand"
	"net"
	"testing"

	"github.com/getlantern/tlsmasq/internal/testutil"
	"github.com/getlantern/tlsutil"
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

	clientTransport, serverTransport := testutil.BufferedPipe()
	clientConn := Client(clientTransport, DialerConfig{secret, StdLibHandshaker{tlsCfg}, 0})
	serverConn := Server(serverTransport, ListenerConfig{
		func() (net.Conn, error) { return serverToOrigin, nil }, secret, 0, make(chan error)},
	)

	done := make(chan struct{})
	go func() {
		defer close(done)
		require.NoError(t, serverConn.Handshake())
	}()

	require.NoError(t, clientConn.Handshake())
	<-done
}

// TestPostHandshakeGarbage ensures that the connection is closed if garbage data is injected
// between the origin's ServerFinished messaged and the server's completion signal. Otherwise, a bad
// actor could inject such garbage data to determine whether a connection is a tlsmasq connection.
func TestPostHandshakeGarbage(t *testing.T) {
	var (
		version uint16 = tls.VersionTLS12
		suite          = tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
		secret  [52]byte
		iv      [16]byte
		seq     [8]byte

		badSecret [52]byte
		badIV     [16]byte
		badSeq    [8]byte
	)
	for _, b := range [][]byte{secret[:], iv[:], seq[:], badSecret[:], badIV[:], badSeq[:]} {
		_, err := rand.Read(b)
		require.NoError(t, err)
	}
	clientState, err := tlsutil.NewConnectionState(version, suite, secret, iv, seq)
	require.NoError(t, err)
	serverState, err := tlsutil.NewConnectionState(version, suite, secret, iv, seq)
	require.NoError(t, err)
	badServerState, err := tlsutil.NewConnectionState(version, suite, badSecret, badIV, badSeq)
	require.NoError(t, err)

	clientTCP, serverTCP := net.Pipe()
	client := Client(clientTCP, DialerConfig{}).(*clientConn)

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		// Write some garbage, then the completion signal. If the garbage data is not in a TLS
		// record, the connection may hang (as it awaits the rest of the data in the "record"). This
		// is acceptable as far as we're concerned, but makes testing harder. Instead we send a
		// record encrypted with a different set of parameters. The client will still get the
		// garbage data, but not hang.
		_, err := tlsutil.WriteRecord(serverTCP, randomData(t, mathrand.Intn(32*1024)), badServerState)
		require.NoError(t, err)
		require.NoError(t, err)
		signal, err := newServerCompletionSignal()
		require.NoError(t, err)
		_, err = tlsutil.WriteRecord(serverTCP, *signal, serverState)
		require.NoError(t, err)
	}()

	_, err = client.watchForCompletion(clientState)
	require.Error(t, err)

	<-serverDone
}
