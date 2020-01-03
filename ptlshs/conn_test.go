package ptlshs

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"net"
	"testing"

	"github.com/getlantern/tlsmasq/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestHandshake(t *testing.T) {
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

		// Not testing nonce logic.
		isValidNonce = func(n Nonce) bool { return true }

		secret Secret
	)
	_, err := rand.Read(secret[:])
	require.NoError(t, err)

	serverToProxied, proxiedToServer := testutil.BufferedPipe()
	proxiedConn := tls.Server(proxiedToServer, tlsCfg)
	go proxiedConn.Handshake()

	clientTransport, serverTransport := testutil.BufferedPipe()
	clientConn := Client(clientTransport, tlsCfg, secret, 0)
	serverConn := Server(serverTransport, serverToProxied, secret, isValidNonce, make(chan error))

	done := make(chan struct{})
	go func() {
		defer close(done)
		require.NoError(t, serverConn.Handshake())
	}()

	require.NoError(t, clientConn.Handshake())
	<-done
}

// Like net.Pipe(), but with internal buffering on writes. In practice, our connections are
// generally TCP connections, for which writes will not block.
func nonBlockingPipe() (net.Conn, net.Conn) {
	rx, tx := net.Pipe()
	return newBufferedConn(rx), newBufferedConn(tx)
}

// Buffers writes to the connection.
type bufferedConn struct {
	net.Conn
	bufW *bufio.Writer
}

func newBufferedConn(conn net.Conn) bufferedConn {
	return bufferedConn{conn, bufio.NewWriter(conn)}
}

func (conn bufferedConn) Write(b []byte) (n int, err error) {
	n, err = conn.bufW.Write(b)
	go conn.bufW.Flush()
	return
}
