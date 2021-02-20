package tlsmasq

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/getlantern/tlsmasq/internal/testutil"
	"github.com/getlantern/tlsmasq/ptlshs"
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
		secret ptlshs.Secret
	)
	_, err := rand.Read(secret[:])
	require.NoError(t, err)

	serverToOrigin, originToServer := testutil.BufferedPipe()
	proxiedConn := tls.Server(originToServer, tlsCfg)
	go proxiedConn.Handshake()

	clientTransport, serverTransport := testutil.BufferedPipe()
	clientConn := Client(clientTransport, DialerConfig{
		TLSConfig: tlsCfg,
		ProxiedHandshakeConfig: ptlshs.DialerConfig{
			Handshaker: ptlshs.StdLibHandshaker{
				Config: tlsCfg,
			},
			Secret: secret,
		},
	})
	serverConn := Server(serverTransport, ListenerConfig{
		TLSConfig: tlsCfg,
		ProxiedHandshakeConfig: ptlshs.ListenerConfig{
			DialOrigin: func(_ context.Context) (net.Conn, error) {
				return serverToOrigin, nil
			},
			Secret: secret,
		},
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
