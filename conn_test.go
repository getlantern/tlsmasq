package tlsmasq

import (
	"crypto/rand"
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/tlsmasq/internal/testutil"
	"github.com/getlantern/tlsmasq/ptlshs"
)

// n.b. We would ideally test the Conn type with nettest.TestConn. However, the underlying tls.Conn
// does not pass nettest.TestConn, preventing us from utilizing the test ourselves.

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
			Certificates:       []tls.Certificate{testutil.Cert},
		}
		secret ptlshs.Secret
	)
	_, err := rand.Read(secret[:])
	require.NoError(t, err)

	origin, err := testutil.StartOrigin(tlsCfg)
	require.NoError(t, err)
	defer origin.Close()
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
	defer clientConn.Close()

	listenerCfg := ListenerConfig{
		TLSConfig: tlsCfg,
		ProxiedHandshakeConfig: ptlshs.ListenerConfig{
			DialOrigin: origin.DialContext,
			Secret:     secret,
		},
	}
	serverConn := newConn(
		ptlshs.Server(
			serverTransport,
			listenerCfg.ProxiedHandshakeConfig),
		listenerCfg.TLSConfig, false,
		listenerCfg.ProxiedHandshakeConfig.Secret,
	)
	defer serverConn.Close()

	serverErr := make(chan error, 1)
	go func() { serverErr <- serverConn.Handshake() }()

	assert.NoError(t, clientConn.Handshake())
	assert.NoError(t, <-serverErr)
}
