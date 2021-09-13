package tlsmasq

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"testing"

	"github.com/getlantern/tlsmasq/internal/testutil"
	"github.com/getlantern/tlsmasq/ptlshs"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHijack(t *testing.T) {
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

		clientMsg, serverMsg = "hello from the client", "hello from server"
		secret               ptlshs.Secret
	)
	_, err := rand.Read(secret[:])
	require.NoError(t, err)

	origin := testutil.StartOrigin(t, tlsCfg)
	clientTransport, serverTransport := testutil.BufferedPipe()
	clientConn := ptlshs.Client(clientTransport, ptlshs.DialerConfig{
		Handshaker: ptlshs.StdLibHandshaker{
			Config: tlsCfg,
		},
		Secret: secret,
	})
	serverConn := ptlshs.Server(serverTransport, ptlshs.ListenerConfig{
		DialOrigin: origin.DialContext,
		Secret:     secret,
	})
	defer clientConn.Close()
	defer serverConn.Close()

	serverErr := make(chan error, 1)
	msgFromClient := make(chan string, 1)
	go func() {
		serverErr <- func() error {
			_, err := hijack(serverConn, tlsCfg, secret, false)
			if err != nil {
				return fmt.Errorf("hijack failed: %w", err)
			}

			b := make([]byte, len(clientMsg))
			n, err := serverConn.Read(b)
			if err != nil {
				return fmt.Errorf("read failed: %w", err)
			}
			msgFromClient <- string(b[:n])

			_, err = serverConn.Write([]byte(serverMsg))
			if err != nil {
				return fmt.Errorf("write failed: %w", err)
			}
			return nil
		}()
	}()

	msgFromServer, clientErr := func() (string, error) {
		_, err = hijack(clientConn, tlsCfg, secret, true)
		if err != nil {
			return "", fmt.Errorf("hijack failed: %w", err)
		}

		_, err = clientConn.Write([]byte(clientMsg))
		if err != nil {
			return "", fmt.Errorf("write failed: %w", err)
		}

		b := make([]byte, len(serverMsg))
		n, err := clientConn.Read(b)
		if err != nil {
			return "", fmt.Errorf("read failed: %w", err)
		}
		return string(b[:n]), nil
	}()

	assert.NoError(t, clientErr)
	assert.NoError(t, <-serverErr)
	assert.Equal(t, clientMsg, <-msgFromClient)
	assert.Equal(t, serverMsg, msgFromServer)
}
