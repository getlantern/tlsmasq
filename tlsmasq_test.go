package tlsmasq

import (
	cryptoRand "crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/getlantern/tlsmasq/internal/testutil"
	"github.com/getlantern/tlsmasq/ptlshs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListenAndDial(t *testing.T) {
	t.Parallel()

	var (
		secret               [52]byte
		clientMsg, serverMsg = "hello from the client", "hello from the server"
	)

	_, err := cryptoRand.Read(secret[:])
	require.NoError(t, err)

	origin, err := testutil.StartOrigin(&tls.Config{Certificates: []tls.Certificate{testutil.Cert}})
	insecureTLSConfig := &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{testutil.Cert}}
	dialerCfg := DialerConfig{
		ProxiedHandshakeConfig: ptlshs.DialerConfig{
			Handshaker: ptlshs.StdLibHandshaker{
				Config: insecureTLSConfig,
			},
			Secret: secret,
		},
		TLSConfig: insecureTLSConfig,
	}
	listenerCfg := ListenerConfig{
		ProxiedHandshakeConfig: ptlshs.ListenerConfig{
			DialOrigin: origin.DialContext,
			Secret:     secret,
		},
		TLSConfig: insecureTLSConfig,
	}

	l, err := Listen("tcp", "localhost:0", listenerCfg)
	require.NoError(t, err)
	defer l.Close()

	serverErr := make(chan error, 1)
	msgFromClient := make(chan string, 1)
	go func() {
		serverErr <- func() error {
			conn, err := l.Accept()
			if err != nil {
				return fmt.Errorf("accept failed: %w", err)
			}
			defer conn.Close()

			b := make([]byte, len(clientMsg))
			n, err := conn.Read(b)
			if err != nil {
				return fmt.Errorf("read failed: %w", err)
			}
			msgFromClient <- string(b[:n])

			_, err = conn.Write([]byte(serverMsg))
			if err != nil {
				return fmt.Errorf("write failed: %w", err)
			}
			return nil
		}()
	}()

	msgFromServer, clientErr := func() (string, error) {
		conn, err := NewTlsMasqDialer(dialerCfg).Dial("tcp", l.Addr().String())
		if err != nil {
			return "", fmt.Errorf("dial failed: %w", err)
		}
		defer conn.Close()

		_, err = conn.Write([]byte(clientMsg))
		if err != nil {
			return "", fmt.Errorf("write failed: %w", err)
		}

		b := make([]byte, len(serverMsg))
		n, err := conn.Read(b)
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("read failed: %w", err)
		}
		return string(b[:n]), nil
	}()

	require.NoError(t, clientErr)
	require.NoError(t, <-serverErr)
	require.Equal(t, clientMsg, <-msgFromClient)
	require.Equal(t, serverMsg, msgFromServer)
}
