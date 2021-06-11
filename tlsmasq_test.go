package tlsmasq

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/getlantern/tlsmasq/ptlshs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListenAndDial(t *testing.T) {
	t.Parallel()

	var (
		secret [52]byte
		// wg                   = new(sync.WaitGroup)
		clientMsg, serverMsg = "hello from the client", "hello from the server"
	)

	_, err := rand.Read(secret[:])
	require.NoError(t, err)

	origin, err := tls.Listen("tcp", "localhost:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	dialOrigin := func(_ context.Context) (net.Conn, error) {
		return net.Dial("tcp", origin.Addr().String())
	}

	originErr := make(chan error, 1)
	go func() {
		originErr <- func() error {
			conn, err := origin.Accept()
			if err != nil {
				return fmt.Errorf("accept failed: %w", err)
			}
			if err := conn.(*tls.Conn).Handshake(); err != nil {
				return fmt.Errorf("handshake failed: %w", err)
			}
			return nil
		}()
	}()

	insecureTLSConfig := &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{cert}}
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
			DialOrigin: dialOrigin,
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
		conn, err := Dial("tcp", l.Addr().String(), dialerCfg)
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

	assert.NoError(t, clientErr)
	assert.NoError(t, <-serverErr)
	assert.NoError(t, <-originErr)
	assert.Equal(t, clientMsg, <-msgFromClient)
	assert.Equal(t, serverMsg, msgFromServer)
}
