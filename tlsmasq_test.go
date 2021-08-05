package tlsmasq

import (
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/getlantern/tlsmasq/internal/testutil"
	"github.com/getlantern/tlsmasq/ptlshs"
	"github.com/getlantern/transports/pluggable"
	"github.com/getlantern/transports/pttls"
	"github.com/getlantern/transports/yamltypes"
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

	origin := testutil.StartOrigin(t, &tls.Config{Certificates: []tls.Certificate{cert}})
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
	assert.Equal(t, clientMsg, <-msgFromClient)
	assert.Equal(t, serverMsg, msgFromServer)
}

func TestTransport(t *testing.T) {
	s := ptlshs.Secret{}
	_, err := rand.Read(s[:])
	require.NoError(t, err)

	o := testutil.StartOrigin(t, &tls.Config{Certificates: []tls.Certificate{cert}})

	pluggable.TestTransport(
		t, Transport{},
		&tlsmasqListenerConfig{
			CommonListenerConfig: pluggable.CommonListenerConfig{
				Addr: "localhost:0",
			},
			OriginAddr:    o.Addr().String(),
			Secret:        yamltypes.NewBytes(s[:]),
			TLSMinVersion: yamltypes.NewUint16(tls.VersionTLS12),
			TLSSuites: yamltypes.NewUint16Slice([]uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			}),
		},
		func(listenerAddr string) interface{} {
			return &tlsmasqDialerConfig{
				CommonDialerConfig: pluggable.CommonDialerConfig{
					Addr: listenerAddr,
				},
				CommonTLSConfig: pttls.CommonTLSConfig{
					CertPEM:             string(certPem),
					ServerNameIndicator: "localhost",
					ClientHelloID:       "HelloChrome_Auto",
					DesktopOrderedCipherSuiteNames: []string{
						"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
						"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
						"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
						"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
					},
				},
				Secret:        yamltypes.NewBytes(s[:]),
				NonceTTL:      time.Hour,
				TLSMinVersion: yamltypes.NewUint16(tls.VersionTLS12),
				TLSSuites: yamltypes.NewUint16Slice([]uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				}),
			}
		},
	)
}
