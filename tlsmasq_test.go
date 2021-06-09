package tlsmasq

import (
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/getlantern/tlsmasq/ptlshs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListenAndDial(t *testing.T) {
	t.Parallel()

	var (
		secret               [52]byte
		wg                   = new(sync.WaitGroup)
		clientMsg, serverMsg = "hello from the client", "hello from the server"
	)

	_, err := rand.Read(secret[:])
	require.NoError(t, err)

	origin, err := tls.Listen("tcp", "localhost:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	dialOrigin := func() (net.Conn, error) { return net.Dial("tcp", origin.Addr().String()) }

	wg.Add(1)
	go func() {
		defer wg.Done()

		conn, err := origin.Accept()
		if !assert.NoError(t, err) {
			return
		}
		assert.NoError(t, conn.(*tls.Conn).Handshake())
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

	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := l.Accept()
		if !assert.NoError(t, err) {
			return
		}
		defer conn.Close()

		b := make([]byte, len(clientMsg))
		n, err := conn.Read(b)
		if !assert.NoError(t, err) {
			return
		}
		if !assert.Equal(t, clientMsg, string(b[:n])) {
			return
		}

		_, err = conn.Write([]byte(serverMsg))
		assert.NoError(t, err)
	}()

	conn, err := Dial("tcp", l.Addr().String(), dialerCfg)
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte(clientMsg))
	require.NoError(t, err)

	b := make([]byte, len(serverMsg))
	n, err := conn.Read(b)
	require.True(t, err == nil || err == io.EOF, "unexpected error: %v", err)
	require.Equal(t, serverMsg, string(b[:n]))

	wg.Wait()
}
