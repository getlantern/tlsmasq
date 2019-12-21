package tlsmasq

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/getlantern/tlsmasq/ptlshs"
	"github.com/stretchr/testify/require"
)

func TestListenAndDial(t *testing.T) {
	t.Parallel()

	var (
		wg      = new(sync.WaitGroup)
		timeout = time.Second

		secret               [52]byte
		clientMsg, serverMsg = "hello from the client", "hello from the server"
	)

	_, err := rand.Read(secret[:])
	require.NoError(t, err)

	proxiedL, err := tls.Listen("tcp", "localhost:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	dialProxied := func() (net.Conn, error) { return net.Dial("tcp", proxiedL.Addr().String()) }

	wg.Add(1)
	go func() {
		defer wg.Done()

		conn, err := proxiedL.Accept()
		require.NoError(t, err)
		require.NoError(t, conn.(*tls.Conn).Handshake())
	}()

	insecureTLSConfig := &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{cert}}
	dialerOpts := DialerOpts{
		ProxiedHandshakeOpts: ptlshs.DialerOpts{
			TLSConfig: insecureTLSConfig,
			Secret:    secret,
		},
		TLSConfig: insecureTLSConfig,
	}
	listenerOpts := ListenerOpts{
		ProxiedHandshakeOpts: ptlshs.ListenerOpts{
			DialProxied: dialProxied,
			Secret:      secret,
		},
		TLSConfig: insecureTLSConfig,
	}

	l, err := Listen("tcp", "localhost:0", listenerOpts)
	require.NoError(t, err)
	defer l.Close()

	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := l.Accept()
		require.NoError(t, err)
		conn.SetDeadline(time.Now().Add(timeout))
		defer conn.Close()

		b := make([]byte, len(clientMsg))
		n, err := conn.Read(b)
		require.NoError(t, err)
		require.Equal(t, clientMsg, string(b[:n]))

		_, err = conn.Write([]byte(serverMsg))
		require.NoError(t, err)
	}()

	conn, err := DialTimeout("tcp", l.Addr().String(), dialerOpts, timeout)
	require.NoError(t, err)
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.Close()

	_, err = conn.Write([]byte(clientMsg))
	require.NoError(t, err)

	b := make([]byte, len(serverMsg))
	n, err := conn.Read(b)
	require.True(t, err == nil || err == io.EOF, "unexpected error: %v", err)
	require.Equal(t, serverMsg, string(b[:n]))

	wg.Wait()
}

func TestDialTimeout(t *testing.T) {
	t.Parallel()
	const timeout = 100 * time.Millisecond

	type dialFn func(network, address string, timeout time.Duration) (net.Conn, error)
	testFunc := func(dial dialFn) func(t *testing.T) {
		return func(t *testing.T) {
			t.Helper()
			t.Parallel()

			l, err := net.Listen("tcp", "localhost:0")
			require.NoError(t, err)
			defer l.Close()

			started := make(chan struct{})
			errc := make(chan error)
			go func() {
				close(started)
				_, err := dial("tcp", l.Addr().String(), timeout)
				errc <- err
			}()

			<-started
			select {
			case <-time.After(2 * timeout):
				t.Fatal("dial should have timed out by now")
			case err := <-errc:
				require.Error(t, err)
				require.Implements(t, (*net.Error)(nil), err, "err: %v", err)
				require.True(t, err.(net.Error).Timeout())
			}
		}
	}
	dialerOpts := DialerOpts{
		ProxiedHandshakeOpts: ptlshs.DialerOpts{TLSConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	t.Run("via argument", testFunc(func(network, address string, timeout time.Duration) (net.Conn, error) {
		return DialTimeout(network, address, dialerOpts, timeout)
	}))
	t.Run("via dialer", testFunc(func(network, address string, timeout time.Duration) (net.Conn, error) {
		return WrapDialer(&net.Dialer{Timeout: timeout}, dialerOpts).Dial(network, address)
	}))
	t.Run("earlier dialer", testFunc(func(network, address string, timeout time.Duration) (net.Conn, error) {
		// The earlier timeout on the dialer should be respected.
		ctx, cancel := context.WithTimeout(context.Background(), timeout*10)
		defer cancel()
		return WrapDialer(&net.Dialer{Timeout: timeout}, dialerOpts).DialContext(ctx, network, address)
	}))
	t.Run("earlier context", testFunc(func(network, address string, timeout time.Duration) (net.Conn, error) {
		// The earlier timeout on the context should be respected.
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return WrapDialer(&net.Dialer{Timeout: timeout * 10}, dialerOpts).DialContext(ctx, network, address)
	}))
}

func TestDialContext(t *testing.T) {
	t.Parallel()

	dialerOpts := DialerOpts{
		ProxiedHandshakeOpts: ptlshs.DialerOpts{
			TLSConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	defer l.Close()

	started := make(chan struct{})
	errc := make(chan error)
	go func() {
		close(started)
		_, err := WrapDialer(&net.Dialer{}, dialerOpts).DialContext(ctx, "tcp", l.Addr().String())
		errc <- err
	}()

	<-started
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-time.After(200 * time.Millisecond):
		t.Fatal("dial should have respected cancel by now")
	case err := <-errc:
		require.Equal(t, context.Canceled, err)
	}
}
