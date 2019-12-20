package ptlshs

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/getlantern/tlsmasq/internal/reptls"
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

	dialerOpts := DialerOpts{TLSConfig: &tls.Config{InsecureSkipVerify: true}, Secret: secret}
	listenerOpts := ListenerOpts{DialProxied: dialProxied, Secret: secret}

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
	require.NoError(t, err)
	require.Equal(t, serverMsg, string(b[:n]))

	wg.Wait()
}

func TestSignalReplay(t *testing.T) {
	t.Parallel()

	var (
		secret                      [52]byte
		timeout                     = time.Second
		serverMsg, proxiedServerMsg = "hello from the real server", "hello from the proxied server"
	)

	_, err := rand.Read(secret[:])
	require.NoError(t, err)

	proxiedL, err := tls.Listen("tcp", "localhost:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	dialProxied := func() (net.Conn, error) { return net.Dial("tcp", proxiedL.Addr().String()) }

	go func() {
		for i := 0; i < 2; i++ {
			conn, err := proxiedL.Accept()
			require.NoError(t, err)

			go func(c net.Conn) {
				require.NoError(t, c.(*tls.Conn).Handshake())
				_, err = c.Write([]byte(proxiedServerMsg))
				require.NoError(t, err)
			}(conn)
		}
	}()

	// We capture the encrypted signal by watching the bytes going in and out of the server. We use
	// some knowledge of the "protocol" and secret to identify the signal, but this could
	// conceivably be done without this information as well.
	var (
		encryptedSignalChan = make(chan []byte, 1)
		serverHello         *reptls.ServerHello
	)
	onServerWrite := func(b []byte) {
		if serverHello != nil {
			return
		}
		var err error
		serverHello, err = reptls.ParseServerHello(b)
		require.NoError(t, err)
	}
	onServerRead := func(b []byte) {
		if serverHello == nil {
			return
		}

		seq, iv, err := deriveSeqAndIV(serverHello.Random)
		require.NoError(t, err)

		connState, err := reptls.NewConnState(serverHello.Version, serverHello.Suite, seq)
		require.NoError(t, err)

		lastN := 0
		results := reptls.ReadRecords(bytes.NewReader(b), connState, secret, iv)
		for _, result := range results {
			if result.Err != nil {
				// If we can't decrypt, assume this wasn't the signal.
				lastN = result.N
				continue
			}
			_, err := parseCompletionSignal(result.Data)
			if err != nil {
				// Again, assume this wasn't the signal.
				lastN = result.N
				continue
			}
			encryptedSignalChan <- b[lastN:result.N]
		}
	}

	_l, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	listenerOpts := ListenerOpts{DialProxied: dialProxied, Secret: secret}
	l := WrapListener(mitmListener{_l, onServerRead, onServerWrite}, listenerOpts)
	defer l.Close()

	go func() {
		for i := 0; i < 2; i++ {
			conn, err := l.Accept()
			if i > 0 {
				// The second one is supposed to fail.
				return
			}
			require.NoError(t, err)
			conn.Write([]byte(serverMsg))
		}
	}()

	// Dial once so that our callbacks pick up the signal.
	dialerOpts := DialerOpts{TLSConfig: &tls.Config{InsecureSkipVerify: true}, Secret: secret}
	conn, err := DialTimeout("tcp", l.Addr().String(), dialerOpts, timeout)
	require.NoError(t, err)
	conn.Close()

	var encryptedSignal []byte
	select {
	case encryptedSignal = <-encryptedSignalChan:
	case <-time.After(timeout):
		t.Fatal("timed out waiting for captured signal")
	}

	// Now we dial again, but with a standard TLS dialer. This should get proxied through to the
	// TLS listener.
	conn, err = tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp", l.Addr().String(),
		&tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)
	conn.SetDeadline(time.Now().Add(timeout))

	// Now the server should be waiting for the completion signal. We replay the signal from before
	// and see how the server responds.
	_, err = conn.Write(encryptedSignal)
	require.NoError(t, err)

	b := make([]byte, len(proxiedServerMsg))
	n, err := conn.Read(b)
	require.NoError(t, err)
	require.Equal(t, proxiedServerMsg, string(b[:n]))
}

// TestProgressionToProxy ensures that the proxied TLS server progresses to a normal proxy if the
// client never sends the completion signal.
func TestProgressionToProxy(t *testing.T) {
	t.Run("client closes", func(t *testing.T) { progressionToProxyHelper(t, true) })
	t.Run("server closes", func(t *testing.T) { progressionToProxyHelper(t, false) })
}

func progressionToProxyHelper(t *testing.T, clientCloses bool) {
	t.Helper()
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
		if !clientCloses {
			defer conn.Close()
		}

		require.NoError(t, conn.(*tls.Conn).Handshake())

		b := make([]byte, len(clientMsg))
		n, err := conn.Read(b)
		require.NoError(t, err)
		require.Equal(t, clientMsg, string(b[:n]))

		_, err = conn.Write([]byte(serverMsg))
		require.NoError(t, err)
	}()

	listenerOpts := ListenerOpts{DialProxied: dialProxied, Secret: secret}
	l, err := Listen("tcp", "localhost:0", listenerOpts)
	require.NoError(t, err)
	defer l.Close()

	// We expect the Accept function to run for the duration of the test as it is serving as a
	// proxy to proxiedL.
	wg.Add(1)
	go func() { l.Accept(); wg.Done() }()

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp",
		l.Addr().String(),
		&tls.Config{InsecureSkipVerify: true},
	)
	require.NoError(t, err)
	conn.SetDeadline(time.Now().Add(timeout))
	if clientCloses {
		defer conn.Close()
	}

	_, err = conn.Write([]byte(clientMsg))
	require.NoError(t, err)

	b := make([]byte, len(serverMsg))
	n, err := conn.Read(b)
	require.NoError(t, err)
	require.Equal(t, serverMsg, string(b[:n]))
}

type mitmListener struct {
	net.Listener
	onRead, onWrite func([]byte)
}

func (l mitmListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return mitm(conn, l.onRead, l.onWrite), nil
}

func randomData(t *testing.T, len int) []byte {
	t.Helper()
	b := make([]byte, len)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}
