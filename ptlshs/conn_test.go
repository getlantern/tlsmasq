package ptlshs

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"io"
	"io/ioutil"
	"net"
	"testing"
	"time"

	"github.com/getlantern/tlsmasq/internal/testutil"
	"github.com/getlantern/tlsutil"
	"github.com/stretchr/testify/require"
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
		secret Secret
	)
	_, err := rand.Read(secret[:])
	require.NoError(t, err)

	serverToOrigin, originToServer := testutil.BufferedPipe()
	proxiedConn := tls.Server(originToServer, tlsCfg)
	go proxiedConn.Handshake()
	defer serverToOrigin.Close()
	defer originToServer.Close()

	clientTransport, serverTransport := testutil.BufferedPipe()
	clientConn := Client(clientTransport, DialerConfig{secret, StdLibHandshaker{tlsCfg}, 0})
	serverConn := Server(serverTransport, ListenerConfig{
		func() (net.Conn, error) { return serverToOrigin, nil }, secret, 0, make(chan error)},
	)
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

// https://github.com/getlantern/tlsmasq/issues/17
func TestIssue17(t *testing.T) {
	t.Parallel()

	var (
		version          uint16 = tls.VersionTLS12
		suite            uint16 = tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
		secret1, secret2 [52]byte
		iv1, iv2         [16]byte
		seq1, seq2       [8]byte
	)
	for _, b := range [][]byte{secret1[:], secret2[:], iv1[:], iv2[:], seq1[:], seq2[:]} {
		_, err := rand.Read(b)
		require.NoError(t, err)
	}
	writerState1, err := tlsutil.NewConnectionState(version, suite, secret1, iv1, seq1)
	require.NoError(t, err)
	writerState2, err := tlsutil.NewConnectionState(version, suite, secret2, iv2, seq2)
	require.NoError(t, err)
	readerState2, err := tlsutil.NewConnectionState(version, suite, secret2, iv2, seq2)
	require.NoError(t, err)

	sig, err := newClientSignal(time.Hour)
	require.NoError(t, err)

	clientTransport, serverTransport := testutil.BufferedPipe()
	clientTransportCopy := new(bytes.Buffer)
	clientTransportW := io.MultiWriter(clientTransport, clientTransportCopy)

	_, err = tlsutil.WriteRecord(clientTransportW, []byte("pre-signal record"), writerState1)
	require.NoError(t, err)
	firstRecordLen := clientTransportCopy.Len()
	_, err = tlsutil.WriteRecord(clientTransportW, *sig, writerState2)
	require.NoError(t, err)

	toOrigin, originReader := testutil.BufferedPipe()
	go io.Copy(ioutil.Discard, originReader)

	conn := &serverConn{
		Conn:       serverTransport,
		nonceCache: newNonceCache(time.Hour),
	}
	require.NoError(t, conn.watchForCompletion(firstRecordLen-1, readerState2, toOrigin))
}
