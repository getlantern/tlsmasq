package reptls

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	certPem = []byte(`-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`)
	keyPem = []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAoGCCqGSM49
AwEHoUQDQgAEPR3tU2Fta9ktY+6P9G0cWO+0kETA6SFs38GecTyudlHz6xvCdz8q
EKTcWGekdmdDPsHloRNtsiCa697B2O9IFA==
-----END EC PRIVATE KEY-----`)

	cert tls.Certificate
)

func init() {
	var err error
	cert, err = tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		panic(err)
	}
}

func TestReadAndWrite(t *testing.T) {
	const (
		msg     = "some great secret"
		timeout = time.Second
	)

	l, err := tls.Listen("tcp", "localhost:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)

	serverConnChan := make(chan *tls.Conn)
	go func() {
		conn, err := l.Accept()
		require.NoError(t, err)
		require.NoError(t, conn.(*tls.Conn).Handshake())
		serverConnChan <- conn.(*tls.Conn)
	}()

	clientConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp", l.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)

	clientConn.SetDeadline(time.Now().Add(timeout))
	require.NoError(t, clientConn.Handshake())

	var serverConn *tls.Conn
	select {
	case serverConn = <-serverConnChan:
	case <-time.After(timeout):
		t.Fatal("timed out waiting for server connection")
	}

	var (
		secret [52]byte
		iv     [16]byte
		seq    [8]byte
		buf    = new(bytes.Buffer)
	)

	_, err = rand.Read(secret[:])
	require.NoError(t, err)
	_, err = rand.Read(iv[:])
	require.NoError(t, err)
	_, err = rand.Read(seq[:])
	require.NoError(t, err)

	clientState, err := GetState(clientConn, seq)
	require.NoError(t, err)
	serverState, err := GetState(serverConn, seq)
	require.NoError(t, err)

	_, err = WriteRecord(buf, []byte(msg), clientState, secret, iv)
	require.NoError(t, err)

	roundTripped, err := ReadRecord(buf, serverState, secret, iv)
	require.NoError(t, err)

	require.Equal(t, msg, string(roundTripped))
}

func TestReadRecords(t *testing.T) {
	const timeout = time.Second
	var msgs = []string{"fee", "fi", "fo", "fum"}

	l, err := tls.Listen("tcp", "localhost:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)

	serverConnChan := make(chan *tls.Conn)
	go func() {
		conn, err := l.Accept()
		require.NoError(t, err)
		require.NoError(t, conn.(*tls.Conn).Handshake())
		serverConnChan <- conn.(*tls.Conn)
	}()

	clientConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp", l.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)

	clientConn.SetDeadline(time.Now().Add(timeout))
	require.NoError(t, clientConn.Handshake())

	var serverConn *tls.Conn
	select {
	case serverConn = <-serverConnChan:
	case <-time.After(timeout):
		t.Fatal("timed out waiting for server connection")
	}

	var (
		secret [52]byte
		iv     [16]byte
		seq    [8]byte
		buf    = new(bytes.Buffer)
	)

	clientState, err := GetState(clientConn, seq)
	require.NoError(t, err)
	serverState, err := GetState(serverConn, seq)
	require.NoError(t, err)

	_, err = rand.Read(secret[:])
	require.NoError(t, err)
	_, err = rand.Read(iv[:])
	require.NoError(t, err)
	_, err = rand.Read(seq[:])
	require.NoError(t, err)

	for _, msg := range msgs {
		_, err = WriteRecord(buf, []byte(msg), clientState, secret, iv)
		require.NoError(t, err)
	}

	results := ReadRecords(buf, serverState, secret, iv)
	require.Equal(t, len(msgs), len(results))
	for i := 0; i < len(results); i++ {
		require.NoError(t, results[i].Err)
		require.Equal(t, msgs[i], string(results[i].Read))
	}
}
