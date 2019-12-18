package tlsmasq

import (
	"crypto/rand"
	"crypto/tls"
	"net"
	"sync"
	"testing"

	"github.com/getlantern/tlsmasq/ptlshs"
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

func TestHijack(t *testing.T) {
	t.Parallel()

	// The choice of version and suite don't matter too much, but we will test with a suite
	// which uses the sequence number as a nonce to ensure that path is tested.
	const version, suite = tls.VersionTLS12, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256

	var (
		// The TLS config must allow for the version and suite we choose.
		tlsCfg = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         version,
			CipherSuites:       []uint16{suite},
			Certificates:       []tls.Certificate{cert},
		}

		wg = new(sync.WaitGroup)

		secret ptlshs.Secret
		seq    [8]byte
		iv     [16]byte
		err    error

		clientMsg, serverMsg = "hello from the client", "hello from server"
	)
	_, err = rand.Read(secret[:])
	require.NoError(t, err)
	_, err = rand.Read(seq[:])
	require.NoError(t, err)
	_, err = rand.Read(iv[:])
	require.NoError(t, err)
	defer wg.Wait()

	clientTransport, serverTransport := net.Pipe()
	clientConn := ptlshs.NewConn(clientTransport, version, suite, seq, iv)
	serverConn := ptlshs.NewConn(serverTransport, version, suite, seq, iv)

	wg.Add(1)
	go func() {
		defer wg.Done()

		hijackedServer, err := allowHijack(serverConn, tlsCfg, secret)
		require.NoError(t, err)

		b := make([]byte, len(clientMsg))
		n, err := hijackedServer.Read(b)
		require.NoError(t, err)
		require.Equal(t, clientMsg, string(b[:n]))

		_, err = hijackedServer.Write([]byte(serverMsg))
		require.NoError(t, err)
	}()

	hijackedClient, err := hijack(clientConn, tlsCfg, secret)
	require.NoError(t, err)

	_, err = hijackedClient.Write([]byte(clientMsg))
	require.NoError(t, err)

	b := make([]byte, len(serverMsg))
	n, err := hijackedClient.Read(b)
	require.NoError(t, err)
	require.Equal(t, serverMsg, string(b[:n]))
}
