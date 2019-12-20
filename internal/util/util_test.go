package util

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
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

func TestHandshakeContext(t *testing.T) {
	t.Parallel()

	doTest := func(t *testing.T, serverResponds bool) {
		t.Helper()
		t.Parallel()

		var (
			wg      = new(sync.WaitGroup)
			timeout = 100 * time.Millisecond
			tlsCfg  = &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{cert},
			}

			_client, _server = net.Pipe()
			client, server   = tls.Client(_client, tlsCfg), tls.Server(_server, tlsCfg)
		)

		if serverResponds {
			go func() {
				require.NoError(t, server.Handshake())
			}()
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		if serverResponds {
			require.NoError(t, HandshakeContext(ctx, client))
		} else {
			err := HandshakeContext(ctx, client)
			require.Error(t, err)
			require.IsType(t, TimeoutError(""), err)
		}
		wg.Wait()
	}

	t.Run("timeout", func(t *testing.T) { doTest(t, false) })
	t.Run("no timeout", func(t *testing.T) { doTest(t, true) })
}
