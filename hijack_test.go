package tlsmasq

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"testing"

	"github.com/getlantern/tlsmasq/internal/testutil"
	"github.com/getlantern/tlsmasq/ptlshs"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHijack(t *testing.T) {
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

		clientMsg, serverMsg = "hello from the client", "hello from server"
		secret               ptlshs.Secret
	)
	_, err := rand.Read(secret[:])
	require.NoError(t, err)

	origin := testutil.StartOrigin(t, tlsCfg)
	clientTransport, serverTransport := testutil.BufferedPipe()
	clientConn := ptlshs.Client(clientTransport, ptlshs.DialerConfig{
		Handshaker: ptlshs.StdLibHandshaker{
			Config: tlsCfg,
		},
		Secret: secret,
	})
	serverConn := ptlshs.Server(serverTransport, ptlshs.ListenerConfig{
		DialOrigin: origin.DialContext,
		Secret:     secret,
	})
	defer clientConn.Close()
	defer serverConn.Close()

	serverErr := make(chan error, 1)
	msgFromClient := make(chan string, 1)
	go func() {
		serverErr <- func() error {
			_, err := hijack(serverConn, tlsCfg, secret, false)
			if err != nil {
				return fmt.Errorf("hijack failed: %w", err)
			}

			b := make([]byte, len(clientMsg))
			n, err := serverConn.Read(b)
			if err != nil {
				return fmt.Errorf("read failed: %w", err)
			}
			msgFromClient <- string(b[:n])

			_, err = serverConn.Write([]byte(serverMsg))
			if err != nil {
				return fmt.Errorf("write failed: %w", err)
			}
			return nil
		}()
	}()

	msgFromServer, clientErr := func() (string, error) {
		_, err = hijack(clientConn, tlsCfg, secret, true)
		if err != nil {
			return "", fmt.Errorf("hijack failed: %w", err)
		}

		_, err = clientConn.Write([]byte(clientMsg))
		if err != nil {
			return "", fmt.Errorf("write failed: %w", err)
		}

		b := make([]byte, len(serverMsg))
		n, err := clientConn.Read(b)
		if err != nil {
			return "", fmt.Errorf("read failed: %w", err)
		}
		return string(b[:n]), nil
	}()

	assert.NoError(t, clientErr)
	assert.NoError(t, <-serverErr)
	assert.Equal(t, clientMsg, <-msgFromClient)
	assert.Equal(t, serverMsg, msgFromServer)
}

var (
	certPem = []byte(`-----BEGIN CERTIFICATE-----
MIIDqDCCApCgAwIBAgIUGmT9hQ3gOyelkJQ7Z5Mjnm4cY3swDQYJKoZIhvcNAQEL
BQAwajELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5NMRAwDgYDVQQHDAdSb3N3ZWxs
MRAwDgYDVQQKDAdBcmVhIDUxMRYwFAYDVQQLDA1MaWZlIFNjaWVuY2VzMRIwEAYD
VQQDDAlsb2NhbGhvc3QwHhcNMjEwNzI2MTgzNzUwWhcNMzEwNzI0MTgzNzUwWjBq
MQswCQYDVQQGEwJVUzELMAkGA1UECAwCTk0xEDAOBgNVBAcMB1Jvc3dlbGwxEDAO
BgNVBAoMB0FyZWEgNTExFjAUBgNVBAsMDUxpZmUgU2NpZW5jZXMxEjAQBgNVBAMM
CWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOUTFCl6
ND7FgI2kPyALrYy9cxdSYUXyoG2aTHj7sPnA78I+gRtorFtN46GvWC8HSzRqwAsh
2yJjTLfz4gAsjegan9u+QsxN3fs53pupI4L8Hfcasl8KIg0yrUBeF03iQqAmS4zm
32HqkQCeEEU7H1t76ZVi/KK+0TAd3GhJYT4UcnfvwVk1D0lOVg6tBnPpeeIpA4yj
3HXMmyQiHTVSdixBqUfwkZv+tsoQIRNJhHUoos9jtPaT92pGJBMrcyb9kisFy7vO
We1cpSOI+5DyLO6IWO2QZeG3l69lr97l136hh+XaQcaEA8/U7KNwVAsczV4iTfL2
saXCowgU/nEQS1cCAwEAAaNGMEQwCwYDVR0PBAQDAgQwMBMGA1UdJQQMMAoGCCsG
AQUFBwMBMCAGA1UdEQQZMBeCCWxvY2FsaG9zdIcEfwAAAYcEAAAAADANBgkqhkiG
9w0BAQsFAAOCAQEAGCnNuelKngTbp7TW+5l1CxtH1GnNUjpK0Qo3K+umipplU0EO
ZzR2QrRA2RjIhDdbtlhsA/8koHulIGj683J1CiRen1QGkzUtIAz3PCRbD7U/8wDY
Bhey45kDZHsXLP3HgNxzJQ7zOd9PpqjBrgN3eL9PY/7c48nlilxXa1hYvDeuWVxp
R11ZaE++bf9Yooe0ny1AIl51QE7d34s1CZAit1A1k6ASKPaH9zj1rZuYKWwM6lJe
xu5ds8dGRzzkEpwnShFOKnY3Ytz/gENlM1QnLWeiOV/wCf9E8K0EKG24WjuRgT7Y
c/bMDOPRMJo92THL3kkWuQHRz42atM+IVD73Yw==
-----END CERTIFICATE-----`)

	keyPem = []byte(`-----BEGIN PRIVATE KEY-----
MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDlExQpejQ+xYCN
pD8gC62MvXMXUmFF8qBtmkx4+7D5wO/CPoEbaKxbTeOhr1gvB0s0asALIdsiY0y3
8+IALI3oGp/bvkLMTd37Od6bqSOC/B33GrJfCiINMq1AXhdN4kKgJkuM5t9h6pEA
nhBFOx9be+mVYvyivtEwHdxoSWE+FHJ378FZNQ9JTlYOrQZz6XniKQOMo9x1zJsk
Ih01UnYsQalH8JGb/rbKECETSYR1KKLPY7T2k/dqRiQTK3Mm/ZIrBcu7zlntXKUj
iPuQ8izuiFjtkGXht5evZa/e5dd+oYfl2kHGhAPP1OyjcFQLHM1eIk3y9rGlwqMI
FP5xEEtXAgMBAAECggEBAJ5ykuiZqZednuzaJfuxeCq4Q+pmxffO+h61sp2gYmpu
hKiT+VOPFGDXQFNu6I0m+2LXT9yjX2Kq0r8Oh01dhA5+lAI32RZd6eRCw/JhjLmm
T8fDBIvug10jp2i1bGMn1LPXqTxd2TduOzv1GQX5/heWXxxAasTbPfCNRw4va362
8HRYWQdl+DLVY9apQLJNs2f/GmPqVEacNXv1c5WuA9QZ9cdUCxztF1MLHbOlYiS0
U4inZnO6vzPH+m0QJk2vk0pyPMdmAfGuCgjWsy5anVFx5xmqNaQJHf6A5BMaJ/4w
2p3RPfhrrZzeIyZqeGCSkWBAflZAJzUHqrDCylYEz8ECgYEA/4+djN9WbSSWLl39
MRyM88A1DkfiVP5uDrydsKy3Bdk8rPrkbJcKsvqsOnNTJdPiXOtwiv+q3yRsgzAP
siNS5LDx44TwzvlFj4ofyAnsH684SmqPPxnBAdhZg71Z2ryMIrl3btE/j2J9tLLN
l9j62BYELaxHs2KIp2p9hyj2OjcCgYEA5XfQ0+b0MQuKRx9/pe25ur1JPIygL6Z8
8pYouwOb1Mo8eLAXdw2MG55bgqay/ggU9A95b0j0P6viqb3woPSLNfNaAxM+PYwJ
sMLI8NCjU55crOk5tT1g7i2SPLkWJMAuaI1nE+SpGJTIf6QpUu3Sly/EXSCzzs0e
WKiuKvEdZ+ECgYEAvnZ/Wf0dQWxyDQ55Y7++gO9v2zvRv7x7s7n44DJomRBFOzol
QZT0IV3XPBy1DE00uEGz97QB2hogUUlheUcAQXZqYEG04tw+bnLnqsNSWm7RSgzO
w51jDgf69scJD49T9ZE6JLoIX8lsnF5iAVhx4tfNt2hda6D07ajc8v2hPNMCgYEA
1PEQQGSVfSH5azEG0uM9tNZNLTxOtolob/H60Dl0Fc6quVCoJdnTiBm3UBIEDotP
boEhrqzjxGZszBowQB1PRnySrkHgQ1s97uODdz4WItXVqLwxykewOLbfeyxDKU2S
g4GdAy/x35bKTPD5TDTYdWZlcgqT8bgVji7SmZTxNeECgYEApL3m8GFej1fUXBbi
Ck3V1o2VQcZpcoZAiD+QnnzpYqMowu1uuWNLGEdaXWM8/GFyASzQ3JjrAKBjwD/k
69vUR7I4PqlnE7w4v1sm8MCFl3vYALh5MjX9KS7ZwDBOv+YTkLPozHefTf2Hq2HJ
e/Xkd98TTJEo4aP/xpmzY2XYK9Q=
-----END PRIVATE KEY-----`)

	cert tls.Certificate
)

func init() {
	var err error
	cert, err = tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		panic(err)
	}
}
