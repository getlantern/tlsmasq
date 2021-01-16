// Command hit-origin tests a tlsmasq connection against an origin site. To achieve this, we start a
// local tlsmasq server pointed at the origin and handshake with this local server.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	utls "github.com/getlantern/utls"

	"github.com/getlantern/tlsmasq"
	"github.com/getlantern/tlsmasq/ptlshs"
)

var (
	originHost  = flag.String("origin", "", "the origin site to use")
	originPort  = flag.Int("port", 443, "the port to use on the origin")
	keyAlgInput = flag.String("key-alg", "", "either RSA or EC; auto-determined if absent")
	serverName  = flag.String("sni", "", "server name indicator; auto-determined if absent")
	timeout     = flag.Duration("timeout", 5*time.Second, "")
)

func getCertInfo(addr string) (sni string, keyAlg x509.PublicKeyAlgorithm, err error) {
	conn, err := tls.Dial("tcp", addr, &tls.Config{})
	if err != nil {
		return "", 0, fmt.Errorf("failed to dial TCP: %w", err)
	}
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		return "", 0, fmt.Errorf("handshake failed: %w", err)
	}
	if len(conn.ConnectionState().PeerCertificates) == 0 {
		return "", 0, errors.New("no peer certificates")
	}
	peerCert := conn.ConnectionState().PeerCertificates[0]
	return peerCert.Subject.CommonName, peerCert.PublicKeyAlgorithm, nil
}

func startServer(origin string, keyAlg x509.PublicKeyAlgorithm, s ptlshs.Secret) (l net.Listener, err error) {
	var cert tls.Certificate
	switch keyAlg {
	case x509.RSA:
		cert = rsaCert
	case x509.ECDSA:
		cert = ecCert
	}

	nonFatalErrors := make(chan error)
	go func() {
		for err := range nonFatalErrors {
			fmt.Fprintln(os.Stderr, "server: non-fatal error reported:", err)
		}
	}()

	cfg := tlsmasq.ListenerConfig{
		ProxiedHandshakeConfig: ptlshs.ListenerConfig{
			DialOrigin:     func() (net.Conn, error) { return net.Dial("tcp", origin) },
			Secret:         s,
			NonFatalErrors: nonFatalErrors,
		},
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}
	l, err = tlsmasq.Listen("tcp", "", cfg)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil && strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "server: accept error:", err)
				continue
			}
			go func(c net.Conn) {
				if err := c.(tlsmasq.Conn).Handshake(); err != nil {
					fmt.Fprintln(os.Stderr, "server: handshake error:", err)
				}
			}(conn)
		}
	}()
	return
}

// utlsHandshaker implements tlsmasq/ptlshs.Handshaker. This allows us to parrot browsers like
// Chrome in our handshakes with tlsmasq origins.
type utlsHandshaker struct {
	cfg *utls.Config
	id  utls.ClientHelloID
}

func (h *utlsHandshaker) Handshake(conn net.Conn) (*ptlshs.HandshakeResult, error) {
	uconn := utls.UClient(conn, h.cfg, h.id)
	res, err := func() (*ptlshs.HandshakeResult, error) {
		if err := uconn.Handshake(); err != nil {
			return nil, err
		}
		return &ptlshs.HandshakeResult{
			Version:     uconn.ConnectionState().Version,
			CipherSuite: uconn.ConnectionState().CipherSuite,
		}, nil
	}()
	return res, err
}

func fail(a ...interface{}) {
	fmt.Fprintln(os.Stderr, a...)
	os.Exit(1)
}

func main() {
	flag.Parse()

	if *originHost == "" {
		fail("origin must be provided")
	}

	origin := fmt.Sprintf("%s:%d", *originHost, *originPort)

	var keyAlg x509.PublicKeyAlgorithm
	switch *keyAlgInput {
	case "RSA":
		keyAlg = x509.RSA
	case "EC":
		keyAlg = x509.ECDSA
	case "":
		keyAlg = x509.UnknownPublicKeyAlgorithm
	default:
		fail("unrecognized key algorithm")
	}

	if *serverName == "" || keyAlg == x509.UnknownPublicKeyAlgorithm {
		_sni, _keyAlg, err := getCertInfo(origin)
		if err != nil {
			fail("failed to auto-determine cert info:", err)
		}
		if *serverName == "" {
			fmt.Fprintln(os.Stderr, "auto-determined SNI:", _sni)
			*serverName = _sni
		}
		if keyAlg == x509.UnknownPublicKeyAlgorithm {
			fmt.Fprintln(os.Stderr, "auto-determined key algorithm:", _keyAlg)
			keyAlg = _keyAlg
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	l, err := startServer(origin, keyAlg, ptlshs.Secret{})
	if err != nil {
		fail("failed to start server:", err)
	}
	defer l.Close()

	cfg := tlsmasq.DialerConfig{
		ProxiedHandshakeConfig: ptlshs.DialerConfig{
			Handshaker: &utlsHandshaker{
				cfg: &utls.Config{
					ServerName: *serverName,
				},
				id: utls.HelloChrome_83,
			},
			Secret: ptlshs.Secret{},
		},
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	conn, err := tlsmasq.WrapDialer(&net.Dialer{}, cfg).DialContext(ctx, "tcp", l.Addr().String())
	if err != nil {
		fail("failed to dial server:", err)
	}
	defer conn.Close()

	handshakeErr := make(chan error, 1)
	go func() {
		handshakeErr <- conn.(tlsmasq.Conn).Handshake()
	}()
	select {
	case err := <-handshakeErr:
		if err != nil {
			fail("handshake failed:", err)
		}
		fmt.Println("success!")
	case <-ctx.Done():
		fail("handshake timed out")
	}
}

// Self-signed localhost certificates. Valid until 2030.
var (
	rsaKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC+n3g738uskOpF
SvJRPk9gX9oVPtIYR4owBecGqouIzcC/gBcMTyKK+bsMNxhXXniaL5rbePDErmB8
zi6kL6ZzxNiCODrWVo4dCliXZC1mD+LuvyQB4LBNms1J1gMtFW6d0kob4rF91XE8
MPpvEApZUvhesRi2epfRfd8KFe7z2qZeGfpiVqE8TuwyiQwVg5h6rY7dHRXwXs44
xAxR4V55sLzW4FPKyESgCVmzmQImW0d9U7jVfRMjYnDQaDLR89yIY1AHvc0JU0J3
0ykA6AmAy6Zqwzb8uWKqTvHuiqKVAi/pOsaPUFxlnKLbkjGCwbn6e5gBX38ntonI
Ya8+jH8NAgMBAAECggEBAL1F+Ity9ng9V/A/r4VN2mD2K8OmodOrzSFL6w3qbywC
KJ29IKV/OexGdRx25Dt0OUnXdOrxFhgkkPe7fgJWse8HiHccQAes3+Uj7b08oftS
UOEAd09J+6TCzY2/611rh287a4xuthAczBeZBkEa6zuwL59ONxyRc4d2dO09xArp
27/BuAbUGa4J/S8LPfth3ewFGEXmN7aO9C9plDoEB5Sox+f/Pa1iBCtBUOij9rFV
NNVkHz6GDL43y1TbGnoFMZbZhhw4+V4gyTaH2Fsu7iCi0bLCm6mxnCA5NDpdUv2d
iWtlddlOVOYUJXlFGjbO+cxtpvJwfBHxNBrJj7av80ECgYEA6Gk9BSVGQLzo4et8
PAnvX15BsxNh8NfkaLs8sVWZja/1L9+3x+q/Rs1Wmv4C2WWQmyBPOAUwlX575wpF
4VSmeujly6hy2qKQHBC3InsNoJHWg6NesUfZWsbiInz8ZEKEK6qzpgPcAd4qE+Lu
R8sgrTfGpHcFPnTNN/wpy9O2MB0CgYEA0fhx9/Rt4hqqL0z6Gy/a+8ieRq4PnD8y
wi7ONn+yPKomEQtBv8hKWnwDe5EyeSDchnvpbDNfYYrOz08+3MgZ/hJmOkqQX1+/
Tx1ss4vAy0tJLG9G2Z5V/mp1tBN9kM26X15m5QEAxUgb9cwx9CCLnGEM4TETWvb9
K6c9V8gLN7ECgYAPFCTdXJm+QYNqhPi+fHaHXXotwCgulBNBqEQ7zS31P2FNBdrK
obRfR5tC2xAcQrarGeGJ5OxOBrLLPqNiBzf16X5fREKPZNSsvXjkR8+Oh2e/iq3u
GpdDiHvLeQh3CMnCe4TEVKPFi0B3odWL2uX31xKQQRiaAMH/y+B6VPYREQKBgQCa
RLa/nggJ4tt9K0prJSr4aPrZJVP00X4iq6743bN/3OdhCGtDVA5FEu6gIBr8YgeE
i5AB3nDKwuiV6jxejGqEgNI5K8WNPVTa9NyDwj9hXiwiCJP+mdXGukNGjjdoZ67y
GPLyeF0vlX5thpyBKFRLDgcfgSYeZG+4XgS09RZA0QKBgQDRtQy1v+nDo1mNzWBc
zG/dDjZDDkwvKtUq7+lgbzoq/axSClOgTAtB5WtfkcQfyX/4L7x/vNLM7dB16nwK
rek9MDeANF+++/2VxQO3YnDuLsLS+0t7WLvtcivMlvEARjstY7IrQWe38SjtfKr5
e+G6ssSwIonGfc2QULzyRaIG5A==
-----END PRIVATE KEY-----
	`)

	rsaCertPEM = []byte(`-----BEGIN CERTIFICATE-----
MIIDozCCAougAwIBAgIUSofIi3aQy2/njq4JrPVd1NJaPnswDQYJKoZIhvcNAQEL
BQAwYTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNPMRUwEwYDVQQHDAxGb3J0IENv
bGxpbnMxDDAKBgNVBAoMA0JOUzEMMAoGA1UECwwDUiZEMRIwEAYDVQQDDAlsb2Nh
bGhvc3QwHhcNMjEwMTExMjIxMjA0WhcNMzEwMTA5MjIxMjA0WjBhMQswCQYDVQQG
EwJVUzELMAkGA1UECAwCQ08xFTATBgNVBAcMDEZvcnQgQ29sbGluczEMMAoGA1UE
CgwDQk5TMQwwCgYDVQQLDANSJkQxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAL6feDvfy6yQ6kVK8lE+T2Bf2hU+0hhH
ijAF5waqi4jNwL+AFwxPIor5uww3GFdeeJovmtt48MSuYHzOLqQvpnPE2II4OtZW
jh0KWJdkLWYP4u6/JAHgsE2azUnWAy0Vbp3SShvisX3VcTww+m8QCllS+F6xGLZ6
l9F93woV7vPapl4Z+mJWoTxO7DKJDBWDmHqtjt0dFfBezjjEDFHhXnmwvNbgU8rI
RKAJWbOZAiZbR31TuNV9EyNicNBoMtHz3IhjUAe9zQlTQnfTKQDoCYDLpmrDNvy5
YqpO8e6KopUCL+k6xo9QXGWcotuSMYLBufp7mAFffye2ichhrz6Mfw0CAwEAAaNT
MFEwHQYDVR0OBBYEFGEGnTBsh/2PB27ReRGHqKa2EiugMB8GA1UdIwQYMBaAFGEG
nTBsh/2PB27ReRGHqKa2EiugMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBABBxTCs1FsH3PeFHeYHJ7L7TOxIqOU2NlpyNpIKO4JCfixdGXzJBcaMF
KIig26KJDbyKFRMcIAY9duAvfrpVy7J6/fh6LWQjpFhb1ZziGvW7Pty0IzgV7iDS
IMwhjd34N7pGYja1JNR7dPbW98VKyHnIpBBDa0hXb/V5yb/LOd4bP5RxFYvoQfS1
awpISwMNML7MbeCJLaBrx8hP/WLiqUMQ/SWaI0j07FjxW69CS3wlPdkc8AH4gu8U
Zdm3Xx0BGyWSYsh5eMxvarBipbhLlwB8xHqVPOPNL33auQW5KS4/UpcUSkg5rHqI
h8u+hlEm1Szli4MPtkZpa+AD/TMbXJA=
-----END CERTIFICATE-----
	`)

	ecKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDB9mOm4UNXmduXRTYHZ
X5jW9hr82Sql3QatBEl8FI5E3TK1z7Ik2C/LgEeMEfv6BEGhZANiAATysf/UG63A
YfxSQ/aSC9jraJ9keRq++gPJkhd2MegvVdpu0Nq21drmZajDAjCShxb2t7lmPga7
TkTwH94+xsqODhGLl3heNFeWhfhFS0q7qJ4TkMgb/zRjn6wq4tzH+24=
-----END PRIVATE KEY-----
	`)

	ecCertPEM = []byte(`-----BEGIN CERTIFICATE-----
MIICUzCCAdqgAwIBAgIUNSOaEWADj2WuE3cNzJdyeKv8/s0wCgYIKoZIzj0EAwIw
YTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNPMRUwEwYDVQQHDAxGb3J0IENvbGxp
bnMxDDAKBgNVBAoMA0JOUzEMMAoGA1UECwwDUiZEMRIwEAYDVQQDDAlsb2NhbGhv
c3QwHhcNMjEwMTExMjIxNDAyWhcNMzEwMTA5MjIxNDAyWjBhMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCQ08xFTATBgNVBAcMDEZvcnQgQ29sbGluczEMMAoGA1UECgwD
Qk5TMQwwCgYDVQQLDANSJkQxEjAQBgNVBAMMCWxvY2FsaG9zdDB2MBAGByqGSM49
AgEGBSuBBAAiA2IABPKx/9QbrcBh/FJD9pIL2Oton2R5Gr76A8mSF3Yx6C9V2m7Q
2rbV2uZlqMMCMJKHFva3uWY+BrtORPAf3j7Gyo4OEYuXeF40V5aF+EVLSruonhOQ
yBv/NGOfrCri3Mf7bqNTMFEwHQYDVR0OBBYEFCLSSt3vwUlsBC1u42SBRkhsT7bn
MB8GA1UdIwQYMBaAFCLSSt3vwUlsBC1u42SBRkhsT7bnMA8GA1UdEwEB/wQFMAMB
Af8wCgYIKoZIzj0EAwIDZwAwZAIwNsnsuxZx0x3zcbPr+TzV0a7ImdRBZi40gYXn
jQ4AMJ3KdiTSIM3CMKGVBYJrkiJwAjBcwydaITLmDbB3PBFUaFDDVMTAFKBel4KQ
0NsUddXdmIIbhsqH/+UZIZ5Yj1Ik06E=
-----END CERTIFICATE-----
	`)

	rsaCert, ecCert tls.Certificate
)

func init() {
	var err error
	rsaCert, err = tls.X509KeyPair(rsaCertPEM, rsaKeyPEM)
	if err != nil {
		panic(fmt.Sprintf("failed to load RSA cert: %v", err))
	}
	ecCert, err = tls.X509KeyPair(ecCertPEM, ecKeyPEM)
	if err != nil {
		panic(fmt.Sprintf("failed to load EC cert: %v", err))
	}
}
