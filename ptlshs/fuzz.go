// +build gofuzz

package ptlshs

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/getlantern/tlsmasq/internal/testutil"

	utls "github.com/refraction-networking/utls"
)

// We consider a handshake to have failed after this much time has elapsed.
const handshakeTimeout = time.Second

// Variables which do not change between fuzzing runs.
var (
	secret = Secret{0xff} // We have to set at least one byte in the secret.
	tlsCfg = &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{testutil.Cert},
	}
	utlsCfg = &utls.Config{
		InsecureSkipVerify: true,
		Certificates:       []utls.Certificate{testutil.UTLSCert},
	}
	origin = tlsOrigin{tlsCfg.Clone()}
)

// Fuzz is the entrypoint for go-fuzz. To generate and test input:
//
// - Install github.com/dvyukov/go-fuzz and github.com/dvyukov/go-fuzz-build.
// - In getlantern/tlsmasq/fuzz, run 'go-fuzz-build -o fuzzbin'.
// - In getlantern/tlsmasq/fuzz, run 'go-fuzz -bin fuzzbin -workdir workdir'.
//
// For more information, see github.com/dvyukov/go-fuzz.
func Fuzz(data []byte) int {
	spec, err := utls.FingerprintClientHello(data)
	if err != nil {
		// Not a valid ClientHello.
		return 0
	}

	_client, _server := net.Pipe()
	client := Client(_client, DialerConfig{
		Secret: secret,
		Handshaker: &utlsHandshaker{
			cfg:   utlsCfg,
			hello: spec,
		},
	})
	server := Server(_server, ListenerConfig{
		Secret:     secret,
		DialOrigin: origin.dial,
	})
	defer client.Close()
	defer server.Close()

	cHS, sHS := make(chan error, 1), make(chan error, 1)
	go func() { cHS <- client.Handshake() }()
	go func() { sHS <- server.Handshake() }()

	timer := time.NewTimer(handshakeTimeout)
	defer timer.Stop()

	for i := 0; i < 2; i++ {
		// n.b. We don't care about most errors; we're looking for panics.
		select {
		case err := <-cHS:
			if errors.Is(err, errBadHello) {
				// We do care about this error as it reflects a malformed ClientHello.
				return 0
			}
		case <-sHS:
		case <-timer.C:
			panic("handshake timeout")
		}
	}
	return 1
}

type tlsOrigin struct {
	// cfg is used for both the client and server sides of the connection.
	cfg *tls.Config
}

func (o tlsOrigin) dial(_ context.Context) (net.Conn, error) {
	_client, _server := net.Pipe()
	client, server := tls.Client(_client, o.cfg), tls.Server(_server, o.cfg)
	go server.Handshake()
	return client, nil
}

var errBadHello = errors.New("could not apply hello spec to utls connection")

// utlsHandshaker implements Handshaker. This allows us to specify custom ClientHellos.
type utlsHandshaker struct {
	cfg   *utls.Config
	hello *utls.ClientHelloSpec
	sync.Mutex
}

func (h *utlsHandshaker) Handshake(conn net.Conn) (*HandshakeResult, error) {
	uconn := utls.UClient(conn, h.cfg.Clone(), utls.HelloCustom)
	if err := uconn.ApplyPreset(h.hello); err != nil {
		return nil, errBadHello
	}
	if err := uconn.Handshake(); err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	return &HandshakeResult{
		Version:     uconn.ConnectionState().Version,
		CipherSuite: uconn.ConnectionState().CipherSuite,
	}, nil
}
