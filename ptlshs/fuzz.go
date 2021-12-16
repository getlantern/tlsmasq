// +build gofuzz

package ptlshs

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/getlantern/tlsmasq/internal/testutil"

	utls "github.com/refraction-networking/utls"
)

// TODO: doc and revisit
const testTimeout = time.Second

// Variables which do not change between fuzzing runs.
var (
	secret = Secret{0xff} // We have to set at least one byte in the secret.
	tlsCfg = &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{testutil.Cert},
	}
)

// Fuzz is the entrypoint for go-fuzz. To generate and test input:
//
// - Install github.com/dvyukov/go-fuzz and github.com/dvyukov/go-fuzz-build.
// - In getlantern/tlsmasq/fuzz, run 'go-fuzz-build -o fuzzbin'.
// - In getlantern/tlsmasq/fuzz, run 'go-fuzz -bin fuzzbin -workdir workdir'.
//
// Input to this function is treated as a ClientHello message. Note that we do not expect record
// headers, only the hello message itself. This is because utls.FingerprintClientHello accepts hello
// messages, not full records.
//
// For more information on fuzz testing, see github.com/dvyukov/go-fuzz.
// TODO: add some kind of test
func Fuzz(data []byte) int {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	if isValid, handshaker := isClientHello(ctx, data); isValid {
		if err := assertSuccessfulHandshake(ctx, *handshaker); err != nil {
			panic(fmt.Sprintf("handshake failed: %v", err))
		}
		return 1
	} else {
		if err := assertProxyBehavior(ctx, data); err != nil {
			panic(fmt.Sprintf("proxying failed: %v", err))
		}
		// A random sequence which does not break anything is not interesting; return 0.
		return 0
	}
}

// Returns true iff 'data' represents a valid ClientHello. In this case, a handshaker is returned
// which can be used to execute a TLS handshake using the provided ClientHello.
func isClientHello(ctx context.Context, data []byte) (bool, *utlsHandshaker) {
	origin := tlsOrigin{tlsCfg.Clone(), ctx}

	handshaker := utlsHandshaker{
		cfg:         &utls.Config{InsecureSkipVerify: true},
		sampleHello: data,
	}

	// n.b. tlsOrigin.dial never returns an error.
	transportToOrigin, _ := origin.dial(ctx)
	if _, err := handshaker.Handshake(transportToOrigin); err != nil {
		return false, nil
	}
	return true, &handshaker
}

func assertProxyBehavior(ctx context.Context, data []byte) error {
	serverToOrigin, originToServer := net.Pipe()
	dialOrigin := func(_ context.Context) (net.Conn, error) {
		return serverToOrigin, nil
	}

	_client, _server := net.Pipe()
	client := Client(_client, DialerConfig{
		Secret: secret,
		Handshaker: dumbHandshaker{
			ctx:  ctx,
			data: data,
		},
	})
	server := Server(_server, ListenerConfig{
		Secret:     secret,
		DialOrigin: dialOrigin,
	})
	defer client.Close()
	defer server.Close()

	// This channel receives an error if the origin fails to read all bytes in data. Receives nil
	// if the origin reads all bytes in data.
	originReceive := make(chan error, 1)
	go func() {
		rcvd := make([]byte, len(data))
		bytesRcvd := 0
		for bytesRcvd < len(data) {
			n, err := originToServer.Read(rcvd[bytesRcvd:])
			bytesRcvd += n
			if err != nil {
				originReceive <- fmt.Errorf("read failed after %d bytes: %w", bytesRcvd, err)
			}
		}
		originReceive <- nil
	}()

	// In the expected case, neither handshake channel should return until this function returns
	// (and the deferred Close calls are invoked).
	cHS, sHS := make(chan error, 1), make(chan error, 1)
	go func() { cHS <- client.Handshake() }()
	go func() { sHS <- server.Handshake() }()

	select {
	case err := <-originReceive:
		if err != nil {
			return fmt.Errorf("origin failed to receive all data: %w", err)
		}
		return nil
	case err := <-cHS:
		return fmt.Errorf("unexpected client handshake error: %w", err)
	case err := <-sHS:
		return fmt.Errorf("unexpected client handshake error: %w", err)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func assertSuccessfulHandshake(ctx context.Context, handshaker utlsHandshaker) error {
	origin := tlsOrigin{tlsCfg.Clone(), ctx}

	_client, _server := net.Pipe()
	client := Client(_client, DialerConfig{
		Secret:     secret,
		Handshaker: handshaker,
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

	for i := 0; i < 2; i++ {
		// n.b. We don't care about most errors; we're looking for panics.
		select {
		case err := <-cHS:
			if err != nil {
				return fmt.Errorf("client error: %w", err)
			}
			return nil
		case err := <-sHS:
			if err != nil {
				return fmt.Errorf("server error: %w", err)
			}
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	// Shouldn't actually be reachable.
	return nil
}

type tlsOrigin struct {
	cfg *tls.Config

	// If this context expires, all spawned connections will be closed and all launched goroutines
	// will be cleaned up.
	ctx context.Context
}

// Never returns an error (the function signature needs to match ListenerConfig.DialOrigin).
func (o tlsOrigin) dial(_ context.Context) (net.Conn, error) {
	clientTransport, serverTransport := net.Pipe()
	server := tls.Server(serverTransport, o.cfg)
	go func() {
		server.Handshake()

		// The client may send records after the handshake (e.g. for ALPN). Since the transport is a
		// synchronous pipe, we need to read everything from the client or the client's writes will
		// block.
		io.Copy(io.Discard, server)
	}()

	// If the origin context expires, clean up.
	go func() {
		<-o.ctx.Done()
		server.Close()
		clientTransport.Close()
	}()

	// Return the raw transport to the origin.
	return clientTransport, nil
}

// dumbHandshaker implements Handshaker. It does not attempt a proper handshake, it simply sends a
// blob of data and waits until the provided context expires.
type dumbHandshaker struct {
	ctx  context.Context
	data []byte
}

func (h dumbHandshaker) Handshake(conn net.Conn) (*HandshakeResult, error) {
	_, err := conn.Write(h.data)
	if err != nil {
		return nil, fmt.Errorf("write failed: %w", err)
	}
	<-h.ctx.Done()
	return nil, h.ctx.Err()
}

// utlsHandshaker implements Handshaker. This allows us to specify custom ClientHellos.
type utlsHandshaker struct {
	cfg *utls.Config

	// We keep a sample hello, rather than a utls.ClientHelloSpec because (i) utls.ClientHelloSpecs
	// cannot be re-used and (ii) this is easier than deep-copying the utls.ClientHelloSpec.
	sampleHello []byte
}

func (h utlsHandshaker) Handshake(conn net.Conn) (*HandshakeResult, error) {
	spec, err := utls.FingerprintClientHello(h.sampleHello)
	if err != nil {
		return nil, fmt.Errorf("failed to fingerprint sample hello: %w", err)
	}

	uconn := utls.UClient(conn, h.cfg.Clone(), utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("failed to apply hello spec to utls conn: %w", err)
	}
	if err := uconn.Handshake(); err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	return &HandshakeResult{
		Version:     uconn.ConnectionState().Version,
		CipherSuite: uconn.ConnectionState().CipherSuite,
	}, nil
}
