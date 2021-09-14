package fuzzutil

import (
	cryptoRand "crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	mathRand "math/rand"

	"github.com/getlantern/tlsmasq"
	"github.com/getlantern/tlsmasq/internal/testutil"
	"github.com/getlantern/tlsmasq/ptlshs"
)

func RunTestFuzz(seed int64, clientHelloHandshake []byte) error {
	var (
		secret               [52]byte
		clientMsg, serverMsg = "hello from the client", "hello from the server"
	)

	_, err := cryptoRand.Read(secret[:])
	if err != nil {
		return err
	}

	mathRand.Seed(seed)
	origin, err := testutil.StartOrigin(
		&tls.Config{Certificates: []tls.Certificate{testutil.Cert}})
	if err != nil {
		return err
	}
	defer origin.Close()
	// XXX Define new insecuretlsconfig (meaning don't let client verify server
	// certificates and just accept them as is)
	insecureTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{testutil.Cert},
		Rand:               MathRandReader(0),
	}
	dialerCfg := tlsmasq.DialerConfig{
		ProxiedHandshakeConfig: ptlshs.DialerConfig{
			Handshaker:              ptlshs.StdLibHandshaker{Config: insecureTLSConfig},
			Secret:                  secret,
			UseFuzzEchoConn:         true,
			FuzzEchoClientHelloData: clientHelloHandshake,
		},
		TLSConfig: insecureTLSConfig,
	}
	listenerCfg := tlsmasq.ListenerConfig{
		ProxiedHandshakeConfig: ptlshs.ListenerConfig{
			DialOrigin: origin.DialContext,
			Secret:     secret,
		},
		TLSConfig: insecureTLSConfig,
	}

	// XXX Start listening for connections
	// tlsmasq is basically a proxying server: this is the point we start listening
	l, err := tlsmasq.Listen("tcp", "localhost:0", listenerCfg)
	if err != nil {
		return err
	}
	defer l.Close()

	serverErr := make(chan error, 1)
	msgFromClientChan := make(chan string, 1)
	go func() {
		serverErr <- func() error {
			// XXX tlsmasq->client: accept client connection
			conn, err := l.Accept()
			if err != nil {
				return fmt.Errorf("accept failed: %w", err)
			}
			defer conn.Close()

			// XXX tlsmasq->client: read client msg
			b := make([]byte, len(clientMsg))
			n, err := conn.Read(b)
			if err != nil {
				return fmt.Errorf("read failed: %w", err)
			}
			// XXX tlsmasq->client: send msg to channel so that we can assert tests
			msgFromClientChan <- string(b[:n])

			// XXX tlsmasq->client: write pre-determined serverMsg to client
			_, err = conn.Write([]byte(serverMsg))
			if err != nil {
				return fmt.Errorf("write failed: %w", err)
			}
			return nil
		}()
	}()

	msgFromServer, err := func() (string, error) {
		// XXX client->tlsmasq: dial to tlsmasq's IP with dialerCfg
		// This makes the tcp handshake
		conn, err := tlsmasq.NewTlsMasqDialer(dialerCfg).Dial("tcp", l.Addr().String())
		if err != nil {
			return "", err
		}
		defer conn.Close()

		// XXX client->tlsmasq: Write something
		// In the process, this also makes the tls handshake
		_, err = conn.Write([]byte(clientMsg))
		if err != nil {
			return "", err
		}

		// XXX client->tlsmasq: read something with the size of serverMsg
		b := make([]byte, len(serverMsg))
		n, err := conn.Read(b)
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("read failed: %w", err)
		}
		return string(b[:n]), nil
	}()
	if err != nil {
		return err
	}
	err = <-serverErr
	if err != nil {
		return err
	}
	msgFromClient := <-msgFromClientChan
	if clientMsg != msgFromClient {
		return fmt.Errorf("clientMsg [%v] does not equal msgFromClient [%v]", clientMsg, msgFromClient)
	}
	if serverMsg != msgFromServer {
		return fmt.Errorf("serverMsg [%v] does not equal msgFromServer [%v]", serverMsg, msgFromServer)
	}
	return nil
}
