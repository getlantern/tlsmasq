package tlsmasq

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	mathRand "math/rand"
	"net"
	"os"
	"testing"

	"github.com/getlantern/tlsmasq/fuzz"
	"github.com/getlantern/tlsmasq/internal/testutil"
	"github.com/getlantern/tlsmasq/ptlshs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	mathRand.Seed(0)
	log.Println("Generation done")
}

func TestRecord(t *testing.T) {
	os.RemoveAll("./tmp")
	require.NoError(t, fuzz.InitRecording())
	runFuzz(t, "")
	require.NoError(t, fuzz.AssemblePackets())
}

func TestFuzz(t *testing.T) {
	runFuzz(t, "./tmp/assembled.dat")
}

func runFuzz(t *testing.T, fuzzDataFile string) {
	var (
		secret [52]byte
		// wg                   = new(sync.WaitGroup)
		clientMsg, serverMsg = "hello from the client", "hello from the server"
	)
	constantRandReader := fuzz.MathRandReader(0)
	_, err := constantRandReader.Read(secret[:])
	require.NoError(t, err)

	var clientFuzzData, tlsmasqToOriginFuzzData,
		originFuzzData, tlsmasqToClientFuzzData []byte
	if fuzzDataFile != "" {
		fuzzData, err := os.ReadFile(fuzzDataFile)
		require.NoError(t, err)
		clientFuzzData, tlsmasqToOriginFuzzData,
			originFuzzData, tlsmasqToClientFuzzData, err = fuzz.ExtractConnDataFromFuzzData(fuzzData)
		require.NoError(t, err)
		log.Println(len(clientFuzzData))
		log.Println(len(tlsmasqToOriginFuzzData))
		log.Println(len(originFuzzData))
		log.Println(len(tlsmasqToClientFuzzData))
	}

	origin := testutil.StartOrigin(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		Rand:         constantRandReader,
	}, originFuzzData)
	insecureTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cert},
		Rand:               constantRandReader,
	}
	dialerCfg := DialerConfig{
		ProxiedHandshakeConfig: ptlshs.DialerConfig{
			Handshaker: ptlshs.StdLibHandshaker{
				Config: insecureTLSConfig,
			},
			Secret:     secret,
			RandReader: constantRandReader,
		},
		TLSConfig: insecureTLSConfig,
	}
	listenerCfg := ListenerConfig{
		ProxiedHandshakeConfig: ptlshs.ListenerConfig{
			DialOrigin: func(ctx context.Context) (net.Conn, error) {
				c, err := (&net.Dialer{}).DialContext(ctx, "tcp", origin.Addr().String())
				if err != nil {
					return nil, err
				}
				return fuzz.NewEchoConn("tlsmasq_origin", c, tlsmasqToOriginFuzzData), nil
			},
			Secret:      secret,
			RandReader:  constantRandReader,
			UseEchoConn: true,
			EchoData:    tlsmasqToClientFuzzData,
		},
		TLSConfig: insecureTLSConfig,
	}

	l, err := Listen("tcp", "localhost:0", listenerCfg)
	require.NoError(t, err)
	defer l.Close()

	serverErr := make(chan error, 1)
	msgFromClient := make(chan string, 1)
	go func() {
		serverErr <- func() error {
			conn, err := l.Accept()
			if err != nil {
				return fmt.Errorf("accept failed: %w", err)
			}
			defer conn.Close()

			b := make([]byte, len(clientMsg))
			n, err := conn.Read(b)
			if err != nil {
				return fmt.Errorf("read failed: %w", err)
			}
			msgFromClient <- string(b[:n])

			_, err = conn.Write([]byte(serverMsg))
			if err != nil {
				return fmt.Errorf("write failed: %w", err)
			}
			return nil
		}()
	}()

	msgFromServer, clientErr := func() (string, error) {
		conn, err := Dial("tcp", l.Addr().String(), dialerCfg, clientFuzzData)
		if err != nil {
			return "", fmt.Errorf("dial failed: %w", err)
		}
		defer conn.Close()

		_, err = conn.Write([]byte(clientMsg))
		if err != nil {
			return "", fmt.Errorf("write failed: %w", err)
		}

		b := make([]byte, len(serverMsg))
		n, err := conn.Read(b)
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("read failed: %w", err)
		}
		return string(b[:n]), nil
	}()

	assert.NoError(t, clientErr)
	assert.NoError(t, <-serverErr)
	assert.Equal(t, clientMsg, <-msgFromClient)
	assert.Equal(t, serverMsg, msgFromServer)
}
