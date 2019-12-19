package ptlshs

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

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
			require.NoError(t, handshakeContext(ctx, client))
		} else {
			err := handshakeContext(ctx, client)
			require.Error(t, err)
			require.IsType(t, timeoutError(""), err)
		}
		wg.Wait()
	}

	t.Run("timeout", func(t *testing.T) { doTest(t, false) })
	t.Run("no timeout", func(t *testing.T) { doTest(t, true) })
}

func TestTest(t *testing.T) {
	var (
		tlsCfg = &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{cert},
		}

		_client, _ = net.Pipe()
		client     = tls.Client(_client, tlsCfg)
	)

	go func() {
		fmt.Println("doing client handshake")
		fmt.Println("client handshake complete; err =", client.Handshake())
	}()

	time.Sleep(time.Second)
	fmt.Println("closing client connection")
	require.NoError(t, client.Close())
	time.Sleep(2 * time.Second)
}
