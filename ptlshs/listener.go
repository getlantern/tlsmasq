package ptlshs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/getlantern/preconn"
	"github.com/getlantern/tlsmasq/internal/reptls"
)

// This should be plenty large enough for handshake records. In the event that the connection
// becomes a fully proxied connection, we may split records up, but that's not a problem.
const listenerReadBufferSize = 1024

type listener struct {
	net.Listener
	ListenerOpts
	nonceCache *nonceCache
}

func (l listener) Accept() (net.Conn, error) {
	// TODO: if the Accept function blocks when proxying a connection (from say, an active probe),
	// then the typical pattern of accept loops will not work. Think about how to resolve this.

	clientConn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	toProxied, err := l.DialProxied()
	if err != nil {
		return nil, fmt.Errorf("failed to dial proxied server: %w", err)
	}

	ctx, stop := context.WithCancel(context.Background())
	errGroup, ctx := errgroup.WithContext(ctx)
	defer stop()

	tryToSend := func(errChan chan<- error, err error) {
		select {
		case errChan <- err:
		default:
		}
	}

	var (
		connState            *reptls.ConnState
		iv                   [16]byte
		serverHelloParsed    = make(chan struct{})
		errOnReadFromProxied = make(chan error, 1)
		postSignalData       = new(bytes.Buffer)
		firstReadFromProxied = true

		// Saved to be passed back in the Conn.
		version, suite uint16
		seq            [8]byte
	)
	onReadFromProxied := func(b []byte) {
		if !firstReadFromProxied {
			return
		}
		firstReadFromProxied = false
		serverHello, err := reptls.ParseServerHello(b)
		if err != nil {
			tryToSend(errOnReadFromProxied, fmt.Errorf("failed to parse server hello: %w", err))
			return
		}
		version, suite = serverHello.Version, serverHello.Suite
		seq, iv, err = deriveSeqAndIV(serverHello.Random)
		if err != nil {
			tryToSend(errOnReadFromProxied, fmt.Errorf("failed to derive sequence and IV: %w", err))
			return
		}
		cs, err := reptls.NewConnState(serverHello.Version, serverHello.Suite, seq)
		if err != nil {
			tryToSend(errOnReadFromProxied, fmt.Errorf("failed to init conn state based on hello info: %w", err))
			return
		}
		connState = cs
		close(serverHelloParsed)
	}
	onReadFromClient := func(b []byte) {
		select {
		case <-serverHelloParsed:
			results := reptls.ReadRecords(bytes.NewReader(b), connState, l.Secret, iv)
			for _, result := range results {
				if result.Err != nil {
					// Only act if we successfully decrypted. Otherwise, assume this wasn't the signal.
					continue
				}
				signal, err := parseCompletionSignal(result.Data)
				if err != nil {
					// Again, only act if this looks like the signal.
					tryToSend(l.NonFatalErrors, fmt.Errorf("decrypted record, but failed to parse signal: %w", err))
					continue
				}
				if !l.nonceCache.isValid(signal.getNonce()) {
					// Looks like a replay. Continue so that the connection will just get proxied.
					tryToSend(l.NonFatalErrors, errors.New("received bad nonce; likely a signal replay"))
					continue
				}
				postSignalData.Write(b[result.N:])
				stop()
			}
		case <-ctx.Done():
			// At this point, we just need to hold on to anything read from the client.
			postSignalData.Write(b)
			return
		default:
			return
		}

	}
	onWriteToProxied := func(b []byte) {
		select {
		case <-ctx.Done():
			// Closing the connection in this callback ensures that we are able to first write any
			// remaining data to the proxied server.
			toProxied.Close()
		default:
		}
	}
	errGroup.Go(func() error {
		select {
		case err := <-errOnReadFromProxied:
			return err
		case <-ctx.Done():
			return nil
		}
	})

	mitmToProxied := mitm(toProxied, onReadFromProxied, onWriteToProxied)
	mitmToClient := mitm(clientConn, onReadFromClient, nil)
	errGroup.Go(func() error {
		return netCopy(
			ctx,
			namedConn{mitmToProxied, "proxied server"},
			namedConn{mitmToClient, "client"},
			listenerReadBufferSize,
		)
	})
	errGroup.Go(func() error {
		return netCopy(
			ctx,
			namedConn{mitmToClient, "client"},
			namedConn{mitmToProxied, "proxied server"},
			listenerReadBufferSize,
		)
	})
	errGroup.Go(func() error {
		<-ctx.Done()
		select {
		case <-mitmToClient.closedByPeer:
			mitmToProxied.Close()
		case <-mitmToProxied.closedByPeer:
			mitmToClient.Close()
		default:
		}
		return nil
	})
	if err := errGroup.Wait(); err != nil {
		return nil, err
	}
	clientConn = preconn.Wrap(clientConn, postSignalData.Bytes())
	return &Conn{clientConn, version, suite, seq, iv, sync.Mutex{}}, nil
}

func (l listener) Close() error {
	l.nonceCache.close()
	return l.Listener.Close()
}

type namedConn struct {
	net.Conn
	name string
}

// Copies from src to dst until the context is done.
func netCopy(ctx context.Context, dst, src namedConn, bufferSize int) error {
	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		src.SetDeadline(deadline)
		dst.SetDeadline(deadline)
	}
	buf := make([]byte, bufferSize)
	for {
		n, err := src.Read(buf)
		if isDone(ctx) {
			// We write what we have left, but we don't worry about whether it makes it.
			dst.Write(buf[:n])
			return nil
		}
		if isNonTemporary(err) {
			return fmt.Errorf("failed to read from %s: %w", src.name, err)
		}
		_, err = dst.Write(buf[:n])
		if isDone(ctx) {
			return nil
		}
		if isNonTemporary(err) {
			return fmt.Errorf("failed to write to %s: %w", dst.name, err)
		}
	}
}

func isNonTemporary(err error) bool {
	if err == nil {
		return false
	}
	if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
		return false
	}
	return true
}

func isDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
