package ptlshs

import (
	"context"
	"fmt"
	"net"
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
	return Server(clientConn, toProxied, l.Secret, l.nonceCache.isValid, l.NonFatalErrors), nil
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
			// TODO: without knowledge of the MITM stuff, it seems like we're just dropping data
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
