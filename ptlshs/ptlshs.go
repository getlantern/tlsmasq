// Package ptlshs implements proxied TLS handshakes. When a client dials a ptlshs listener, the
// initial handshake is proxied to another TLS server. When this proxied handshake is complete, the
// dialer signals to the listener and the connection is established. From here, another, "true"
// handshake may be performed, but this is not the purvue of the ptlshs package.
package ptlshs

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

const (
	// DefaultNonceTTL is used when DialerOpts.NonceTTL is not specified.
	DefaultNonceTTL = 10 * time.Second

	// DefaultNonceSweepInterval is used when ListenerOpts.NonceSweepInterval is not specified.
	DefaultNonceSweepInterval = time.Minute
)

// This should be plenty large enough for handshake records. In the event that the connection
// becomes a fully proxied connection, we may split records up, but that's not a problem.
const listenerReadBufferSize = 1024

// A Secret pre-shared between listeners and dialers. This is used to secure the completion signal
// sent by the dialer.
type Secret [52]byte

// DialerOpts specifies options for dialing.
type DialerOpts struct {
	// TLSConfig is used for the proxied handshake. If nil, the zero value is used. However, it is
	// ideal that configuration be provided with the ServerName field set to the name of the
	// proxied server. This will aid in making the handshake look legitimate.
	TLSConfig *tls.Config

	// A Secret pre-shared between listeners and dialers. This value must be set.
	Secret Secret

	// NonceTTL specifies the time-to-live for nonces used in completion signals. DefaultNonceTTL is
	// used if NonceTTL is unspecified.
	NonceTTL time.Duration
}

func (opts DialerOpts) withDefaults() DialerOpts {
	newOpts := opts
	if opts.TLSConfig == nil {
		newOpts.TLSConfig = &tls.Config{}
	}
	if opts.NonceTTL == 0 {
		newOpts.NonceTTL = DefaultNonceTTL
	}
	return newOpts
}

// Dialer is the interface implemented by network dialers.
type Dialer interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type dialer struct {
	Dialer
	DialerOpts
}

func (d dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// Respect any timeout or deadline on the wrapped dialer.
	if netDialer, ok := d.Dialer.(*net.Dialer); ok {
		if deadline := earliestDeadline(netDialer); !deadline.IsZero() {
			var cancel func()
			ctx, cancel = context.WithDeadline(ctx, deadline)
			defer cancel()
		}
	}
	conn, err := d.Dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return Client(conn, d.TLSConfig, d.Secret, d.NonceTTL), nil
}

// WrapDialer wraps the input dialer with a network dialer which will perform the ptlshs protocol.
func WrapDialer(d Dialer, opts DialerOpts) Dialer {
	return dialer{d, opts.withDefaults()}
}

// Dial a ptlshs listener.
func Dial(network, address string, opts DialerOpts) (net.Conn, error) {
	return WrapDialer(&net.Dialer{}, opts).Dial(network, address)
}

// DialTimeout acts like Dial but takes a timeout.
func DialTimeout(network, address string, opts DialerOpts, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return WrapDialer(&net.Dialer{}, opts).DialContext(ctx, network, address)
}

// ListenerOpts specifies options for listening.
type ListenerOpts struct {
	// DialProxied is used to create TCP connections to the proxied server. Must not be nil.
	DialProxied func() (net.Conn, error)

	// A Secret pre-shared between listeners and dialers.
	Secret Secret

	// NonceSweepInterval determines how often the nonce cache is swept for expired entries. If not
	// specified, DefaultNonceSweepInterval will be used.
	NonceSweepInterval time.Duration

	// NonFatalErrors will be used to log non-fatal errors. These will likely be due to probes.
	NonFatalErrors chan<- error
}

func (opts ListenerOpts) withDefaults() ListenerOpts {
	newOpts := opts
	if opts.NonceSweepInterval == 0 {
		newOpts.NonceSweepInterval = DefaultNonceSweepInterval
	}
	if opts.NonFatalErrors == nil {
		// Errors are dropped if the channel is full, so this should be fine.
		newOpts.NonFatalErrors = make(chan error)
	}
	return newOpts
}

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

// WrapListener wraps the input listener with one which speaks the ptlshs protocol.
func WrapListener(l net.Listener, opts ListenerOpts) net.Listener {
	opts = opts.withDefaults()
	return listener{l, opts, newNonceCache(opts.NonceSweepInterval)}
}

// Listen for ptlshs dialers.
func Listen(network, address string, opts ListenerOpts) (net.Listener, error) {
	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	return WrapListener(l, opts), nil
}

// Returns the earliest of:
//   - time.Now()+Timeout
//   - d.Deadline
// Or zero, if neither Timeout nor Deadline are set.
func earliestDeadline(d *net.Dialer) time.Time {
	if d.Timeout == 0 && d.Deadline.IsZero() {
		return time.Time{}
	}
	if d.Timeout == 0 {
		return d.Deadline
	}
	timeoutExpiration := time.Now().Add(d.Timeout)
	if d.Deadline.IsZero() || timeoutExpiration.Before(d.Deadline) {
		return timeoutExpiration
	}
	return d.Deadline
}
