// Package ptlshs implements proxied TLS handshakes. When a client dials a ptlshs listener, the
// initial handshake is proxied to another TLS server. When this proxied handshake is complete, the
// dialer signals to the listener and the connection is established. From here, another, "true"
// handshake may be performed, but this is not the purvue of the ptlshs package.
package ptlshs

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

const (
	// DefaultNonceTTL is used when DialerOpts.NonceTTL is not specified.
	DefaultNonceTTL = 10 * time.Second

	// DefaultNonceSweepInterval is used when ListenerOpts.NonceSweepInterval is not specified.
	DefaultNonceSweepInterval = time.Minute
)

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
	return WrapDialer(&net.Dialer{Timeout: timeout}, opts).Dial(network, address)
}

// TODO: ListenerOpts.DialProxied should perhaps just be AddrToProxied since we'll always need to
// dial TCP to proxied servers

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
