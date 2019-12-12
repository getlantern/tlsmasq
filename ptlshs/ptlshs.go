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
)

// TODO: import implementation from the fakshake/shakes package

// A Secret pre-shared between listeners and dialers. This is used to secure the completion signal
// sent by the dialer.
type Secret [52]byte

// DialerOpts specifies options for dialing.
type DialerOpts struct {
	// TLSConfig is used for the proxied handshake.
	TLSConfig *tls.Config

	// A Secret pre-shared between listeners and dialers.
	Secret Secret

	// NonceTTL specifies the time-to-live for nonces used in completion signals.
	NonceTTL time.Duration
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
	// TODO: respect timeout and deadline on d.Dialer
	// TODO: implement me!
	return nil, nil
}

// WrapDialer wraps the input dialer with a network dialer which will perform the ptlshs protocol.
func WrapDialer(d Dialer, opts DialerOpts) Dialer {
	return dialer{d, opts}
}

// Dial a ptlshs listener.
func Dial(network, address string, opts DialerOpts) (net.Conn, error) {
	return WrapDialer(&net.Dialer{}, opts).Dial(network, address)
}

// DialTimeout acts like Dial but takes a timeout.
func DialTimeout(network, address string, opts DialerOpts, timeout time.Duration) (net.Conn, error) {
	return WrapDialer(&net.Dialer{Timeout: timeout}, opts).Dial(network, address)
}

// ListenerOpts specifies options for listening.
type ListenerOpts struct {
	// DialProxied is used to create TCP connections to the proxied server. Must not be nil.
	DialProxied func() (net.Conn, error)

	// A Secret pre-shared between listeners and dialers.
	Secret Secret

	// NonceSweepInterval determines how often the nonce cache is swept for expired entries.
	NonceSweepInterval time.Duration

	// NonFatalErrors will be used to log non-fatal errors. These will likely be due to probes.
	NonFatalErrors chan<- error
}

type listener struct {
	net.Listener
	ListenerOpts
}

func (l listener) Accept() (net.Conn, error) {
	// TODO: implement me!
	return nil, nil
}

// WrapListener wraps the input listener with one which speaks the ptlshs protocol.
func WrapListener(l net.Listener, opts ListenerOpts) net.Listener {
	return listener{l, opts}
}

// Listen for ptlshs dialers.
func Listen(network, address string, opts ListenerOpts) (net.Listener, error) {
	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	return listener{l, opts}, nil
}
