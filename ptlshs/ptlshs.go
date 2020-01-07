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
	// DefaultNonceTTL is used when DialerConfig.NonceTTL is not specified.
	DefaultNonceTTL = 10 * time.Second

	// DefaultNonceSweepInterval is used when ListenerConfig.NonceSweepInterval is not specified.
	DefaultNonceSweepInterval = time.Minute
)

// This should be plenty large enough for handshake records. In the event that the connection
// becomes a fully proxied connection, we may split records up, but that's not a problem.
const listenerReadBufferSize = 1024

// A Secret pre-shared between listeners and dialers. This is used to secure the completion signal
// sent by the dialer.
type Secret [52]byte

// DialerConfig specifies configuration for dialing.
type DialerConfig struct {
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

func (cfg DialerConfig) withDefaults() DialerConfig {
	newCfg := cfg
	if cfg.TLSConfig == nil {
		newCfg.TLSConfig = &tls.Config{}
	}
	if cfg.NonceTTL == 0 {
		newCfg.NonceTTL = DefaultNonceTTL
	}
	return newCfg
}

// Dialer is the interface implemented by network dialers.
type Dialer interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type dialer struct {
	Dialer
	DialerConfig
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
func WrapDialer(d Dialer, cfg DialerConfig) Dialer {
	return dialer{d, cfg.withDefaults()}
}

// Dial a ptlshs listener.
func Dial(network, address string, cfg DialerConfig) (net.Conn, error) {
	return WrapDialer(&net.Dialer{}, cfg).Dial(network, address)
}

// DialTimeout acts like Dial but takes a timeout.
func DialTimeout(network, address string, cfg DialerConfig, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return WrapDialer(&net.Dialer{}, cfg).DialContext(ctx, network, address)
}

// ListenerConfig specifies configuration for listening.
type ListenerConfig struct {
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

func (cfg ListenerConfig) withDefaults() ListenerConfig {
	newCfg := cfg
	if cfg.NonceSweepInterval == 0 {
		newCfg.NonceSweepInterval = DefaultNonceSweepInterval
	}
	if cfg.NonFatalErrors == nil {
		// Errors are dropped if the channel is full, so this should be fine.
		newCfg.NonFatalErrors = make(chan error)
	}
	return newCfg
}

type listener struct {
	net.Listener
	ListenerConfig
	nonceCache *nonceCache
}

func (l listener) Accept() (net.Conn, error) {
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
func WrapListener(l net.Listener, cfg ListenerConfig) net.Listener {
	cfg = cfg.withDefaults()
	return listener{l, cfg, newNonceCache(cfg.NonceSweepInterval)}
}

// Listen for ptlshs dialers.
func Listen(network, address string, cfg ListenerConfig) (net.Listener, error) {
	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	return WrapListener(l, cfg), nil
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
