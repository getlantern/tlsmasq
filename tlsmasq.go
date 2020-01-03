// Package tlsmasq implements a server which masquerades as a different TLS server. For example, the
// server may masquerade as a microsoft.com server, depsite not actually being run by Microsoft.
//
// Clients properly configured with the masquerade protocol can connect and speak to the true
// server, but passive observers will see connections which look like connections to microsoft.com.
// Similarly, active probes will find that the server behaves like a microsoft.com server.
package tlsmasq

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/getlantern/tlsmasq/ptlshs"
)

// DialerOpts specifies options for dialing.
type DialerOpts struct {
	// ProxiedHandshakeOpts specifies options for the proxied handshake.
	ProxiedHandshakeOpts ptlshs.DialerOpts

	// TLSConfig specifies configuration for the hijacked, true TLS connection with the server. This
	// hijacked connection will use whatever combination of cipher suite and version was negotiated
	// during the proxied handshake. Thus it is important to set fields like CipherSuites and
	// MinVersion to ensure that the security parameters of the hijacked connection are acceptable.
	TLSConfig *tls.Config
}

func (opts DialerOpts) withDefaults() DialerOpts {
	newOpts := opts
	if opts.TLSConfig == nil {
		newOpts.TLSConfig = &tls.Config{}
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
	ptlsDialer := ptlshs.WrapDialer(d.Dialer, d.ProxiedHandshakeOpts)
	conn, err := ptlsDialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	type hijackResult struct {
		conn net.Conn
		err  error
	}
	resultChan := make(chan hijackResult, 1)
	go func() {
		conn, err = hijack(conn.(ptlshs.Conn), d.TLSConfig, d.ProxiedHandshakeOpts.Secret)
		resultChan <- hijackResult{conn, err}
	}()
	select {
	case result := <-resultChan:
		if result.err != nil {
			return nil, fmt.Errorf("failed to hijack connection: %w", err)
		}
		return result.conn, nil
	case <-ctx.Done():
		conn.Close()
		// Note: context.DeadlineExceeded implements net.Error, as we'd like.
		return nil, ctx.Err()
	}
}

// WrapDialer wraps the input dialer with a network dialer which will perform the tlsmasq protocol.
// Dialing will result in TLS connections with peers.
func WrapDialer(d Dialer, opts DialerOpts) Dialer {
	return dialer{d, opts.withDefaults()}
}

// Dial a tlsmasq listener. This will result in a TLS connection with the peer.
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
	// ProxiedHandshakeOpts specifies options for the proxied handshake.
	ProxiedHandshakeOpts ptlshs.ListenerOpts

	// TLSConfig specifies configuration for hijacked, true TLS connections with the clients. These
	// hijacked connections will use whatever combination of cipher suite and version was negotiated
	// during the proxied handshake. Thus it is important to set fields like CipherSuites and
	// MinVersion to ensure that the security parameters of the hijacked connections are acceptable.
	TLSConfig *tls.Config
}

func (opts ListenerOpts) withDefaults() ListenerOpts {
	newOpts := opts
	if opts.TLSConfig == nil {
		newOpts.TLSConfig = &tls.Config{}
	}
	return newOpts
}

type listener struct {
	net.Listener // a listener created by the ptlshs package
	ListenerOpts
}

func (l listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	// We know the type assertion will succeed because we know l.Listener comes from ptlshs.
	conn, err = allowHijack(conn.(ptlshs.Conn), l.TLSConfig, l.ProxiedHandshakeOpts.Secret)
	if err != nil {
		return nil, fmt.Errorf("failed while negotiating hijack: %w", err)
	}
	return conn, nil
}

// WrapListener wraps the input listener with one which speaks the tlsmasq protocol. Accepted
// connections will be TLS connections.
func WrapListener(l net.Listener, opts ListenerOpts) net.Listener {
	return listener{ptlshs.WrapListener(l, opts.ProxiedHandshakeOpts), opts.withDefaults()}
}

// Listen for tlsmasq dialers. Accepted connections will be TLS connections.
func Listen(network, address string, opts ListenerOpts) (net.Listener, error) {
	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	return listener{ptlshs.WrapListener(l, opts.ProxiedHandshakeOpts), opts}, nil
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
