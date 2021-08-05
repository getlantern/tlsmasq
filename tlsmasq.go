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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/getlantern/golog"
	"github.com/getlantern/tlsmasq/ptlshs"
	"github.com/getlantern/transports/pluggable"
	"github.com/getlantern/transports/pttls"
	"github.com/getlantern/transports/yamltypes"
)

var log = golog.LoggerFor("tlsmasq")

// DialerConfig specifies configuration for dialing.
type DialerConfig struct {
	// ProxiedHandshakeConfig specifies configuration for the proxied handshake.
	ProxiedHandshakeConfig ptlshs.DialerConfig

	// TLSConfig specifies configuration for the hijacked, true TLS connection with the server. This
	// hijacked connection will use whatever combination of cipher suite and version was negotiated
	// during the proxied handshake. Thus it is important to set fields like CipherSuites and
	// MinVersion to ensure that the security parameters of the hijacked connection are acceptable.
	TLSConfig *tls.Config
}

func (cfg DialerConfig) withDefaults() DialerConfig {
	newCfg := cfg
	if cfg.TLSConfig == nil {
		newCfg.TLSConfig = &tls.Config{}
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
	ptlsDialer := ptlshs.WrapDialer(d.Dialer, d.ProxiedHandshakeConfig)
	conn, err := ptlsDialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return newConn(conn.(ptlshs.Conn), d.TLSConfig, true, d.ProxiedHandshakeConfig.Secret), nil
}

// WrapDialer wraps the input dialer with a network dialer which will perform the tlsmasq protocol.
// Dialing will result in TLS connections with peers.
func WrapDialer(d Dialer, cfg DialerConfig) Dialer {
	return dialer{d, cfg.withDefaults()}
}

// Dial a tlsmasq listener. This will result in a TLS connection with the peer.
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
	// ProxiedHandshakeConfig specifies configuration for the proxied handshake.
	ProxiedHandshakeConfig ptlshs.ListenerConfig

	// TLSConfig specifies configuration for hijacked, true TLS connections with the clients. These
	// hijacked connections will use whatever combination of cipher suite and version was negotiated
	// during the proxied handshake. Thus it is important to set fields like CipherSuites and
	// MinVersion to ensure that the security parameters of the hijacked connections are acceptable.
	TLSConfig *tls.Config
}

func (cfg ListenerConfig) withDefaults() ListenerConfig {
	newCfg := cfg
	if cfg.TLSConfig == nil {
		newCfg.TLSConfig = &tls.Config{}
	}
	return newCfg
}

type listener struct {
	net.Listener // a listener created by the ptlshs package
	ListenerConfig
}

func (l listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	// We know the type assertion will succeed because we know l.Listener comes from ptlshs.
	return newConn(conn.(ptlshs.Conn), l.TLSConfig, false, l.ProxiedHandshakeConfig.Secret), nil
}

// WrapListener wraps the input listener with one which speaks the tlsmasq protocol. Accepted
// connections will be TLS connections.
func WrapListener(l net.Listener, cfg ListenerConfig) net.Listener {
	return listener{ptlshs.WrapListener(l, cfg.ProxiedHandshakeConfig), cfg.withDefaults()}
}

// Listen for tlsmasq dialers. Accepted connections will be TLS connections.
func Listen(network, address string, cfg ListenerConfig) (net.Listener, error) {
	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	return listener{ptlshs.WrapListener(l, cfg.ProxiedHandshakeConfig), cfg}, nil
}

// Transport implements getlantern/transports/pluggable.Transport.
type Transport struct{}

type tlsmasqDialerConfig struct {
	pluggable.CommonDialerConfig
	pttls.CommonTLSConfig

	Secret   *yamltypes.Bytes
	NonceTTL time.Duration // if not configured, the default will be used

	TLSMinVersion *yamltypes.Uint16
	TLSSuites     *yamltypes.Uint16Slice
}

type tlsmasqListenerConfig struct {
	pluggable.CommonListenerConfig

	OriginAddr    string
	Secret        *yamltypes.Bytes
	TLSMinVersion *yamltypes.Uint16
	TLSSuites     *yamltypes.Uint16Slice
}

func (_ Transport) NewDialer(config interface{}, serverName string, cc pluggable.ClientConfig) (pluggable.Dialer, error) {
	cfg, ok := config.(*tlsmasqDialerConfig)
	if !ok {
		return nil, fmt.Errorf("expected config of type %T, but got %T", &tlsmasqDialerConfig{}, config)
	}

	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("malformed server address: %v", err)
	}

	// Add the proxy cert to the root CAs as proxy certs are self-signed.
	if cfg.CertPEM == "" {
		return nil, errors.New("no proxy certificate configured")
	}
	block, rest := pem.Decode([]byte(cfg.CertPEM))
	if block == nil {
		return nil, errors.New("failed to decode proxy certificate as PEM block")
	}
	if len(rest) > 0 {
		return nil, errors.New("unexpected extra data in proxy certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	if cfg.ServerNameIndicator == "" {
		return nil, fmt.Errorf("server name indicator must be configured for tlsmasq")
	}

	tlsCfg, hellos := cfg.UTLSConfig(
		context.Background(), serverName, cc.ConfigDir, cc.CountryCode, cc.UserID)
	tlsCfg.ServerName = cfg.ServerNameIndicator

	secret := ptlshs.Secret{}
	if cfg.Secret.Len() != len(secret) {
		return nil, fmt.Errorf("bad secret len (%d)", cfg.Secret.Len())
	}
	cfg.Secret.CopyTo(secret[:])

	dCfg := DialerConfig{
		ProxiedHandshakeConfig: ptlshs.DialerConfig{
			Handshaker: &utlsHandshaker{tlsCfg, pttls.NewHelloRoller(hellos), sync.Mutex{}},
			Secret:     secret,
			NonceTTL:   cfg.NonceTTL,
		},
		TLSConfig: &tls.Config{
			MinVersion:   cfg.TLSMinVersion.Uint16(),
			CipherSuites: cfg.TLSSuites.Slice(),
			// Proxy certificates are valid for the host (usually their IP address).
			ServerName: host,
			RootCAs:    pool,
		},
	}
	d := WrapDialer(&net.Dialer{}, dCfg)

	return pluggable.WrapContextDialer(
		// TODO: should we do the handshake?
		func(ctx context.Context) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", cfg.Addr)
		},
	), nil
}

func (_ Transport) NewListener(config interface{}, rlc pluggable.RuntimeListenerConfig) (net.Listener, error) {
	cfg, ok := config.(*tlsmasqListenerConfig)
	if !ok {
		return nil, fmt.Errorf("expected config of type %T, but got %T", &tlsmasqListenerConfig{}, config)
	}

	secret := ptlshs.Secret{}
	if cfg.Secret.Len() != len(secret) {
		return nil, fmt.Errorf("bad secret len (%d)", cfg.Secret.Len())
	}
	cfg.Secret.CopyTo(secret[:])

	cert, err := tls.LoadX509KeyPair(rlc.CertFile, rlc.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load keypair: %w", err)
	}

	lCfg := ListenerConfig{
		ProxiedHandshakeConfig: ptlshs.ListenerConfig{
			DialOrigin: func(ctx context.Context) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", cfg.OriginAddr)
			},
			Secret: secret,
		},
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   cfg.TLSMinVersion.Uint16(),
			CipherSuites: cfg.TLSSuites.Slice(),
		},
	}
	return Listen("tcp", cfg.Addr, lCfg)
}

func (_ Transport) DialerConfig() interface{}   { return &tlsmasqDialerConfig{} }
func (_ Transport) ListenerConfig() interface{} { return &tlsmasqListenerConfig{} }

// utlsHandshaker implements tlsmasq/ptlshs.Handshaker. This allows us to parrot browsers like
// Chrome in our handshakes with tlsmasq origins.
type utlsHandshaker struct {
	cfg    *utls.Config
	roller *pttls.HelloRoller
	sync.Mutex
}

func (h *utlsHandshaker) Handshake(conn net.Conn) (*ptlshs.HandshakeResult, error) {
	r := h.roller.Clone()
	defer h.roller.UpdateTo(r)

	isHelloErr := func(err error) bool {
		if strings.Contains(err.Error(), "hello spec") {
			// These errors are created below.
			return true
		}
		if strings.Contains(err.Error(), "tls: ") {
			// A TLS-level error is likely related to a bad hello.
			return true
		}
		return false
	}

	currentHello := r.Current()
	uconn, err := currentHello.UConn(conn, h.cfg.Clone())
	if err != nil {
		// An error from helloSpec.uconn implies an invalid hello.
		log.Debugf("invalid custom hello; advancing roller: %v", err)
		r.Advance()
		return nil, err
	}
	if err = uconn.Handshake(); err != nil {
		if isHelloErr(err) {
			log.Debugf("got error likely related to bad hello; advancing roller: %v", err)
			r.Advance()
		}
		return nil, err
	}
	return &ptlshs.HandshakeResult{
		Version:     uconn.ConnectionState().Version,
		CipherSuite: uconn.ConnectionState().CipherSuite,
	}, nil
}
