package tlsmasq

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/getlantern/tlsmasq/ptlshs"
)

// hijack a TLS connection. This new connection will use the same TLS version and cipher suite, but
// a new set of symmetric keys will be negotiated via a second handshake. The input tls.Config will
// be used for this second handshake. As such, things like session resumption are also supported.
//
// All communication during this second handshake will be disguised in TLS records, secured using
// the already-negotiated version and cipher suite, but with the preshared secret.
//
// Because we want to continue with the already-negotiated version and cipher suite, it is an error
// to use a tls.Config which does not support this version and/or suite. However, it is important to
// set fields like cfg.CipherSuites and cfg.MinVersion to ensure that the security parameters of the
// hijacked connection are acceptable.
func hijack(conn *ptlshs.Conn, cfg *tls.Config, preshared ptlshs.Secret) (net.Conn, error) {
	cfg, err := ensureParameters(cfg, conn)
	if err != nil {
		return nil, err
	}

	disguisedConn := disguisedConn{conn.Conn, conn, preshared, true}
	hijackedConn := tls.Client(&disguisedConn, cfg)
	if err := hijackedConn.Handshake(); err != nil {
		return nil, fmt.Errorf("hijack handshake failed: %w", err)
	}

	// Now that the handshake is complete, we no longer need the disguise. The connection is
	// successfully hijacked and further communication will be conducted with the appropriate
	// version and suite, but newly-negotiated symmetric keys.
	disguisedConn.inDisguise = false
	return hijackedConn, nil
}

// allowHijack is the server-side counterpart to hijack. Waits for the second handshake on the
// connection, expecting the handshake to be disguised. Expects that the disguise will be shed when
// the handshake is complete.
func allowHijack(conn *ptlshs.Conn, cfg *tls.Config, preshared ptlshs.Secret) (net.Conn, error) {
	cfg, err := ensureParameters(cfg, conn)
	if err != nil {
		return nil, err
	}

	disguisedConn := disguisedConn{conn.Conn, conn, preshared, true}
	hijackedConn := tls.Server(&disguisedConn, cfg)
	if err := hijackedConn.Handshake(); err != nil {
		return nil, fmt.Errorf("hijack handshake failed: %w", err)
	}

	// Now that the handshake is complete, we no longer need the disguise. The connection is
	// successfully hijacked and further communication will be conducted with the appropriate
	// version and suite, but newly-negotiated symmetric keys.
	disguisedConn.inDisguise = false
	return hijackedConn, nil
}

func ensureParameters(cfg *tls.Config, conn *ptlshs.Conn) (*tls.Config, error) {
	version, suite := conn.TLSVersion(), conn.CipherSuite()
	if !suiteSupported(cfg, suite) {
		return nil, fmt.Errorf("negotiated suite %d is not supported", suite)
	}
	if version < cfg.MinVersion || version > cfg.MaxVersion {
		return nil, fmt.Errorf("negotiated version %d is not supported", version)
	}

	cfg = cfg.Clone()
	cfg.MinVersion, cfg.MaxVersion = version, version
	cfg.CipherSuites = []uint16{suite}
	return cfg, nil
}

func suiteSupported(cfg *tls.Config, suite uint16) bool {
	if cfg.CipherSuites == nil {
		return true
	}
	for _, supportedSuite := range cfg.CipherSuites {
		if supportedSuite == suite {
			return true
		}
	}
	return false
}

type disguisedConn struct {
	net.Conn

	ptlshsConn *ptlshs.Conn
	preshared  ptlshs.Secret

	// When set, this connection will disguise writes as TLS records using the parameters of
	// ptlshsConn and the pre-shared secret. Reads will be assumed to be disguised as well.
	// When unset, this connection just uses the underlying net.Conn directly.
	inDisguise bool
}

func (dc *disguisedConn) Read(b []byte) (n int, err error) {
	if !dc.inDisguise {
		return dc.Conn.Read(b)
	}

	// TODO: implement me!
	return 0, nil
}

func (dc *disguisedConn) Write(b []byte) (n int, err error) {
	if !dc.inDisguise {
		return dc.Conn.Write(b)
	}

	// TODO: implement me!
	return 0, nil
}
