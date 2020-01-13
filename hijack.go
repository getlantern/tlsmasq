package tlsmasq

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"

	"github.com/getlantern/tlsmasq/internal/reptls"
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
func hijack(conn ptlshs.Conn, cfg *tls.Config, preshared ptlshs.Secret,
	tlsConn func(net.Conn, *tls.Config) *tls.Conn) (net.Conn, error) {

	if err := conn.Handshake(); err != nil {
		return nil, fmt.Errorf("proxied handshake failed: %w", err)
	}
	cfg, err := ensureParameters(cfg, conn)
	if err != nil {
		return nil, err
	}
	disguisedConn, err := disguise(conn, preshared)
	if err != nil {
		return nil, err
	}
	hijackedConn := tlsConn(disguisedConn, cfg)
	if err := hijackedConn.Handshake(); err != nil {
		return nil, fmt.Errorf("hijack handshake failed: %w", err)
	}

	// Now that the handshake is complete, we no longer need the disguise. The connection is
	// successfully hijacked and further communication will be conducted with the appropriate
	// version and suite, but newly-negotiated symmetric keys.
	disguisedConn.inDisguise = false
	return hijackedConn, nil
}

func ensureParameters(cfg *tls.Config, conn ptlshs.Conn) (*tls.Config, error) {
	version, suite := conn.TLSVersion(), conn.CipherSuite()
	if !suiteSupported(cfg, suite) {
		return nil, fmt.Errorf("negotiated suite %#x is not supported", suite)
	}
	if !versionSupported(cfg, version) {
		return nil, fmt.Errorf("negotiated version %#x is not supported", version)
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

func versionSupported(cfg *tls.Config, version uint16) bool {
	if version < cfg.MinVersion {
		return false
	}
	if cfg.MaxVersion != 0 && version > cfg.MaxVersion {
		return false
	}
	return true
}

type disguisedConn struct {
	net.Conn

	state     *reptls.ConnState
	preshared ptlshs.Secret
	iv        [16]byte

	// processed holds data unwrapped from TLS records.
	// unprocessed holds data which is either not yet unwrapped or was not wrapped to begin with.
	processed, unprocessed *bytes.Buffer

	// When set, this connection will disguise writes as TLS records using the parameters of
	// ptlshsConn and the pre-shared secret. Reads will be assumed to be disguised as well.
	// When unset, this connection just uses the underlying net.Conn directly.
	inDisguise bool
}

func disguise(conn ptlshs.Conn, preshared ptlshs.Secret) (*disguisedConn, error) {
	state, err := reptls.NewConnState(conn.TLSVersion(), conn.CipherSuite(), conn.NextSeq())
	if err != nil {
		return nil, fmt.Errorf("failed to derive connection state: %w", err)
	}
	return &disguisedConn{
		conn, state, preshared, conn.IV(), new(bytes.Buffer), new(bytes.Buffer), true,
	}, nil
}

func (dc *disguisedConn) Read(b []byte) (n int, err error) {
	if !dc.inDisguise {
		return io.MultiReader(dc.processed, dc.unprocessed, dc.Conn).Read(b)
	}

	// Note: the only error a bytes.Buffer can return is io.EOF, which we would ignore anyway.
	n, _ = dc.processed.Read(b)
	if n > 0 {
		return
	}

	connReader := io.MultiReader(dc.unprocessed, dc.Conn)
	record, unprocessed, err := reptls.ReadRecord(connReader, dc.state, dc.preshared, dc.iv)
	if err != nil {
		return n, fmt.Errorf("failed to unwrap TLS record: %w", err)
	}
	nCopied := copy(b[n:], record)
	n += nCopied
	// Note: writes to bytes.Buffers do not return errors.
	dc.processed.Write(record[nCopied:])
	dc.unprocessed.Write(unprocessed)
	return
}

func (dc *disguisedConn) Write(b []byte) (n int, err error) {
	if !dc.inDisguise {
		return dc.Conn.Write(b)
	}
	n, err = reptls.WriteRecord(dc.Conn, b, dc.state, dc.preshared, dc.iv)
	if err != nil {
		err = fmt.Errorf("failed to wrap data in TLS record: %w", err)
	}
	return
}
