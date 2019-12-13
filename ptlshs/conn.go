package ptlshs

import (
	"crypto/tls"
	"net"
	"sync"
)

// Conn is the dereferenced version of the concrete type returned whenever a net.Conn is returned in
// this package. Most users will not need this type.
type Conn struct {
	// The underlying connection to the server. This is likely just a TCP connection.
	net.Conn

	// The state of the TLS connection with the proxied server. Useful for determining things like
	// the negotiated version and cipher suite.
	proxiedConnectionState tls.ConnectionState

	seq [8]byte
	iv  [16]byte

	seqLock sync.Mutex
}

// NextSeq increments and returns the connection's sequence number. The starting sequence number is
// derived from the server random in the proxied handshake. Dialers and listeners will have the same
// derived sequence numbers, so this can be used in cipher suites which use the sequence number as a
// nonce.
func (c *Conn) NextSeq() [8]byte {
	c.seqLock.Lock()
	defer c.seqLock.Unlock()

	// Taken from crypto/tls.halfConn.incSeq.
	for i := 7; i >= 0; i-- {
		c.seq[i]++
		if c.seq[i] != 0 {
			return c.seq
		}
	}

	// Not allowed to let sequence number wrap.
	// Instead, must renegotiate before it does.
	// Not likely enough to bother.
	panic("TLS: sequence number wraparound")
}

// IV is an initialization vector. This is derived from the server random in the proxied handshake.
// Dialers and listeners will have the same IV, so this can be used when needed in ciphers.
func (c *Conn) IV() [16]byte {
	return c.iv
}

// ProxiedConnectionState returns the state of the TLS connection with the proxied server. This is
// useful for determining things like the negotiated version and cipher suite.
func (c *Conn) ProxiedConnectionState() tls.ConnectionState {
	return c.proxiedConnectionState
}
