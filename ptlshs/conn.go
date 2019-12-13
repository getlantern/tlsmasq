package ptlshs

import (
	"net"
	"sync"
)

// Conn is the dereferenced version of the concrete type returned whenever a net.Conn is returned in
// this package. Most users will not need this type.
type Conn struct {
	// The underlying connection to the server. This is likely just a TCP connection.
	net.Conn

	version, suite uint16

	seq [8]byte
	iv  [16]byte

	seqLock sync.Mutex
}

// Version is the TLS version negotiated during the proxied handshake.
func (c *Conn) Version() uint16 {
	return c.version
}

// CipherSuite is the cipher suite negotiated during the proxied handshake.
func (c *Conn) CipherSuite() uint16 {
	return c.suite
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
