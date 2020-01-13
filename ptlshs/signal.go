package ptlshs

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"time"
)

// Completion signal format:
//
// +--------------------------------------------------------+
// | signalPrefix | 32-byte nonce | padding up to signalLen |
// +--------------------------------------------------------+

const (
	// An HTTP GET request will be about 100 bytes so we target this length with our signal.
	signalLen = 100
)

var signalPrefix = []byte("handshake complete")

type completionSignal [signalLen]byte

func newCompletionSignal(ttl time.Duration) (*completionSignal, error) {
	nonce, err := newNonce(ttl)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	s := completionSignal{}
	n := copy(s[:], signalPrefix)
	n += copy(s[n:], nonce[:])
	if _, err := rand.Read(s[n:]); err != nil {
		return nil, fmt.Errorf("failed to generate random padding: %w", err)
	}
	return &s, nil
}

func parseCompletionSignal(b []byte) (*completionSignal, error) {
	s := completionSignal{}
	if len(b) != len(s) {
		return nil, fmt.Errorf("expected %d bytes, received %d", len(s), len(b))
	}
	if !bytes.HasPrefix(b, signalPrefix) {
		return nil, fmt.Errorf("missing signal prefix")
	}
	copy(s[:], b[:])
	return &s, nil
}

func (s completionSignal) getNonce() nonce {
	n := nonce{}
	copy(n[:], s[len(signalPrefix):])
	return n
}
