package ptlshs

import (
	"bytes"
	"crypto/rand"
	"fmt"
	mathrand "math/rand"
	"time"
)

// Completion signal format:
//
// +--------------------------------------------------------+
// | signalPrefix | 32-byte nonce | padding up to signalLen |
// +--------------------------------------------------------+

const (
	// We target this range to make our completion signal look like an HTTP request. We could
	// probably stand to do a bit of research on the best values here.
	minSignalLen, maxSignalLen = 50, 300
)

var signalPrefix = []byte("handshake complete")

type completionSignal []byte

func newCompletionSignal(ttl time.Duration) (*completionSignal, error) {
	nonce, err := newNonce(ttl)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	s := make(completionSignal, mathrand.Intn(maxSignalLen-minSignalLen)+minSignalLen)
	n := copy(s[:], signalPrefix)
	n += copy(s[n:], nonce[:])
	if _, err := rand.Read(s[n:]); err != nil {
		return nil, fmt.Errorf("failed to generate random padding: %w", err)
	}
	return &s, nil
}

func parseCompletionSignal(b []byte) (*completionSignal, error) {
	if len(b) < minSignalLen {
		return nil, fmt.Errorf("expected %d bytes, received %d", minSignalLen, len(b))
	}
	if !bytes.HasPrefix(b, signalPrefix) {
		return nil, fmt.Errorf("missing signal prefix")
	}
	s := make(completionSignal, len(b))
	copy(s[:], b[:])
	return &s, nil
}

func (s completionSignal) getNonce() nonce {
	n := nonce{}
	copy(n[:], s[len(signalPrefix):])
	return n
}
