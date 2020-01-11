package ptlshs

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"time"
)

const (
	// An HTTP GET request will be about 100 bytes so we target this length with our signal.
	ptlsSignalLen = 100
)

var ptlsSignalPrefix = []byte("handshake complete")

type ptlsSignal [ptlsSignalLen]byte

func newCompletionSignal(ttl time.Duration) (*ptlsSignal, error) {
	nonce, err := newNonce(ttl)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	s := ptlsSignal{}
	n := copy(s[:], ptlsSignalPrefix)
	n += copy(s[n:], nonce[:])
	if _, err := rand.Read(s[n:]); err != nil {
		return nil, fmt.Errorf("failed to generate random padding: %w", err)
	}
	return &s, nil
}

func parseCompletionSignal(b []byte) (*ptlsSignal, error) {
	s := ptlsSignal{}
	if len(b) != len(s) {
		return nil, fmt.Errorf("expected %d bytes, received %d", len(s), len(b))
	}
	if !bytes.HasPrefix(b, ptlsSignalPrefix) {
		return nil, fmt.Errorf("missing signal prefix")
	}
	copy(s[:], b[:])
	return &s, nil
}

func (s ptlsSignal) getNonce() nonce {
	n := nonce{}
	copy(n[:], s[len(ptlsSignalPrefix):])
	return n
}
