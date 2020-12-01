package ptlshs

import (
	"bytes"
	"fmt"
	"math/rand"
	"time"
)

// Completion signal format:
//
// +-------------------------------------------------------------------+
// | signalPrefix | 32-byte nonce | padding up to signalLen: all zeros |
// +-------------------------------------------------------------------+

const (
	// We target this range to make the client completion signal look like an HTTP GET request.
	minSignalLenClient, maxSignalLenClient = 50, 300

	// The server signal is made to look like the response.
	minSignalLenServer, maxSignalLenServer = 250, 1400

	serverSignalLenSpread = 50
)

// Initialized in init. We narrow the range so that the server responses are somewhat consistent.
var actualMinSignalLenServer int

func init() {
	// Choose a random number in the range to serve as the minimum for this runtime.
	actualMinSignalLenServer = rand.Intn(maxSignalLenServer - minSignalLenServer - serverSignalLenSpread)
}

var signalPrefix = []byte("handshake complete")

type completionSignal []byte

func newClientCompletionSignal(ttl time.Duration) (*completionSignal, error) {
	nonce, err := newNonce(ttl)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	s := make(completionSignal, rand.Intn(maxSignalLenClient-minSignalLenClient)+minSignalLenClient)
	n := copy(s[:], signalPrefix)
	copy(s[n:], nonce[:])
	return &s, nil
}

func newServerCompletionSignal() (*completionSignal, error) {
	// We are not concerned about server signals being replayed to clients, so we don't bother
	// setting the nonce.
	s := make(completionSignal, rand.Intn(serverSignalLenSpread)+actualMinSignalLenServer)
	copy(s[:], signalPrefix)
	return &s, nil
}

func parseCompletionSignal(b []byte) (*completionSignal, error) {
	if len(b) < minSignalLenClient {
		return nil, fmt.Errorf("expected %d bytes, received %d", minSignalLenClient, len(b))
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
