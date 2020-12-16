package ptlshs

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"time"
)

// Both the client and the server send a completion signal.
//
// Client signal format:
//
// +-------------------------------------------------------------------+
// | signalPrefix | 32-byte nonce  | padding up to signalLen: all zeros |
// +-------------------------------------------------------------------+
//
// Server signal format:
//
// +--------------------------------------------------------------------+
// | signalPrefix | transcript MAC | padding up to signalLen: all zeros |
// +--------------------------------------------------------------------+
//
// where 'transcript MAC' is a MAC of everything sent from the server to the client. This MAC is
// performed using SHA-256 and the pre-shared secret. For an explanation of this MAC's purpose, see
// clientConn.watchForCompletion.

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

type clientSignal []byte

func newClientSignal(ttl time.Duration) (*clientSignal, error) {
	nonce, err := newNonce(ttl)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	cs := make(clientSignal, rand.Intn(maxSignalLenClient-minSignalLenClient)+minSignalLenClient)
	n := copy(cs[:], signalPrefix)
	copy(cs[n:], nonce[:])
	return &cs, nil
}

func parseClientSignal(b []byte) (*clientSignal, error) {
	if len(b) < minSignalLenClient {
		return nil, fmt.Errorf("expected %d bytes, received %d", minSignalLenClient, len(b))
	}
	if !bytes.HasPrefix(b, signalPrefix) {
		return nil, fmt.Errorf("missing signal prefix")
	}
	cs := make(clientSignal, len(b))
	copy(cs[:], b[:])
	return &cs, nil
}

func (cs clientSignal) getNonce() nonce {
	n := nonce{}
	copy(n[:], cs[len(signalPrefix):])
	return n
}

type serverSignal []byte

func newServerSignal(transcript []byte, s Secret) (*serverSignal, error) {
	ss := make(serverSignal, rand.Intn(serverSignalLenSpread)+actualMinSignalLenServer)
	n := copy(ss[:], signalPrefix)
	m := hmac.New(sha256.New, s[:sha256.Size])
	m.Write(transcript)
	copy(ss[n:], m.Sum(nil))
	return &ss, nil
}

func parseServerSignal(b []byte) (*serverSignal, error) {
	if len(b) < minSignalLenServer {
		return nil, fmt.Errorf("expected %d bytes, received %d", minSignalLenServer, len(b))
	}
	if !bytes.HasPrefix(b, signalPrefix) {
		return nil, fmt.Errorf("missing signal prefix")
	}
	ss := make(serverSignal, len(b))
	copy(ss[:], b[:])
	return &ss, nil
}

func (ss serverSignal) validMAC(transcript []byte, s Secret) bool {
	m := hmac.New(sha256.New, s[:sha256.Size])
	m.Write(transcript)
	computed := m.Sum(nil)
	embedded := ss[len(signalPrefix) : len(signalPrefix)+sha256.Size]
	return hmac.Equal(computed, embedded)
}
