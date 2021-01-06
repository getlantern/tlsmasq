package ptlshs

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignalLen(t *testing.T) {
	// Sanity checks not checked at runtime.
	require.LessOrEqual(t, len(signalPrefix)+len(nonce{}), minSignalLenClient)
	require.LessOrEqual(t, minSignalLenClient, minSignalLenServer)
	require.GreaterOrEqual(t, minSignalLenServer, len(signalPrefix)+sha256.Size)
	// TODO: is this actually necessary for a SHA256-based HMAC? If so, move this somewhere else?
	require.GreaterOrEqual(t, len(Secret{}), sha256.Size)
}
