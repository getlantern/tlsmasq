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
	require.GreaterOrEqual(t, len(Secret{}), sha256.Size)
}
