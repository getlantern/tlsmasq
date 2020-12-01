package ptlshs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignalLen(t *testing.T) {
	// Just a sanity check since this isn't checked at runtime.
	require.LessOrEqual(t, len(signalPrefix)+len(nonce{}), minSignalLenClient)
	require.LessOrEqual(t, minSignalLenClient, minSignalLenServer)
}
