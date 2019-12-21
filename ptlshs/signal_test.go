package ptlshs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProxiedSignalLen(t *testing.T) {
	// Just a sanity check since this isn't checked at runtime.
	require.LessOrEqual(t, len(ptlsSignalPrefix)+len(Nonce{}), len(ptlsSignal{}))
}
