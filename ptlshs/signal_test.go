package ptlshs

import (
	"crypto/sha256"
	"io/ioutil"
	"testing"

	"github.com/getlantern/tlsutil"
	"github.com/stretchr/testify/require"
)

func TestSignalLen(t *testing.T) {
	// Sanity checks not checked at runtime.
	require.LessOrEqual(t, len(signalPrefix)+len(nonce{}), minSignalLenClient)
	require.LessOrEqual(t, minSignalLenClient, absMinSignalLenServer)
	require.GreaterOrEqual(t, absMinSignalLenServer, len(signalPrefix)+sha256.Size)
}

// The client assumes the server signal will arrive in a single record. This test ensures that is
// true across all cipher suites (which have varying maximum payload sizes).
func TestSingleRecordSignal(t *testing.T) {
	tlsutil.TestOverAllSuites(t, func(t *testing.T, version, suite uint16) {
		cs, err := tlsutil.NewConnectionState(version, suite, [52]byte{}, [16]byte{}, [8]byte{})
		require.NoError(t, err)
		payload := make([]byte, absMaxSignalLenServer)
		_, err = tlsutil.WriteRecord(ioutil.Discard, payload, cs)
		// WriteRecord will return an error if the payload does not fit in a single record.
		require.NoError(t, err)
	})
}
