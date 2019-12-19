package reptls

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	certPem = []byte(`-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`)
	keyPem = []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAoGCCqGSM49
AwEHoUQDQgAEPR3tU2Fta9ktY+6P9G0cWO+0kETA6SFs38GecTyudlHz6xvCdz8q
EKTcWGekdmdDPsHloRNtsiCa697B2O9IFA==
-----END EC PRIVATE KEY-----`)

	cert tls.Certificate
)

func init() {
	var err error
	cert, err = tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		panic(err)
	}
}

func TestReadAndWrite(t *testing.T) {
	t.Parallel()

	var (
		secret [52]byte
		iv     [16]byte
		seq    [8]byte
		err    error

		msg = "some great secret"
		buf = new(bytes.Buffer)
	)

	_, err = rand.Read(secret[:])
	require.NoError(t, err)
	_, err = rand.Read(iv[:])
	require.NoError(t, err)
	_, err = rand.Read(seq[:])
	require.NoError(t, err)

	pre13Suites, tls13Suites := []uint16{}, []uint16{}
	for suiteValue, suite := range cipherSuites {
		if _, is13 := suite.(cipherSuiteTLS13); is13 {
			tls13Suites = append(tls13Suites, suiteValue)
		} else {
			pre13Suites = append(pre13Suites, suiteValue)
		}
	}

	testFunc := func(version, suite uint16) func(t *testing.T) {
		return func(t *testing.T) {
			t.Helper()

			writerState, err := NewConnState(version, suite, seq)
			require.NoError(t, err)
			readerState, err := NewConnState(version, suite, seq)
			require.NoError(t, err)

			_, err = WriteRecord(buf, []byte(msg), writerState, secret, iv)
			require.NoError(t, err)

			roundTripped, err := ReadRecord(buf, readerState, secret, iv)
			require.NoError(t, err)

			require.Equal(t, msg, string(roundTripped))
		}
	}

	for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12} {
		for _, suite := range pre13Suites {
			t.Run(fmt.Sprintf("version_%#x_suite%#x", version, suite), testFunc(version, suite))
		}
	}
	for _, suite := range tls13Suites {
		t.Run(fmt.Sprintf("version_%#x_suite%#x", tls.VersionTLS13, suite), testFunc(tls.VersionTLS13, suite))
	}
}

func TestReadRecords(t *testing.T) {
	var (
		secret [52]byte
		iv     [16]byte
		seq    [8]byte

		msgs           = []string{"fee", "fi", "fo", "fum"}
		version uint16 = tls.VersionTLS13
		suite          = tls.TLS_AES_128_GCM_SHA256
		buf            = new(bytes.Buffer)
	)

	writerState, err := NewConnState(version, suite, seq)
	require.NoError(t, err)
	readerState, err := NewConnState(version, suite, seq)
	require.NoError(t, err)

	_, err = rand.Read(secret[:])
	require.NoError(t, err)
	_, err = rand.Read(iv[:])
	require.NoError(t, err)
	_, err = rand.Read(seq[:])
	require.NoError(t, err)

	for _, msg := range msgs {
		_, err = WriteRecord(buf, []byte(msg), writerState, secret, iv)
		require.NoError(t, err)
	}

	results := ReadRecords(buf, readerState, secret, iv)
	require.Equal(t, len(msgs), len(results))
	for i := 0; i < len(results); i++ {
		require.NoError(t, results[i].Err)
		require.Equal(t, msgs[i], string(results[i].Read))
	}
}
