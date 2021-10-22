// Command start-corpus was used to generate the initial fuzzing corpus. It is kept here for
// illustrative purposes.
//
// This will create a corpus of ClientHellos based on those seen from popular web browsers. Note
// that the output files do *not* contain record headers: they contain only the hello message. This
// is because utls.FingerprintClientHello accepts hello messages, not full records.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/getlantern/tlsmasq/internal/testutil"
	utls "github.com/refraction-networking/utls"
)

var outputDir = flag.String("output-dir", "corpus", "the output directory for the initial corpus")

func startCorpus(dirpath string) error {
	utlsCfg := &utls.Config{
		InsecureSkipVerify: true,
		Certificates:       []utls.Certificate{testutil.UTLSCert},
	}
	helloIDs := []utls.ClientHelloID{
		utls.HelloFirefox_65,
		utls.HelloChrome_83,
		utls.HelloIOS_12_1,
		utls.HelloEdge_85,
		utls.HelloExplorer_11,
		utls.HelloSafari_13_1,
		utls.Hello360_7_5,
		utls.HelloQQ_10_6,
	}

	if err := os.MkdirAll(dirpath, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	for _, hid := range helloIDs {
		uconn := utls.UClient(nil, utlsCfg, hid)
		if err := uconn.BuildHandshakeState(); err != nil {
			return fmt.Errorf("failed to build handshake state for %s: %w", hid.Str(), err)
		}
		err := os.WriteFile(filepath.Join(dirpath, hid.Str()), uconn.HandshakeState.Hello.Raw, 0644)
		if err != nil {
			return fmt.Errorf("failed to write file for %s: %w", hid.Str(), err)
		}
	}
	return nil
}

func main() {
	flag.Parse()

	if err := startCorpus(*outputDir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
