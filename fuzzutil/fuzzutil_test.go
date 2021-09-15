package fuzzutil

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	mathRand "math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/getlantern/tlsmasq/projectpath"
	"github.com/stretchr/testify/require"
)

var recvHandshakeChan = make(chan []byte)

// DumpClientHelloConn implements net.Conn interface. It doesn't do anything
// apart from sending whatever it would write to recvHandshakeChan
type DumpClientHelloConn struct {
}

func (self *DumpClientHelloConn) Read(b []byte) (n int, err error) {
	return
}

func (self *DumpClientHelloConn) Write(b []byte) (n int, err error) {
	recvHandshakeChan <- b
	return len(b), nil
}

func (self *DumpClientHelloConn) Close() error {
	return nil
}

func (self *DumpClientHelloConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IP{127, 0, 0, 1}, Port: 49706, Zone: ""}
}

func (self *DumpClientHelloConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IP{127, 0, 0, 1}, Port: 49706, Zone: ""}
}

func (self *DumpClientHelloConn) SetDeadline(t time.Time) error {
	return nil
}

func (self *DumpClientHelloConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (self *DumpClientHelloConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// writeGenerationReport dumps a report including the git commit hash and tlsConfig
func writeGenerationReport(tlsConfig *tls.Config, fuzzOutDirPath string) error {
	var sb strings.Builder
	commitHash, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return err
	}
	sb.WriteString("This corpus was generated under:\n\n")
	sb.WriteString(fmt.Sprintf("- Date: %v\n", time.Now().Format(time.UnixDate)))
	sb.WriteString(fmt.Sprintf("- Commit: %v\n", strings.TrimSpace(string(commitHash))))
	sb.WriteString(fmt.Sprintf("- tls.Config: %v\n", spew.Sdump(tlsConfig)))
	err = os.WriteFile(filepath.Join(fuzzOutDirPath, "README.md"), []byte(sb.String()), 0644)
	if err != nil {
		return err
	}
	return nil
}

// TestGenerateClientHellos is not a test, but an entry to a standalone binary
// that runs and captures TLS ClientHello packets from various tls
// configurations. See "On Fuzzing" section in the READMe for more info
func TestGenerateClientHellos(t *testing.T) {
	// Safeguard from running this test with `go test ./...`
	if os.Getenv("DO") == "" {
		t.SkipNow()
	}

	for _, aCase := range []struct {
		tlsConfig *tls.Config
	}{
		{
			tlsConfig: &tls.Config{InsecureSkipVerify: true},
		},
	} {
		// Make a random identifier for each fuzz input directory
		fileid, err := getSecureRandomIdentifier()
		require.NoError(t, err)
		fuzzOutDirPath := fmt.Sprintf(filepath.Join(projectpath.Root,
			"fuzz_workdir/annotated_corpus", "%s"), fileid)
		require.NoError(t, os.MkdirAll(fuzzOutDirPath, os.ModePerm))

		// For each config, make 5 permutations with different seeds
		for i := 0; i < 5; i++ {
			// Make a random seed
			// XXX Currently, the random number seed is the entire serializable
			// tls configuration we work with. See 'On Fuzzing: Limitations'
			// section in the README for more details
			seed, err := getSecureRandomByteSlice(CONFIG_SIZE)
			require.NoError(t, err)

			nonce, key, encryptedConfig, err := encryptFuzzConfig(seed)
			require.NoError(t, err)

			// XXX 0 here doesn't mean anything. The seed is implanted in
			// mathRand.Seed()
			aCase.tlsConfig.Rand = MathRandReader(0)
			mathRand.Seed(int64(binary.LittleEndian.Uint64(seed)))
			tlsClient := tls.Client(new(DumpClientHelloConn), aCase.tlsConfig)
			// XXX This will block until a read occurs, which will never happen
			// since we're short-circuiting the program after a successful
			// net.Conn.Write()
			go func() {
				require.NoError(t, tlsClient.Handshake())
			}()

			// Wait until a write is done and close everything
			clientHelloData := <-recvHandshakeChan
			require.NoError(t, tlsClient.Close())

			fuzzInput := packFuzzInput(nonce, key, encryptedConfig, clientHelloData)
			outFilePath := fmt.Sprintf(filepath.Join(fuzzOutDirPath, "%s_%d.raw"), fileid, i)
			err = os.WriteFile(outFilePath, fuzzInput, 0644)
			require.NoError(t, err)
			log.Printf("Wrote config %+v with seed %v and key %v to %s\n", aCase.tlsConfig, seed, key, outFilePath)
		}
		err = writeGenerationReport(aCase.tlsConfig, fuzzOutDirPath)
		require.NoError(t, err)
	}
}

// TestFuzz is a predictable sanity check for `fuzz.go:Fuzz()`
//
// It basically does the same thing as `fuzz.go:Fuzz()`, which is run
// fuzzutil.RunFuzz(), but does it without any mutations. Helpful for debugging
// specific cases
func TestFuzz(t *testing.T) {
	t.Parallel()

	inputDir := filepath.Join(projectpath.Root, "fuzz_workdir/corpus")
	inputFiles, err := ioutil.ReadDir(inputDir)
	require.NoError(t, err)
	for _, f := range inputFiles {
		data, err := os.ReadFile(filepath.Join(inputDir, f.Name()))
		require.NoError(t, err)
		seedAsBytes, clientHelloHandshake, err := DecryptAndUnpackFuzzInput(data)
		require.NoError(t, err)
		seed := int64(binary.LittleEndian.Uint64(seedAsBytes))
		// log.Println(len(clientHelloHandshake))
		// log.Println(seed)
		require.NoError(t, RunFuzz(seed, clientHelloHandshake))
	}
}
