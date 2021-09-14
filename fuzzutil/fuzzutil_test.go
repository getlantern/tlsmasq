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

func TestGenerateClientHellos(t *testing.T) {
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
			// Make random seed and write seed to file, along with the seedAndDataSeparator
			seed, err := getSecureRandomByteSlice(CONFIG_SIZE)
			require.NoError(t, err)
			nonce, key, encryptedConfig, err := encryptFuzzConfig(seed)
			require.NoError(t, err)

			// Set tlsConfig default valus and make tlsClient
			aCase.tlsConfig.Rand = MathRandReader(0)
			mathRand.Seed(int64(binary.LittleEndian.Uint64(seed)))
			// myCase.tlsConfig.Time = func() time.Time { return time.Date(2000, 1, 1, 1, 1, 1, 1, nil) }
			tlsClient := tls.Client(new(DumpClientHelloConn), aCase.tlsConfig)
			// XXX This will block until a read occurs, which will never happen
			go func() {
				require.NoError(t, tlsClient.Handshake())
			}()

			// Wait until a write is done and close stuff
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
		require.NoError(t, RunTestFuzz(seed, clientHelloHandshake))
	}
}
