package ptlshs

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordReader(t *testing.T) {
	const numDataRecords = 5

	t.Parallel()

	var (
		stream = createRecordStream(t, numDataRecords)
		rr     = new(recordReader)

		// Vetted in the first test.
		recordsBaseline = rr.read(stream)
	)

	t.Run("simple", func(t *testing.T) {
		require.GreaterOrEqual(t, len(recordsBaseline), 1)
		require.Equal(t, recordTypeHandshake, recordsBaseline[0].recordType())
		parsedDataRecords := 0
		joinedRecords := []byte{}
		for _, r := range recordsBaseline {
			if r.recordType() == recordTypeApplicationData {
				parsedDataRecords++
			} else {
				require.Equal(t, 0, parsedDataRecords, "records out of order (data record followed by non-data record)")
			}
			joinedRecords = append(joinedRecords, r...)
		}
		require.Equal(t, stream, joinedRecords)
	})
	t.Run("multiple reads", func(t *testing.T) {
		var (
			rr        = new(recordReader)
			records   = []tlsRecord{}
			streamBuf = bytes.NewBuffer(stream)
		)
		for streamBuf.Len() > 0 {
			currentSliceLen, err := randInt(1, streamBuf.Len())
			require.NoError(t, err)
			currentSlice := streamBuf.Next(currentSliceLen)
			records = append(records, rr.read(currentSlice)...)
		}
		for i, r := range records {
			require.Equal(t, recordsBaseline[i], r, "record %d failed baseline check", i)
		}
	})
	t.Run("on boundary", func(t *testing.T) {
		var (
			rr            = new(recordReader)
			records       = []tlsRecord{}
			streamBuf     = bytes.NewBuffer(stream)
			currentRecord = 0
		)
		for streamBuf.Len() > 0 {
			currentSlice := streamBuf.Next(len(recordsBaseline[currentRecord]))
			records = append(records, rr.read(currentSlice)...)
			currentRecord++
		}
		for i, r := range records {
			require.Equal(t, recordsBaseline[i], r, "record %d failed baseline check", i)
		}
	})
	t.Run("mid-header", func(t *testing.T) {
		var (
			rr            = new(recordReader)
			records       = []tlsRecord{}
			streamBuf     = bytes.NewBuffer(stream)
			currentRecord = 0
			posInHdr      = 0
			err           error
		)
		for streamBuf.Len() > 0 {
			currentLen := len(recordsBaseline[currentRecord])
			nextStart := currentLen - posInHdr
			posInHdr, err = randInt(1, recordHeaderLen-1)
			require.NoError(t, err)
			currentSlice := streamBuf.Next(nextStart + posInHdr)

			records = append(records, rr.read(currentSlice)...)
			currentRecord++
		}
		for i, r := range records {
			require.Equal(t, recordsBaseline[i], r, "record %d failed baseline check", i)
		}
	})
}

func createRecordStream(t *testing.T, dataRecords int) []byte {
	t.Helper()

	clientTCP, _serverTCP := net.Pipe()
	serverTCP := newRecordingConn(_serverTCP)

	client := tls.Client(clientTCP, &tls.Config{InsecureSkipVerify: true})
	server := tls.Server(serverTCP, &tls.Config{Certificates: []tls.Certificate{cert}})
	defer server.Close()
	defer client.Close()

	go func() {
		assert.NoError(t, client.Handshake())
		// Read from the client side until the connection is closed
		b := make([]byte, 1024)
		for {
			if _, err := client.Read(b); err != nil {
				return
			}
		}
	}()
	require.NoError(t, server.Handshake())

	// We have to read from the server side of the connection or the deferred client.Close call will
	// block forever (it tries to write and piped connections have no internal buffering).
	go func() {
		b := make([]byte, 1024)
		for {
			if _, err := server.Read(b); err != nil {
				return
			}
		}
	}()

	for i := 0; i < dataRecords; i++ {
		lenData, err := randInt(1, 1024)
		require.NoError(t, err)
		server.Write(randomData(t, lenData))
	}
	return serverTCP.writeBuf.Bytes()
}

type recordingConn struct {
	net.Conn
	recordingW io.Writer
	writeBuf   *bytes.Buffer
}

func newRecordingConn(conn net.Conn) recordingConn {
	buf := new(bytes.Buffer)
	return recordingConn{conn, io.MultiWriter(conn, buf), buf}
}

func (rc recordingConn) Write(b []byte) (int, error) {
	return rc.recordingW.Write(b)
}
