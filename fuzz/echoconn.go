package fuzz

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
)

const (
	ECHOCONN_MODE_RECORD = iota
	ECHOCONN_MODE_USE    = iota
)

var PACKETSEPARATOR = []byte("AAAAAAAA")
var recordedPacketsDirPath string
var echoConnMode = ECHOCONN_MODE_USE

// XXX <30-09-21, soltzen> When recording and observing logs, it's sometimes easy to have a very
// clear sequence. Uncomment this and the other mutex lock code to achieve
// this. This is not necessary in production
// var packageLock = sync.Mutex{}

type EchoConn struct {
	net.Conn
	id        string
	writeData []byte
	seq       int
}

func InitRecording() error {
	echoConnMode = ECHOCONN_MODE_RECORD
	var err error
	recordedPacketsDirPath, err = filepath.Abs("./tmp")
	if err != nil {
		return err
	}
	err = os.MkdirAll(recordedPacketsDirPath, os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

func NewEchoConn(id string, conn net.Conn, writeData []byte) *EchoConn {
	return &EchoConn{conn, id, writeData, 0}
}

func (self *EchoConn) dumpPacket(data []byte) error {
	outFilePath := filepath.Join(recordedPacketsDirPath, fmt.Sprintf("%s__%d.dat", self.id, self.seq))
	f, err := os.Create(outFilePath)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err != nil {
		return err
	}
	return nil
}

// Write() sends self.clientData instead of the original byte slice Conn wanted to send
func (self *EchoConn) Write(originalBuff []byte) (n int, err error) {
	if len(originalBuff) == 0 {
		panic("Must never happen")
	}
	// packageLock.Lock()
	// defer packageLock.Unlock()

	if echoConnMode == ECHOCONN_MODE_RECORD {
		// Write and dump the packets to a file
		n, err = self.Conn.Write(originalBuff)
		if err != nil {
			return 0, err
		}
		log.Printf("%v sent %d bytes\n", self.id, len(originalBuff))
		err = self.dumpPacket(originalBuff)
		if err != nil {
			return 0, err
		}
		self.seq++
	} else if echoConnMode == ECHOCONN_MODE_USE {
		// Use the packets in self.writeData.
		//
		// Each file contains all the packets this net.Conn should send.
		// Each packet in the file is separated by a PACKETSEPARATOR.
		//
		// The last packet does not have any PACKETSEPARATOR before the EOF
		var limit int
		var nextWriteDataValue []byte

		idx := bytes.Index(self.writeData, PACKETSEPARATOR)
		if idx == -1 {
			// Means we reached the end of the file: the limit here then is
			// until end of the file and there's no next write data value
			limit = len(self.writeData)
			nextWriteDataValue = nil
		} else {
			limit = idx
			nextWriteDataValue = self.writeData[limit+len(PACKETSEPARATOR):]
		}

		fmt.Printf("%v sent %d bytes: ", self.id, len(originalBuff))
		n, err = self.Conn.Write(self.writeData[:limit])
		fmt.Printf("DONE\n")
		self.writeData = nextWriteDataValue
	}
	return
}
