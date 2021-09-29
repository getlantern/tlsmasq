package fuzz

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var CONNSEPARATOR = []byte("BBBBBBBB")

func assemblePacketToFile(packetId int, packetFilePath string, writer io.Writer) error {
	if packetId > 0 {
		_, err := writer.Write(PACKETSEPARATOR)
		if err != nil {
			return err
		}
	}
	fd, err := os.Open(packetFilePath)
	if err != nil {
		return err
	}
	defer fd.Close()
	_, err = io.Copy(writer, fd)
	if err != nil {
		return err
	}
	return nil
}

// AssemblePackets assembles all packet files (dumped during
// ECHOCONN_MODE_RECORD with dumpPacket()) into a single file, separated by
// CONNSEPARATOR for each net.Conn.
// The order of net.Conn is stable. From the beginning of the file, it should be:
// - `client`: all writes out of client's net.Conn to tlsmasq
// - `tlsmasq_origin`: all writes out of tlsmasq's net.Conn to origin
// - `origin`: all writes out of origin's net.Conn to tlsmasq
// - `tlsmasq_client`: all writes out of tlsmasq's net.Conn to client
//
// This graph is helpful:
//
//             1           2
//      client -> tlsmasq -> origin
//             <-         <-
//             4           3
//      1. client->tlsmasq writes
//      2. tlsmasq->origin writes
//      3. origin->tlsmasq writes
//      4. tlsmasq->client writes
//
// The opposite of this assembly is handled by ExtractConnDataFromFuzzData,
// whereas the assembled file is broken into different []byte slices
func AssemblePackets() error {
	// Make a new file in root of the project
	assembledPacketsFilepath := filepath.Join(recordedPacketsDirPath, "assembled.dat")
	assembledPacketsFile, err := os.Create(assembledPacketsFilepath)
	if err != nil {
		return err
	}
	clientFiles := []string{}
	tlsmasqToOriginFiles := []string{}
	OriginFiles := []string{}
	tlsmasqToClientFiles := []string{}
	files, err := ioutil.ReadDir(recordedPacketsDirPath)
	if err != nil {
		return err
	}
	// go over all files in recordedPacketsDirPath
	for _, file := range files {
		if strings.HasPrefix(file.Name(), "client__") {
			clientFiles = append(clientFiles, filepath.Join(recordedPacketsDirPath, file.Name()))
		} else if strings.HasPrefix(file.Name(), "tlsmasq_origin__") {
			tlsmasqToOriginFiles = append(tlsmasqToOriginFiles, filepath.Join(recordedPacketsDirPath, file.Name()))
		} else if strings.HasPrefix(file.Name(), "origin__") {
			OriginFiles = append(OriginFiles, filepath.Join(recordedPacketsDirPath, file.Name()))
		} else if strings.HasPrefix(file.Name(), "tlsmasq_client__") {
			tlsmasqToClientFiles = append(tlsmasqToClientFiles, filepath.Join(recordedPacketsDirPath, file.Name()))
		} else {
			continue
		}
	}
	if len(clientFiles) == 0 {
		return fmt.Errorf("No packets sent from client's net.Conn to anywhere")
	}
	if len(tlsmasqToOriginFiles) == 0 {
		return fmt.Errorf("No packets sent from tlsmasq's net.Conn to origin")
	}
	if len(OriginFiles) == 0 {
		return fmt.Errorf("No packets sent from origin's net.Conn to anywhere")
	}
	if len(tlsmasqToClientFiles) == 0 {
		return fmt.Errorf("No packets sent from tlsmasq's net.Conn to client")
	}

	for i, file := range clientFiles {
		err = assemblePacketToFile(i, file, assembledPacketsFile)
		if err != nil {
			return err
		}
		// os.Remove(file)
	}
	_, err = assembledPacketsFile.Write(CONNSEPARATOR)
	if err != nil {
		return err
	}

	for i, file := range tlsmasqToOriginFiles {
		err = assemblePacketToFile(i, file, assembledPacketsFile)
		if err != nil {
			return err
		}
		// os.Remove(file)
	}
	_, err = assembledPacketsFile.Write(CONNSEPARATOR)
	if err != nil {
		return err
	}

	for i, file := range OriginFiles {
		err = assemblePacketToFile(i, file, assembledPacketsFile)
		if err != nil {
			return err
		}
		// os.Remove(file)
	}
	_, err = assembledPacketsFile.Write(CONNSEPARATOR)
	if err != nil {
		return err
	}

	for i, file := range tlsmasqToClientFiles {
		err = assemblePacketToFile(i, file, assembledPacketsFile)
		if err != nil {
			return err
		}
		// os.Remove(file)
	}
	log.Printf("Assembled packet in %v\n", assembledPacketsFilepath)

	return nil
}

// Format for a fuzz file should be:
// - uint8 mentioning how many packets for client data
// - client data (containing util.echoconn.go:PACKETSEPARATOR as separator)
// - util.echoconn.go:CONNSEPARATOR
// - uint8 mentioning how many packets for server data
// - server data (containing util.echoconn.go:PACKETSEPARATOR as separator)
// For later
// - util.echoconn.go:CONNSEPARATOR
// - uint8 mentioning how many packets for origin data
// - origin data (containing util.echoconn.go:PACKETSEPARATOR as separator)
func ExtractConnDataFromFuzzData(fuzzData []byte) (
	clientData []byte, tlsmasqToOriginData []byte,
	originData []byte, tlsmasqToClientData []byte,
	err error) {
	if bytes.Count(fuzzData, CONNSEPARATOR) != 3 {
		return nil, nil, nil, nil, fmt.Errorf("Number of CONNSEPARATOR is not 3")
	}

	idx := bytes.Index(fuzzData, CONNSEPARATOR)
	clientData = fuzzData[:idx]
	if len(clientData) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("clientData is nil")
	}
	fuzzData = fuzzData[idx+len(CONNSEPARATOR):]

	idx = bytes.Index(fuzzData, CONNSEPARATOR)
	tlsmasqToOriginData = fuzzData[:idx]
	if len(tlsmasqToOriginData) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("tlsmasqToOriginData is nil")
	}
	fuzzData = fuzzData[idx+len(CONNSEPARATOR):]

	idx = bytes.Index(fuzzData, CONNSEPARATOR)
	originData = fuzzData[:idx]
	if len(originData) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("originData is nil")
	}
	fuzzData = fuzzData[idx+len(CONNSEPARATOR):]

	tlsmasqToClientData = fuzzData[:len(fuzzData)]
	if len(tlsmasqToClientData) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("tlsmasqToClientData is nil")
	}

	return clientData, tlsmasqToOriginData, originData, tlsmasqToClientData, nil
}
