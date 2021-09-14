package fuzzutil

import "net"

type fuzzEchoConn struct {
	net.Conn
	id           string
	writeData    []byte
	didWriteOnce bool
}

func NewFuzzEchoConn(id string, conn net.Conn, writeData []byte) *fuzzEchoConn {
	return &fuzzEchoConn{conn, id, writeData, false}
}

// Read reads data regularly from Conn
func (self *fuzzEchoConn) Read(b []byte) (n int, err error) {
	n, err = self.Conn.Read(b)
	return
}

// Write sends self.clientData instead of the original byte slice Conn wanted to send
func (self *fuzzEchoConn) Write(b []byte) (n int, err error) {
	if self.didWriteOnce {
		n, err = self.Conn.Write(b)
		return
	}
	n, err = self.Conn.Write(self.writeData[:len(self.writeData)])
	self.didWriteOnce = true
	return
}
