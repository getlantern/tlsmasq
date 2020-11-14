package ptlshs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/getlantern/preconn"
	"github.com/getlantern/tlsutil"
)

// Conn is a network connection between two peers speaking the ptlshs protocol. Methods returning
// connection state data (TLSVersion, CipherSuite, etc.) block until the handshake is complete.
//
// Connections returned by listeners and dialers in this package will implement this interface.
// However, most users of this package can ignore this type.
type Conn interface {
	net.Conn

	// Handshake executes the ptlshs handshake protocol, if it has not yet been performed. Note
	// that, per the protocol, the connection will proxy all data until the completion signal. Thus,
	// if this connection comes from an active probe, this handshake function may not return until
	// the probe closes the connection on its end. As a result, this function should be treated as
	// one which may be long-running or never return.
	Handshake() error

	// TLSVersion is the TLS version negotiated during the proxied handshake.
	TLSVersion() uint16

	// CipherSuite is the cipher suite negotiated during the proxied handshake.
	CipherSuite() uint16

	// NextSeq increments and returns the connection's sequence number. The starting sequence number
	// is derived from the server random in the proxied handshake. Clients and servers will have the
	// same derived sequence numbers, so this can be used in cipher suites which use the sequence
	// number as a nonce.
	NextSeq() [8]byte

	// IV is an initialization vector. This is derived from the server random in the proxied handshake.
	// Dialers and listeners will have the same IV, so this can be used when needed in ciphers.
	IV() [16]byte
}

type connState struct {
	version, suite uint16

	seq [8]byte
	iv  [16]byte

	seqLock sync.Mutex
}

func (s *connState) nextSeq() [8]byte {
	s.seqLock.Lock()
	defer s.seqLock.Unlock()

	// Taken from crypto/tls.halfConn.incSeq.
	for i := 7; i >= 0; i-- {
		s.seq[i]++
		if s.seq[i] != 0 {
			return s.seq
		}
	}

	// Not allowed to let sequence number wrap.
	// Instead, must renegotiate before it does.
	// Not likely enough to bother.
	panic("ptlshs: sequence number wraparound")
}

type clientConn struct {
	// The underlying connection to the server. This is likely just a TCP connection.
	net.Conn

	cfg DialerConfig

	// One of the following is initialized after Handshake().
	state        *connState
	handshakeErr error

	shakeOnce         sync.Once
	handshakeComplete chan struct{}
}

// Client initializes a client-side connection.
func Client(toServer net.Conn, cfg DialerConfig) Conn {
	cfg = cfg.withDefaults()
	return &clientConn{toServer, cfg, nil, nil, sync.Once{}, make(chan struct{})}
}

func (c *clientConn) Read(b []byte) (n int, err error) {
	if err := c.Handshake(); err != nil {
		return 0, fmt.Errorf("handshake failed: %w", err)
	}
	return c.Conn.Read(b)
}

func (c *clientConn) Write(b []byte) (n int, err error) {
	if err := c.Handshake(); err != nil {
		return 0, fmt.Errorf("handshake failed: %w", err)
	}
	return c.Conn.Write(b)
}

// Handshake performs the ptlshs handshake protocol, if it has not yet been performed. Note that,
// per the protocol, the connection will proxy all data until the completion signal. Thus, if this
// connection comes from an active probe, this handshake function may not return until the probe
// closes the connection on its end. As a result, this function should be treated as one which may
// be long-running or never return.
func (c *clientConn) Handshake() error {
	c.shakeOnce.Do(func() {
		c.handshakeErr = c.handshake()
		close(c.handshakeComplete)
	})
	return c.handshakeErr
}

func (c *clientConn) handshake() error {
	var (
		serverRandom []byte
	)
	onClientRead := func(b []byte) error {
		if serverRandom != nil {
			return nil
		}
		serverHello, err := tlsutil.ParseServerHello(b)
		if err != nil {
			return fmt.Errorf("failed to parse server hello: %w", err)
		}
		serverRandom = serverHello.Random
		return nil
	}

	mitmConn := mitm(c.Conn, onClientRead, nil)
	hsResult, err := c.cfg.Handshaker.Handshake(mitmConn)
	if err != nil {
		return err
	}
	if serverRandom == nil {
		return fmt.Errorf("never saw server hello")
	}
	seq, iv, err := deriveSeqAndIV(serverRandom)
	if err != nil {
		return fmt.Errorf("failed to derive sequence and IV: %w", err)
	}
	tlsState, err := tlsutil.NewConnectionState(
		hsResult.Version, hsResult.CipherSuite, c.cfg.Secret, iv, seq)
	if err != nil {
		return fmt.Errorf("failed to read TLS connection state: %w", err)
	}
	signal, err := newCompletionSignal(c.cfg.NonceTTL)
	if err != nil {
		return fmt.Errorf("failed to create completion signal: %w", err)
	}
	_, err = tlsutil.WriteRecord(c.Conn, *signal, tlsState)
	if err != nil {
		return fmt.Errorf("failed to signal completion: %w", err)
	}
	// We're overwriting a concurrently accessed field here. However, this is not used until the
	// handshake is complete, and the handshake is executed in a sync.Once.
	c.state = &connState{hsResult.Version, hsResult.CipherSuite, seq, iv, sync.Mutex{}}
	return nil
}

func (c *clientConn) TLSVersion() uint16 {
	<-c.handshakeComplete
	if c.state == nil {
		return 0
	}
	return c.state.version
}

func (c *clientConn) CipherSuite() uint16 {
	<-c.handshakeComplete
	if c.state == nil {
		return 0
	}
	return c.state.suite
}

func (c *clientConn) NextSeq() [8]byte {
	<-c.handshakeComplete
	if c.state == nil {
		return [8]byte{}
	}
	return c.state.nextSeq()
}

func (c *clientConn) IV() [16]byte {
	<-c.handshakeComplete
	if c.state == nil {
		return [16]byte{}
	}
	return c.state.iv
}

type serverConn struct {
	// The underlying connection to the client. This is likely just a TCP connection.
	net.Conn

	cfg ListenerConfig

	nonceCache *nonceCache
	closeCache bool

	// One of the following is initialized after Handshake().
	state        *connState
	handshakeErr error

	shakeOnce         sync.Once
	handshakeComplete chan struct{}
}

// Server initializes a server-side connection.
func Server(toClient net.Conn, cfg ListenerConfig) Conn {
	cfg = cfg.withDefaults()
	nc := newNonceCache(cfg.NonceSweepInterval)
	return serverConnWithCache(toClient, cfg, nc, true)
}

// Ignores cfg.NonceSweepInterval.
func serverConnWithCache(toClient net.Conn, cfg ListenerConfig, cache *nonceCache, closeCache bool) Conn {
	return &serverConn{toClient, cfg, cache, closeCache, nil, nil, sync.Once{}, make(chan struct{})}
}

func (c *serverConn) Read(b []byte) (n int, err error) {
	if err := c.Handshake(); err != nil {
		return 0, fmt.Errorf("handshake failed: %w", err)
	}
	return c.Conn.Read(b)
}

func (c *serverConn) Write(b []byte) (n int, err error) {
	if err := c.Handshake(); err != nil {
		return 0, fmt.Errorf("handshake failed: %w", err)
	}
	return c.Conn.Write(b)
}

func (c *serverConn) Close() error {
	if c.closeCache {
		c.nonceCache.close()
	}
	return c.Conn.Close()
}

// Handshake performs the ptlshs handshake protocol, if it has not yet been performed. Note that,
// per the protocol, the connection will proxy all data until the completion signal. Thus, if this
// connection comes from an active probe, this handshake function may not return until the probe
// closes the connection on its end. As a result, this function should be treated as one which may
// be long-running or never return.
func (c *serverConn) Handshake() error {
	c.shakeOnce.Do(func() {
		c.handshakeErr = c.handshake()
		close(c.handshakeComplete)
	})
	return c.handshakeErr
}

func (c *serverConn) handshake() error {
	origin, err := c.cfg.DialOrigin()
	if err != nil {
		return fmt.Errorf("failed to dial origin server: %w", err)
	}
	defer origin.Close()

	// Read and copy ClientHello.
	b, err := readClientHello(c.Conn, listenerReadBufferSize)
	if err != nil && !errors.As(err, new(networkError)) {
		// Client sent something other than ClientHello. Proxy everything to match origin behavior.
		proxyUntilClose(preconn.Wrap(c.Conn, b), origin)
		return fmt.Errorf("did not receive ClientHello: %w", err)
	}
	if err != nil {
		return fmt.Errorf("failed to read ClientHello: %w", err)
	}
	_, err = makeNetworkCall(origin.Write, b)
	if err != nil {
		return fmt.Errorf("failed to write to origin: %w", err)
	}

	// Read, parse, and copy ServerHello.
	b, c.state, err = readServerHello(origin, listenerReadBufferSize)
	if err != nil && !errors.As(err, new(networkError)) {
		// Origin sent something other than ServerHello. Proxy everything to match origin behavior.
		proxyUntilClose(c.Conn, preconn.Wrap(origin, b))
		return fmt.Errorf("did not receieve ServerHello: %w", err)
	}
	if err != nil {
		return fmt.Errorf("failed to parse ServerHello: %w", err)
	}
	tlsState, err := tlsutil.NewConnectionState(
		c.state.version, c.state.suite, c.cfg.Secret, c.state.iv, c.state.seq)
	if err != nil {
		return fmt.Errorf("failed to init conn state based on hello info: %w", err)
	}
	_, err = makeNetworkCall(c.Conn.Write, b)
	if err != nil {
		return fmt.Errorf("failed to write to client: %w", err)
	}

	// Wait until we've received the completion signal.
	err = c.watchForCompletion(listenerReadBufferSize, *tlsState, origin)
	if err != nil {
		return fmt.Errorf("failed while watching for completion signal: %w", err)
	}
	return nil
}

// Copies data between the client (c.Conn) and the origin server, watching client messages for the
// completion signal. If the signal is received, the origin connection will be closed.
func (c *serverConn) watchForCompletion(bufferSize int, tlsState tlsutil.ConnectionState, toOrigin net.Conn) error {
	// Note: we assume here that the completion signal will arrive in a single read. This is not
	// guaranteed, but it is highly likely. Also the penalty is minor - the client can just redial.
	foundSignal := false
	onClientRead := func(b []byte) error {
		ok, preSignal, postSignal := c.checkForSignal(b, tlsState)
		if ok {
			foundSignal = true

			// We stop both copy routines by closing the connection to the origin server. We first
			// attempt to flush any unprocessed data.
			toOrigin.Write(preSignal)
			toOrigin.Close()

			// We also need to ensure the unprocessed post-signal data is not lost. We prepend it to
			// the client connection. Access to c.Conn is single-threaded until the handshake is
			// complete, so this is safe to do without synchronization.
			c.Conn = preconn.Wrap(c.Conn, postSignal)
		}
		return nil
	}

	var (
		eg         = new(errgroup.Group)
		client     = netReadWriter{mitm(c.Conn, onClientRead, nil)}
		origin     = netReadWriter{toOrigin}
		buf1, buf2 = make([]byte, bufferSize), make([]byte, bufferSize)
	)
	eg.Go(func() error { _, err := io.CopyBuffer(client, origin, buf1); return err })
	eg.Go(func() error { _, err := io.CopyBuffer(origin, client, buf2); return err })
	err := eg.Wait()
	switch {
	case foundSignal:
		return nil
	case err != nil:
		return err
	default:
		// If the copy routines returned before the signal, it means we hit EOF.
		return io.EOF
	}
}

// preSignal and postSignal hold data from b from before and after the signal. These will be non-nil
// iff the signal was found.
func (c *serverConn) checkForSignal(b []byte, cs tlsutil.ConnectionState) (found bool, preSignal, postSignal []byte) {
	tryToSend := func(errChan chan<- error, err error) {
		select {
		case errChan <- err:
		default:
		}
	}

	r := bytes.NewReader(b)
	unprocessedBuf := new(bufferList)
	for r.Len() > 0 || unprocessedBuf.len() > 0 {
		signalStart := len(b) - r.Len() - unprocessedBuf.len()
		record, unprocessed, err := tlsutil.ReadRecord(io.MultiReader(unprocessedBuf, r), &cs)
		if unprocessed != nil {
			unprocessedBuf.prepend(unprocessed)
		}
		if err != nil {
			// If we failed to decrypt, then this must not have been the signal.
			continue
		}

		signal, err := parseCompletionSignal(record)
		if err != nil {
			// Again, this must not have been the signal.
			tryToSend(c.cfg.NonFatalErrors, fmt.Errorf("decrypted record, but failed to parse signal: %w", err))
			continue
		}
		if !c.nonceCache.isValid(signal.getNonce()) {
			// Looks like a replay. Continue so that the connection will just get proxied.
			tryToSend(c.cfg.NonFatalErrors, errors.New("received bad nonce; likely a signal replay"))
			continue
		}
		signalEnd := len(b) - r.Len() - unprocessedBuf.len()
		return true, b[:signalStart], b[signalEnd:]
	}
	return false, nil, nil
}

func (c *serverConn) TLSVersion() uint16 {
	<-c.handshakeComplete
	if c.state == nil {
		return 0
	}
	return c.state.version
}

func (c *serverConn) CipherSuite() uint16 {
	<-c.handshakeComplete
	if c.state == nil {
		return 0
	}
	return c.state.suite
}

func (c *serverConn) NextSeq() [8]byte {
	<-c.handshakeComplete
	if c.state == nil {
		return [8]byte{}
	}
	return c.state.nextSeq()
}

func (c *serverConn) IV() [16]byte {
	<-c.handshakeComplete
	if c.state == nil {
		return [16]byte{}
	}
	return c.state.iv
}

// Continuously reads off of conn until one of the following:
// 	- The bytes read constitute a valid TLS ClientHello.
//	- The bytes read could not possibly constitute a valid TLS ClientHello.
//	- A non-temporary network error is encountered.
// Whatever was read is always returned.
func readClientHello(conn net.Conn, bufferSize int) ([]byte, error) {
	buf := make([]byte, bufferSize)
	read := new(bytes.Buffer)
	for {
		n, err := makeNetworkCall(conn.Read, buf)
		if err != nil {
			return read.Bytes(), networkError{err}
		}
		// Note: bytes.Buffer.Write does not return errors.
		read.Write(buf[:n])
		_, err = tlsutil.ValidateClientHello(read.Bytes())
		if err == nil {
			return read.Bytes(), nil
		}
		if !errors.Is(err, io.EOF) {
			return read.Bytes(), err
		}
	}
}

// Continuously reads off of conn until one of the following:
// 	- The bytes read constitute a valid TLS ServerHello.
//	- The bytes read could not possibly constitute a valid TLS ServerHello.
//	- A non-temporary network error is encountered.
// Whatever was read is always returned. When a valid ServerHello is read, it is parsed and used to
// create a connection state.
func readServerHello(conn net.Conn, bufferSize int) ([]byte, *connState, error) {
	buf := make([]byte, bufferSize)
	read := new(bytes.Buffer)
	for {
		n, err := makeNetworkCall(conn.Read, buf)
		if err != nil {
			return read.Bytes(), nil, networkError{err}
		}
		// Note: bytes.Buffer.Write does not return errors.
		read.Write(buf[:n])
		serverHello, err := tlsutil.ParseServerHello(read.Bytes())
		if err == nil {
			version, suite := serverHello.Version, serverHello.Suite
			seq, iv, err := deriveSeqAndIV(serverHello.Random)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to derive sequence and IV: %w", err)
			}
			return read.Bytes(), &connState{version, suite, seq, iv, sync.Mutex{}}, nil
		}
		if !errors.Is(err, io.EOF) {
			return read.Bytes(), nil, err
		}
	}
}

func deriveSeqAndIV(serverRandom []byte) (seq [8]byte, iv [16]byte, err error) {
	// https://tools.ietf.org/html/rfc5246#section-6.1
	// https://tools.ietf.org/html/rfc8446#section-4.1.3
	const serverRandomSize = 32

	if len(serverRandom) != serverRandomSize {
		return seq, iv, fmt.Errorf(
			"expected larger server random (should be 32 bytes, got %d)", len(serverRandom))
	}
	copy(seq[:], serverRandom)
	copy(iv[:], serverRandom[len(seq):])
	return seq, iv, nil
}

type mitmConn struct {
	net.Conn

	// Any errors returned by onRead or onWrite will result in an error returned by Read or Write
	// respectively. Though these callback errors may not reflect actual read or write errors,
	// treating them as such allows for simpler usage of mitmConn.
	onRead, onWrite func([]byte) error
}

// Sets up a MITM'd connection. Callbacks will be invoked synchronously. Either callback may be nil.
func mitm(conn net.Conn, onRead, onWrite func([]byte) error) mitmConn {
	if onRead == nil {
		onRead = func(_ []byte) error { return nil }
	}
	if onWrite == nil {
		onWrite = func(_ []byte) error { return nil }
	}
	return mitmConn{conn, onRead, onWrite}
}

func (c mitmConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		if err := c.onRead(b[:n]); err != nil {
			return n, err
		}
	}
	return
}

func (c mitmConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		if err := c.onWrite(b[:n]); err != nil {
			return n, err
		}
	}
	return
}

// Wraps the input io.ReadWriter such that Reads and Writes will be retried on temporary errors.
type netReadWriter struct {
	rw io.ReadWriter
}

func (nrw netReadWriter) Read(b []byte) (n int, err error) {
	return makeNetworkCall(nrw.rw.Read, b)
}

func (nrw netReadWriter) Write(b []byte) (n int, err error) {
	return makeNetworkCall(nrw.rw.Write, b)
}

// Make a network call, ignoring temporary errors.
func makeNetworkCall(networkFn func([]byte) (int, error), buf []byte) (int, error) {
	for {
		n, err := networkFn(buf)
		if err == nil {
			return n, nil
		}
		if netErr, ok := err.(net.Error); !ok || !netErr.Temporary() {
			return n, err
		}
	}
}

type networkError struct {
	cause error
}

func (err networkError) Error() string {
	return err.cause.Error()
}

func proxyUntilClose(a, b net.Conn) {
	wg := new(sync.WaitGroup)
	wg.Add(2)
	go func() { io.Copy(a, b); wg.Done() }()
	go func() { io.Copy(b, a); wg.Done() }()
	wg.Wait()
}
