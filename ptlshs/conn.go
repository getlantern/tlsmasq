package ptlshs

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/getlantern/preconn"
	"github.com/getlantern/tlsmasq/internal/reptls"
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
		serverHello, err := reptls.ParseServerHello(b)
		if err != nil {
			return fmt.Errorf("failed to parse server hello: %w", err)
		}
		serverRandom = serverHello.Random
		return nil
	}

	mitmConn := mitm(c.Conn, onClientRead, nil)
	tlsConn := tls.Client(mitmConn, c.cfg.TLSConfig)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	if serverRandom == nil {
		return fmt.Errorf("never saw server hello")
	}
	seq, iv, err := deriveSeqAndIV(serverRandom)
	if err != nil {
		return fmt.Errorf("failed to derive sequence and IV: %w", err)
	}
	tlsState, err := reptls.GetState(tlsConn, seq)
	if err != nil {
		return fmt.Errorf("failed to read TLS connection state: %w", err)
	}
	signal, err := newCompletionSignal(c.cfg.NonceTTL)
	if err != nil {
		return fmt.Errorf("failed to create completion signal: %w", err)
	}
	_, err = reptls.WriteRecord(c.Conn, signal[:], tlsState, c.cfg.Secret, iv)
	if err != nil {
		return fmt.Errorf("failed to signal completion: %w", err)
	}
	// We're overwriting a concurrently accessed field here. However, this is not used until the
	// handshake is complete, and the handshake is executed in a sync.Once.
	cs := tlsConn.ConnectionState()
	c.state = &connState{cs.Version, cs.CipherSuite, seq, iv, sync.Mutex{}}
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
	toProxied, err := c.cfg.DialProxied()
	if err != nil {
		return fmt.Errorf("failed to dial proxied server: %w", err)
	}
	defer toProxied.Close()

	buf := make([]byte, listenerReadBufferSize)

	// Read and copy ClientHello.
	clientHello, err := readClientHello(c.Conn, buf)
	if err != nil {
		return fmt.Errorf("failed to read ClientHello: %w", err)
	}
	_, err = makeNetworkCall(toProxied.Write, clientHello)
	if err != nil {
		return fmt.Errorf("failed to write to proxied: %w", err)
	}

	// Read, parse, and copy ServerHello.
	var serverHello []byte
	serverHello, c.state, err = readServerHello(toProxied, buf)
	if err != nil {
		return fmt.Errorf("failed to parse ServerHello: %w", err)
	}
	tlsState, err := reptls.NewConnState(c.state.version, c.state.suite, c.state.seq)
	if err != nil {
		return fmt.Errorf("failed to init conn state based on hello info: %w", err)
	}
	_, err = makeNetworkCall(c.Conn.Write, serverHello)
	if err != nil {
		return fmt.Errorf("failed to write to client: %w", err)
	}

	// Wait until we've received the completion signal.
	err = c.watchForCompletionSignal(listenerReadBufferSize, *tlsState, toProxied)
	if err != nil {
		return fmt.Errorf("failed while watching for completion signal: %w", err)
	}
	return nil
}

// Copies data between the client (c.Conn) and the proxied server (c.toProxied), watching client
// messages for the completion signal. If the signal is received, the connection toProxied will be
// closed.
func (c *serverConn) watchForCompletionSignal(bufferSize int, tlsState reptls.ConnState, toProxied net.Conn) error {
	type namedConn struct {
		net.Conn
		name string
	}

	var (
		groupCtx, stop = context.WithCancel(context.Background())
		group, ctx     = errgroup.WithContext(groupCtx)

		client  = namedConn{c.Conn, "client"}
		proxied = namedConn{toProxied, "proxied"}
	)

	// Note: we assume here that the completion signal will arrive in a single read. As it is sent
	// by clients we control and presently only 100 bytes, that should be a fairly safe assumption.

	copyFn := func(dst, src namedConn, onRead func([]byte)) func() error {
		return func() error {
			buf := make([]byte, bufferSize)
			for {
				n, err := makeNetworkCall(src.Read, buf)
				onRead(buf[:n])
				if isDone(ctx) {
					return nil
				}
				if err != nil {
					return fmt.Errorf("failed to read from %s: %w", src.name, err)
				}
				_, err = makeNetworkCall(dst.Write, buf[:n])
				if isDone(ctx) {
					return nil
				}
				if err != nil {
					return fmt.Errorf("failed to write to %s: %w", dst.name, err)
				}
			}
		}
	}
	onClientRead := func(b []byte) {
		ok, preSignal, postSignal := c.checkForSignal(b, tlsState)
		if ok {
			// Cancel the context to indicate to both routines that work is done.
			stop()

			// The other routine will be blocked reading from the proxied server. We unblock it by
			// closing the connection to the proxied server, after flushing the unprocessed data.
			toProxied.Write(preSignal)
			toProxied.Close()

			// We also need to ensure the unprocessed post-signal data is not lost. We prepend it to
			// the client connection. Access to c.Conn is single-threaded until the handshake is
			// complete, so this is safe to do without synchronization.
			c.Conn = preconn.Wrap(c.Conn, postSignal)
		}
	}

	// Note that the following two routines will continue to proxy data between the client and the
	// proxied server until (1) the completion signal is received or (2) a non-temporary error
	// occurs. Case 2 covers scenarios in which one peer closes the connection on their end.
	group.Go(copyFn(client, proxied, func(_ []byte) {}))
	group.Go(copyFn(proxied, client, onClientRead))
	return group.Wait()
}

// preSignal and postSignal hold data from b from before and after the signal. These will be non-nil
// iff the signal was found.
func (c *serverConn) checkForSignal(b []byte, cs reptls.ConnState) (found bool, preSignal, postSignal []byte) {
	tryToSend := func(errChan chan<- error, err error) {
		select {
		case errChan <- err:
		default:
		}
	}

	preSignalBuf := new(bytes.Buffer)
	results := reptls.ReadRecords(bytes.NewReader(b), &cs, c.cfg.Secret, c.state.iv)
	for i, result := range results {
		if result.Err != nil {
			// Only act if we successfully decrypted. Otherwise, assume this wasn't the signal.
			continue
		}
		signal, err := parseCompletionSignal(result.Data)
		if err != nil {
			// Again, only act if this looks like the signal.
			tryToSend(c.cfg.NonFatalErrors, fmt.Errorf("decrypted record, but failed to parse signal: %w", err))
			continue
		}
		if !c.nonceCache.isValid(signal.getNonce()) {
			// Looks like a replay. Continue so that the connection will just get proxied.
			tryToSend(c.cfg.NonFatalErrors, errors.New("received bad nonce; likely a signal replay"))
			continue
		}
		postSignal = b[result.N:]
		if i > 0 {
			preSignalBuf.Write(b[:results[i-1].N])
		}
		return true, preSignalBuf.Bytes(), postSignal
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

// Continuously reads off of conn until the bytes read constitute a valid TLS ClientHello. Does not
// return until (1) a ClientHello has been received or (2) conn.Read returns a non-temporary error.
func readClientHello(conn net.Conn, buf []byte) ([]byte, error) {
	read := new(bytes.Buffer)
	for {
		n, err := makeNetworkCall(conn.Read, buf)
		if err != nil {
			return nil, err
		}
		// Note: bytes.Buffer.Write does not return errors.
		read.Write(buf[:n])
		if err := reptls.ValidateClientHello(read.Bytes()); err == nil {
			return read.Bytes(), nil
		}
	}
}

// Continuously reads off of conn until the bytes read constitute a valid TLS ServerHello. Does not
// return until (1) a ServerHello has been receieved or (2) conn.Read returns a non-temporary error.
// Once the ServerHello is receieved, it is parsed and used to create a connection state.
func readServerHello(conn net.Conn, buf []byte) ([]byte, *connState, error) {
	read := new(bytes.Buffer)
	for {
		n, err := makeNetworkCall(conn.Read, buf)
		if err != nil {
			return nil, nil, err
		}
		// Note: bytes.Buffer.Write does not return errors.
		read.Write(buf[:n])
		serverHello, err := reptls.ParseServerHello(read.Bytes())
		if err == nil {
			version, suite := serverHello.Version, serverHello.Suite
			seq, iv, err := deriveSeqAndIV(serverHello.Random)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to derive sequence and IV: %w", err)
			}
			return read.Bytes(), &connState{version, suite, seq, iv, sync.Mutex{}}, nil
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

func isDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
