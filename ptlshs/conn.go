package ptlshs

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/getlantern/preconn"
	"github.com/getlantern/tlsmasq/internal/reptls"
	"golang.org/x/sync/errgroup"
)

// Conn is a network connection between two peers speaking the ptlshs protocol. Methods returning
// connection state data (TLSVersion, CipherSuite, etc.) block until the handshake is complete.
//
// Connections returned by listeners and dialers in this package will implement this interface.
type Conn interface {
	net.Conn

	// Underlying connection to the peer.
	Underlying() net.Conn

	// Handshake performs the ptlshs handshake protocol, if it has not yet been performed. Note
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

	tlsCfg    *tls.Config
	preshared Secret
	nonceTTL  time.Duration

	// One of the following is initialized after Handshake().
	state        *connState
	handshakeErr error

	shakeOnce         sync.Once
	handshakeComplete chan struct{}
}

// Client initializes a client-side connection.
func Client(toServer net.Conn, tlsCfg *tls.Config, preshared Secret, nonceTTL time.Duration) Conn {
	return &clientConn{toServer, tlsCfg, preshared, nonceTTL, nil, nil, sync.Once{}, make(chan struct{})}
}

func (c *clientConn) Underlying() net.Conn {
	return c.Conn
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
	<-c.handshakeComplete
	return c.handshakeErr
}

func (c *clientConn) handshake() error {
	var (
		serverRandom    []byte
		serverRandomErr error
	)
	onClientRead := func(b []byte) {
		if serverRandom != nil || serverRandomErr != nil {
			return
		}
		serverHello, err := reptls.ParseServerHello(b)
		if err != nil {
			serverRandomErr = err
			return
		}
		serverRandom = serverHello.Random
	}

	mitmConn := mitm(c.Conn, onClientRead, nil)
	tlsConn := tls.Client(mitmConn, c.tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	if serverRandomErr != nil {
		return fmt.Errorf("failed to parse server hello: %w", serverRandomErr)
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
	signal, err := newCompletionSignal(c.nonceTTL)
	if err != nil {
		return fmt.Errorf("failed to create completion signal: %w", err)
	}
	_, err = reptls.WriteRecord(c.Conn, signal[:], tlsState, c.preshared, iv)
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

	toProxied      net.Conn
	preshared      Secret
	isValidNonce   func(Nonce) bool
	nonFatalErrors chan<- error // TODO: evaluate whether this is still necessary

	// One of the following is initialized after Handshake().
	state        *connState
	handshakeErr error

	shakeOnce         sync.Once
	handshakeComplete chan struct{}
}

// Server initializes a new server-side connection.
func Server(toClient, toProxied net.Conn,
	preshared Secret, isValidNonce func(Nonce) bool, nonFatalErrors chan<- error) Conn {

	return &serverConn{
		toClient, toProxied, preshared, isValidNonce, nonFatalErrors, nil, nil, sync.Once{}, make(chan struct{}),
	}
}

func (c *serverConn) Underlying() net.Conn {
	return c.Conn
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
	<-c.handshakeComplete
	return c.handshakeErr
}

func (c *serverConn) handshake() error {
	// TODO: see if we can distinguish proxying and return a special error

	ctx, stop := context.WithCancel(context.Background())
	errGroup, ctx := errgroup.WithContext(ctx)
	defer stop()

	tryToSend := func(errChan chan<- error, err error) {
		select {
		case errChan <- err:
		default:
		}
	}

	var (
		tlsState             *reptls.ConnState
		iv                   [16]byte
		serverHelloParsed    = make(chan struct{})
		errOnReadFromProxied = make(chan error, 1)
		firstReadFromProxied = true

		// Data read off the connection after the completion signal. We assume this is data intended
		// for the real server.
		postSignalData = new(bytes.Buffer)

		// Data read off the connection before the completion signal and which has not yet been
		// written to the proxied server. Only used once we have receieved the signal.
		preSignalData = new(bytes.Buffer)

		// Saved to be passed back in the returned connection.
		version, suite uint16
		seq            [8]byte
	)
	onReadFromProxied := func(b []byte) {
		if !firstReadFromProxied {
			return
		}
		firstReadFromProxied = false
		serverHello, err := reptls.ParseServerHello(b)
		if err != nil {
			tryToSend(errOnReadFromProxied, fmt.Errorf("failed to parse server hello: %w", err))
			return
		}
		version, suite = serverHello.Version, serverHello.Suite
		seq, iv, err = deriveSeqAndIV(serverHello.Random)
		if err != nil {
			tryToSend(errOnReadFromProxied, fmt.Errorf("failed to derive sequence and IV: %w", err))
			return
		}
		cs, err := reptls.NewConnState(serverHello.Version, serverHello.Suite, seq)
		if err != nil {
			tryToSend(errOnReadFromProxied, fmt.Errorf("failed to init conn state based on hello info: %w", err))
			return
		}
		tlsState = cs
		close(serverHelloParsed)
	}
	onReadFromClient := func(b []byte) {
		select {
		case <-serverHelloParsed:
			results := reptls.ReadRecords(bytes.NewReader(b), tlsState, c.preshared, iv)
			for i, result := range results {
				if result.Err != nil {
					// Only act if we successfully decrypted. Otherwise, assume this wasn't the signal.
					continue
				}
				signal, err := parseCompletionSignal(result.Data)
				if err != nil {
					// Again, only act if this looks like the signal.
					tryToSend(c.nonFatalErrors, fmt.Errorf("decrypted record, but failed to parse signal: %w", err))
					continue
				}
				if !c.isValidNonce(signal.getNonce()) {
					// Looks like a replay. Continue so that the connection will just get proxied.
					tryToSend(c.nonFatalErrors, errors.New("received bad nonce; likely a signal replay"))
					continue
				}
				postSignalData.Write(b[result.N:])
				if i > 0 {
					preSignalData.Write(b[:results[i-1].N])
				}
				stop()
			}
		case <-ctx.Done():
			// At this point, we just need to hold on to anything read from the client.
			postSignalData.Write(b)
			return
		default:
			return
		}
	}
	errGroup.Go(func() error {
		// TODO: think about allowing mitm callbacks to return errors
		select {
		case err := <-errOnReadFromProxied:
			return err
		case <-ctx.Done():
			return nil
		}
	})
	errGroup.Go(func() error {
		<-ctx.Done()
		// Write the remaining data, but don't worry about whether it makes it.
		c.toProxied.Write(preSignalData.Bytes())
		c.toProxied.Close()
		return nil
	})

	mitmToProxied := mitm(c.toProxied, onReadFromProxied, nil)
	mitmToClient := mitm(c.Conn, onReadFromClient, nil)
	errGroup.Go(func() error {
		return netCopy(
			ctx,
			namedConn{mitmToProxied, "proxied server"},
			namedConn{mitmToClient, "client"},
			listenerReadBufferSize,
		)
	})
	errGroup.Go(func() error {
		return netCopy(
			ctx,
			namedConn{mitmToClient, "client"},
			namedConn{mitmToProxied, "proxied server"},
			listenerReadBufferSize,
		)
	})
	errGroup.Go(func() error {
		<-ctx.Done()
		select {
		case <-mitmToClient.closedByPeer:
			mitmToProxied.Close()
		case <-mitmToProxied.closedByPeer:
			mitmToClient.Close()
		default:
		}
		return nil
	})
	if err := errGroup.Wait(); err != nil {
		return err
	}
	// We're overwriting concurrently accessed fields here. However, these are not used until the
	// handshake is complete, and the handshake is executed in a sync.Once.
	c.Conn = preconn.Wrap(c.Conn, postSignalData.Bytes())
	c.state = &connState{version, suite, seq, iv, sync.Mutex{}}
	return nil
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
