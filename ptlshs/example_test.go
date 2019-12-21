package ptlshs

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// Example demonstrates proxied TLS handshakes.
func Example() {
	var (
		clientMsg, serverMsg = "hello from the client", "hello from the server"
		successfulHandshakes = make(chan struct{}, 1)
	)

	// Start a TLS server to which we will proxy the handshake.
	tlsServerAddr, err := startTLSServer(successfulHandshakes)
	if err != nil {
		panic(err)
	}

	secret := new(Secret)
	if _, err := rand.Read(secret[:]); err != nil {
		panic(err)
	}

	// Start a TCP server which begins with our proxied TLS handshake.
	dialProxied := func() (net.Conn, error) { return net.Dial("tcp", tlsServerAddr) }
	listenerOpts := ListenerOpts{DialProxied: dialProxied, Secret: *secret}
	l, err := Listen("tcp", "localhost:0", listenerOpts)
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil && strings.Contains(err.Error(), "use of closed network connection") {
				// This is an unexported error indicating that the connection is closed.
				// See https://golang.org/pkg/internal/poll/#pkg-variables
				return
			}
			if err != nil {
				panic(err)
			}
			go func(c net.Conn) {
				defer c.Close()

				b := make([]byte, len(clientMsg))
				if _, err := c.Read(b); err != nil {
					panic(err)
				}
				fmt.Println("received message from the client:", string(b))

				if _, err := c.Write([]byte(serverMsg)); err != nil {
					panic(err)
				}
			}(conn)
		}
	}()

	// Dial with a ptlshs client.
	dialerOpts := DialerOpts{TLSConfig: &tls.Config{InsecureSkipVerify: true}, Secret: *secret}
	conn, err := Dial("tcp", l.Addr().String(), dialerOpts)
	if err != nil {
		panic(err)
	}

	// We can use the connection like any other now.
	if _, err := conn.Write([]byte(clientMsg)); err != nil {
		panic(err)
	}
	b := make([]byte, len(serverMsg))
	if _, err := conn.Read(b); err != nil {
		panic(err)
	}
	fmt.Println("received message from the server:", string(b))

	// Make sure there was actually a handshake with the TLS server. This is not necessary, we're
	// just demonstrating that the handshake actually occurred.
	select {
	case <-successfulHandshakes:
	case <-time.After(100 * time.Millisecond):
		panic("no handshake with TLS server")
	}

	// Try connecting to the server with an unsuspecting HTTPS client. The connection will simply be
	// proxied to the TLS server.
	httpClient := http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := httpClient.Get("https://" + l.Addr().String())
	if err != nil {
		panic(err)
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println("HTTPS client got:", string(respBody))

	// Output:
	// received message from the client: hello from the client
	// received message from the server: hello from the server
	// HTTPS client got: Hello from the TLS server
}

// Each successful handshake will result in a signal sent on the input channel.
func startTLSServer(successfulHandshakes chan<- struct{}) (addr string, err error) {
	tlsListener, err := tls.Listen("tcp", "localhost:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		return "", err
	}
	loggingListener := loggingTLSListener{tlsListener, successfulHandshakes}
	go func() {
		log.Fatal(http.Serve(loggingListener, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			fmt.Fprint(w, "Hello from the TLS server")
		})))
	}()
	return tlsListener.Addr().String(), nil
}

type loggingTLSListener struct {
	net.Listener
	handshakes chan<- struct{}
}

func (l loggingTLSListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if err := conn.(*tls.Conn).Handshake(); err != nil {
		return nil, fmt.Errorf("handshake failed: %w", err)
	}
	l.handshakes <- struct{}{}
	return conn, nil
}

var (
	certPem = []byte(`-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`)
	keyPem = []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAoGCCqGSM49
AwEHoUQDQgAEPR3tU2Fta9ktY+6P9G0cWO+0kETA6SFs38GecTyudlHz6xvCdz8q
EKTcWGekdmdDPsHloRNtsiCa697B2O9IFA==
-----END EC PRIVATE KEY-----`)

	cert tls.Certificate
)

func init() {
	var err error
	cert, err = tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		panic(err)
	}
}
