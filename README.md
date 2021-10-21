# TLS Masquerade

A server which masquerades as a different TLS server. For example, the server
may masquerade as a microsoft.com server, depsite not actually being run by
Microsoft.

Clients properly configured with the masquerade protocol can connect and speak
to the true server, but passive observers will see connections which look like
connections to microsoft.com. Similarly, active probes will find that the
server behaves like a microsoft.com server.

# Overview

There are three components in tlsmasq protocol: the tlsmasq client, the tlsmasq server and the origin (which may belong to a 3rd party):

    client <-> server <-> origin

1. `client` completes a TLS handshake with `origin`, with `server` acting as a simple proxy.
2. Upon completion of the handshake, `client` signals to `server` that it would like to progress to a full tlsmasq connection. This is done via a TLS record encrypted using a secret shared out-of-band.
3. The TLS session negotiated between `client` and `origin` is hijacked: a second TLS handshake is performed between `client` and `server`. All records in this second handshake are wrapped in records made to look like part of the `client-origin` session.
4. Once the `client-server` handshake is complete, the `client-server` connection operates as a normal TLS connection; the records are no longer wrapped.

For more details, consult the code =)

# Usage

For using tlsmasq as a library, consult the godoc. To see a simple, fully-encapsulated example, look to tlsmasq/TestListenAndDial.

# [Fuzzing](#fuzzing)

We fuzz-test against ClientHellos. See tlsmasq/fuzz/fuzz.go.
