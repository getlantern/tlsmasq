# TLS Masquerade

A server which masquerades as a different TLS server. For example, the server
may masquerade as a microsoft.com server, depsite not actually being run by
Microsoft.

Clients properly configured with the masquerade protocol can connect and speak
to the true server, but passive observers will see connections which look like
connections to microsoft.com. Similarly, active probes will find that the
server behaves like a microsoft.com server.

# Overview

There are three components in tlsmasq protocol: the client, the tlsmasq server and the origin:

    client <-> tlsmasq_server <-> origin_server

1. `client` would establish a connection with `tlsmasq_server`
  - Technically, this means it will finish a modified version of the TLS
    handshake. It's modified in order to trick active probes. Let's call this
    modified handshake the `tlsmasq_protocol`.
2. In turn, `tlsmasq_server` would establish a proper TLS handshake with `origin_server`
3. After a successful connection, all `client` communication will resume with
  `tlsmasq_server` as normal
4. If an active probe tries to connect as the `client` (by replaying the
  packets, or morphing it slightly), `tlsmasq_server` will act and respond just
  like `origin_server`, effectively "masquerading" as `origin_server` and
  hiding itself.

# Usage

For using tlsmasq as a library, see `tlsmasq_test.go:TestListenAndDial`. There's also a similiar test in `ptlshs/example_test.go`

For running the tests and the fuzzer, see the comments on each makefile target, or install [rocky/remake](https://github.com/rocky/remake) and run `remake --tasks`.

# [On Fuzzing](#fuzzing)

Fuzzing is achieved here by replaying mutated versions of pre-generated ClientHellos multiple times until a crash is observed. This is basically mutating step 1 in the `Overview` section above. Mutations in this point are echoed across the entire pipeline.

We're using [go-fuzz](https://github.com/dvyukov/go-fuzz) for mutating the input. The initial input corpus is generated through `make generate-fuzz-input`. This target runs `TestGenerateClientHellos` function in `fuzzutil/fuzzutil_test.go`, which acts as a standalone program that runs various TLS configurations and captures their ClientHellos and dumps them in a format the fuzzer can understand.

To start fuzzing:

- Either generate fuzz input, or use the ones already committed to the project
  - Generate fuzz-input by going into `fuzzutil/fuzzutil_test.go:TestGenerateClientHellos` function and modifying the TLS configurations there however you like
  - Then run `make generate-fuzz-input`. This'll place your generated ClientHellos and TLS configurations in `fuzz_workdir/annotated_corpus`
- Run `make run-fuzz`
  - This'll install `go-fuzz`, transfer the fuzz corpus to the correct location and run the fuzzer
  - `go-fuzz` is configured so that only application-level bugs should cause a panic, which means any crash is very much relevant.

## Fuzzing Internals

Internally, here's how the `tlsmasq_protocol` accommodates fuzzing:

- `fuzz.go:Fuzz()` function takes a mutated input from the corpus located in `fuzz_workdir/annotated_corpus`
  - Each input represents **one** ClientHello packet and the [`tls.Config`](https://pkg.go.dev/crypto/tls#Config) properties it was made with
    - Currently, **only** the random number seed is saved. See this [limitation](#tls-config-limitation).
  - This input must have this format: `nonce | key | AES_encrypted(tls_config) | SEPARATOR | clientHelloData`
    - Where `|` is a concatenation
    - `nonce` and `key` are the AES-GCM-128 nonce and key for `AES_encrypted(tls_config)`
    - `AES_encrypted(tls_config)` is the ciphertext result of an AES-GCM-128 encryption over the tls_config bytes
      - `tls_config` is encrypted as an integrity check to make sure `go-fuzz` does **not** mutate `tls_config`, but **only** mutates `clientHelloData`. Mutations to the `tls.Config` will most probably be sporadic and won't represent a real-life scenario. In the future, when `tls_config` [contains more data](#tls-config-limitation), it would be wise to think about mutating it with something like [google/gofuzz](https://github.com/google/gofuzz), which specializes in mutating structures.
    - `tls_config` of the TLS client the ClientHello originated from
    - `SEPARATOR` is just a known string to separate the input. It's located in `fuzzutil/encryption.go:SEPARATOR`
    - And `clientHelloData` is the bytes of the input ClientHello
  - `fuzz.go:Fuzz()` parses the mutated input and runs a test similar to `tlsmasq_test.go:TestListenAndDial()`:
    - Creates a `client`, `tlsmasq_server`, and `origin_server`
    - Initialize the state of `client` to match that of the input `tls_config`
    - Have `client` communicate with `tlsmasq_origin` as it normally should do
      - `client` uses `fuzzutil/fuzzechoconn.go:FuzzEchoConn` to replace `client`'s ClientHello with the mutated `clientHelloData` we got from `go-fuzz`. This is where the fuzzing actually happens. `FuzzEchoConn` only modifies the ClientHello; the rest of the communication remains intact.

## Limitations

### ClientHello Mutations
Only the ClientHello is mutated: all other client communication remains the same (i.e., cipher spec changes, application data, etc.).

While the initial ClientHello is most important part, we should assume that an active probe is capable of manipulating packets **after** the ClientHello as well. This should be addressed in the future.

### [Tls Configurations](#tls-config-limitation)
Currently, **only the random number seed** of the TLS configuration is saved, not anything else. It's very hard to 'serialize' `tls.Config` in Go since it contains mutexes and structs that have private (read: unexported) fields, which makes serializers like `encoding/gob` yield `gob: type sync.Mutex has no exported fields` errors.

On the other hand, `tls.Config` is not notoriously big and can be serialized to a protobuf or JSON in `fuzzutil/fuzzutil_test.go:TestGenerateClientHellos`, which later can be read by `fuzz.go:Fuzz()` (and `fuzzutil/fuzzutil_test.go:TestFuzz` for testing the fuzzer input without running the fuzzer).
