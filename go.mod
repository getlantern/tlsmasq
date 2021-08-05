module github.com/getlantern/tlsmasq

go 1.13

require (
	github.com/getlantern/golog v0.0.0-20210606115803-bce9f9fe5a5f
	github.com/getlantern/preconn v0.0.0-20210115195610-7b15d0535d80
	github.com/getlantern/tlsutil v0.4.1
	github.com/getlantern/transports v0.0.0-00010101000000-000000000000
	github.com/refraction-networking/utls v0.0.0-20200729012536-186025ac7b77
	github.com/stretchr/testify v1.7.0
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e
)

replace github.com/getlantern/transports => ../transports

replace github.com/refraction-networking/utls => github.com/getlantern/utls v0.0.0-20200903013459-0c02248f7ce1
