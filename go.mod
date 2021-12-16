module github.com/getlantern/tlsmasq

go 1.13

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dvyukov/go-fuzz v0.0.0-20210914135545-4980593459a1 // indirect
	github.com/getlantern/nettest v1.0.0
	github.com/getlantern/preconn v1.0.0
	github.com/getlantern/tlsutil v0.5.0
	github.com/refraction-networking/utls v0.0.0-20210713165636-0b2885c8c0d4
	github.com/stretchr/testify v1.7.0
	golang.org/x/sys v0.0.0-20210809222454-d867a43fc93e // indirect
)

replace github.com/refraction-networking/utls => github.com/getlantern/utls v0.0.0-20200903013459-0c02248f7ce1
