.PHONY: build, prep-corpus, all, run-fuzz, run-tests, clean

all: build

#: Build the project. Useful as a sanity check
build:
	go build

#: Generate fuzz input from various tls configurations. See README for more info
generate-fuzz-input:
	(cd fuzzutil; DO=1 go test -run TestGenerateClientHellos)
	@echo "Fuzz input generated and automatically propagated to ./fuzz_workdir/annotated_corpus"

#: Run tests
run-tests:
	go test -race ./...

#: Run the fuzz suite. See README for more info
run-fuzz: prep-corpus tlsmasq-fuzz.zip
	go-fuzz -bin=./tlsmasq-fuzz.zip -workdir=fuzz_workdir

#: Copy all corpus input to fuzz_workdir/corpus
prep-corpus:
	find fuzz_workdir/annotated_corpus -type f -name "*.raw" -exec cp "{}" fuzz_workdir/corpus \;

tlsmasq-fuzz.zip:
	go get github.com/dvyukov/go-fuzz/go-fuzz
	go get github.com/dvyukov/go-fuzz/go-fuzz-build
	go-fuzz-build github.com/getlantern/tlsmasq

clean:
	rm -rf ./tlsmasq-fuzz.zip
