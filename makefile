.PHONY: build, prep-corpus, all, run-fuzz, run-tests, clean

all: build

#: Build the project. Since tlsmasq is a library, this is useful only as a sanity check.
build:
	go build

#: runs `fuzzutil/fuzzutil_test.go:TestGenerateClientHellos` as a standalone program to generate fuzz input. See "On Fuzzing" section in the README for more info
generate-fuzz-input:
	(cd fuzzutil; DO=1 go test -run TestGenerateClientHellos)
	@echo "Fuzz input generated and automatically propagated to ./fuzz_workdir/annotated_corpus"

#: Run all tests
run-tests:
	go test -race ./...

#: Run the fuzz suite. See README for more info
run-fuzz: prep-corpus tlsmasq-fuzz.zip
	go-fuzz -bin=./tlsmasq-fuzz.zip -workdir=fuzz_workdir

prep-corpus:
	find fuzz_workdir/annotated_corpus -type f -name "*.raw" -exec cp "{}" fuzz_workdir/corpus \;

tlsmasq-fuzz.zip:
	go get github.com/dvyukov/go-fuzz/go-fuzz
	go get github.com/dvyukov/go-fuzz/go-fuzz-build
	go-fuzz-build -o tlsmasq-fuzz.zip github.com/getlantern/tlsmasq/fuzzutil

clean:
	rm -rf ./tlsmasq-fuzz.zip
