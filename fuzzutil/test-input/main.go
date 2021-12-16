// +build gofuzz

// Command test-input can be used to test an input in the fuzzing corpus. This is mostly useful for
// testing crashers to trigger a panic. Must be built with the gofuzz build tag.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/getlantern/tlsmasq/ptlshs"
)

var inputPath = flag.String("path", "", "path to the input, probably something like workdir/crashers")

func main() {
	flag.Parse()

	if *inputPath == "" {
		fmt.Fprintln(os.Stderr, "path to input must be provided")
		os.Exit(1)
	}
	b, err := os.ReadFile(*inputPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to read input file:", err)
		os.Exit(1)
	}
	fmt.Println("fuzz.Fuzz output:", ptlshs.Fuzz(b))
}
