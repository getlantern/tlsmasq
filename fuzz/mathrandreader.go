package fuzz

import (
	mathRand "math/rand"
	"runtime/debug"
	"strings"
)

// MathRandReader is used exclusively with
// [tls.Config.Rand](https://pkg.go.dev/crypto/tls#Config) after setting a seed
// using mathRand.Seed(whatever)
type MathRandReader int

func (MathRandReader) Read(buf []byte) (int, error) {
	stack := string(debug.Stack())
	// XXX <30-09-21, soltzen> This is a very special case.
	// There's a function called
	// [randutil.MaybeReadByte](https://pkg.go.dev/crypto/internal/randutil#MaybeReadByte),
	// which reads has a 50% chance to read a single byte from the io.Reader
	// representing "rand". This is destructive for us since we want 100%
	// reproducible results; one byte off and the encryption will result in
	// different results, which means the recorded data will have a 50% chance
	// of being reproducible.
	//
	// The solution here is to **always** yields a null byte to buf whenever
	// this happens: if MaybeReadByte reads that null byte, the order of
	// MathRandReader remains intact (and reproducible next time Read() is
	// called). If it doesn't read it, nothing happens and the output of
	// MathRandReader's Read() remains intact and reproducible
	if strings.Contains(stack, "MaybeReadByte") {
		buf[0] = 0
		return 1, nil
	}
	c, err := mathRand.Read(buf)
	return c, err
}
