package fuzzutil

import (
	mathRand "math/rand"
)

// MathRandReader is used exclusively with
// [tls.Config.Rand](https://pkg.go.dev/crypto/tls#Config) after setting a seed
// using mathRand.Seed(whatever)
type MathRandReader int

func (MathRandReader) Read(buf []byte) (int, error) {
	return mathRand.Read(buf)
}
