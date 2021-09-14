package fuzzutil

import (
	mathRand "math/rand"
)

type MathRandReader int

func (MathRandReader) Read(buf []byte) (int, error) {
	return mathRand.Read(buf)
}
