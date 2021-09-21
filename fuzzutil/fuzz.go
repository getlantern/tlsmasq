// +build gofuzz

package fuzzutil

import (
	"encoding/binary"
)

func Fuzz(fuzzedData []byte) int {
	seedAsBytes, clientHelloHandshake, err := DecryptAndUnpackFuzzInput(fuzzedData)
	if err != nil {
		// This means the input data was badly-parsed. Return -1 so that
		// go-fuzz doesn't continue with this permutation
		return -1
	}
	seed := int64(binary.LittleEndian.Uint64(seedAsBytes))
	err = RunFuzz(seed, clientHelloHandshake)
	if err != nil {
		// Panic to indicate application-level errors
		panic(err)
	}
	// Taken from go-fuzz: "The function must return 1 if the fuzzer should
	// increase priority of the given input during subsequent fuzzing (for
	// example, the input is lexically correct and was parsed successfully)
	//
	// Ref https://github.com/dvyukov/go-fuzz/tree/b1f3d6f4ef4e0fab65fa66f9191e6b115ad34f31#usage
	return 1
}
