package fuzzutil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	cryptoRand "crypto/rand"
	"encoding/hex"
	"fmt"
)

// XXX It's easy to see 0x4141414141414141 in a debugger
var SEPARATOR = []byte("AAAAAAAA")
var AES128_NONCE_SIZE = 12
var AES128_KEY_SIZE = 16
var CONFIG_SIZE = 8

func getSecureRandomByteSlice(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := cryptoRand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func getSecureRandomIdentifier() (string, error) {
	s := make([]byte, 4)
	_, err := cryptoRand.Read(s)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(s), nil
}

func encryptFuzzConfig(plaintext []byte) (nonce []byte, key []byte, ciphertext []byte, err error) {
	nonce = make([]byte, AES128_NONCE_SIZE)
	_, err = cryptoRand.Read(nonce)
	if err != nil {
		return nil, nil, nil, err
	}
	key = make([]byte, AES128_KEY_SIZE)
	_, err = cryptoRand.Read(key)
	if err != nil {
		return nil, nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}
	aesCipher, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}
	// log.Printf("plaintext %x\n", plaintext)
	// log.Printf("nonce %x\n", nonce)
	// log.Printf("ciphertext %x\n", ciphertext)

	return nonce, key, aesCipher.Seal(nil, nonce, plaintext, nil), nil
}

// packFuzzInput packs data in this format:
//
//	  nonce | key | AES(seed) | SEPARATOR | clientHelloData
//
// See 'On Fuzzing -> Fuzzing Internals' in the README for a lengthy breakdown
func packFuzzInput(nonce, key, encryptedConfig, clientHelloData []byte) []byte {
	var b bytes.Buffer
	b.Write(nonce)
	b.Write(key)
	b.Write(encryptedConfig)
	b.Write(SEPARATOR)
	b.Write(clientHelloData)
	return b.Bytes()
}

func DecryptAndUnpackFuzzInput(packedData []byte) (decryptedConfig []byte, clientHelloHandshake []byte, err error) {
	idx := bytes.Index(packedData, SEPARATOR)
	if idx == -1 {
		return nil, nil, fmt.Errorf("No SEPARATOR found")
	}
	nonce := packedData[:AES128_NONCE_SIZE]
	key := packedData[AES128_NONCE_SIZE : AES128_NONCE_SIZE+AES128_KEY_SIZE]
	ciphertext := packedData[AES128_NONCE_SIZE+AES128_KEY_SIZE : idx]
	packedData = packedData[idx+len(SEPARATOR):]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aesCipher, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	decryptedConfig, err = aesCipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, nil, err
	}
	if len(decryptedConfig) != CONFIG_SIZE {
		panic(fmt.Sprintf("len(decryptedConfig) is not %d", CONFIG_SIZE))
	}

	return decryptedConfig, packedData, nil
}
