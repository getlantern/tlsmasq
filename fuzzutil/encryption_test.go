package fuzzutil

import (
	cryptoRand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncryption(t *testing.T) {
	// XXX For now, the only configurations we have is the seed value
	config := make([]byte, CONFIG_SIZE)
	_, err := cryptoRand.Read(config)
	require.NoError(t, err)
	nonce, key, encryptedConfig, err := EncryptFuzzConfig(config)
	require.NoError(t, err)
	fuzzInput := PackFuzzInput(nonce, key, encryptedConfig, []byte{})

	decryptedConfig, clientHelloData, err := DecryptAndUnpackFuzzInput(fuzzInput)
	require.NoError(t, err)
	require.NotNil(t, clientHelloData)
	require.Equal(t, config, decryptedConfig)
}
