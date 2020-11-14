package ptlshs

import (
	"errors"
	"io"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBufferList(t *testing.T) {
	l := new(bufferList)

	// Note that these tests are designed to run serially.

	t.Run("empty", func(t *testing.T) {
		require.Equal(t, 0, l.len())

		b := make([]byte, 10)
		n, err := l.Read(b)
		require.Error(t, err)
		require.True(t, errors.Is(err, io.EOF))
		require.Equal(t, 0, n)
	})

	t.Run("simple", func(t *testing.T) {
		contents := []byte("contents")

		// Do the following twice to ensure the buffer list still works after a full read.
		for i := 0; i < 2; i++ {
			l.prepend(contents)
			require.Equal(t, len(contents), l.len())

			readResult, err := ioutil.ReadAll(l)
			require.NoError(t, err)
			require.Equal(t, contents, readResult)

			readResult, err = ioutil.ReadAll(l)
			require.NoError(t, err)
			require.Equal(t, 0, len(readResult))
		}
	})

	t.Run("multiple elements", func(t *testing.T) {
		contents := [][]byte{
			[]byte("contents 1"),
			[]byte("contents 2"),
			[]byte("contents 3"),
		}
		concatContents := []byte{}
		for _, c := range contents {
			concatContents = append(concatContents, c...)
		}

		// Do the following twice to ensure the buffer list still works after a full read.
		for i := 0; i < 2; i++ {
			for i := len(contents) - 1; i >= 0; i-- {
				l.prepend(contents[i])
			}
			require.Equal(t, len(concatContents), l.len())

			readResult, err := ioutil.ReadAll(l)
			require.NoError(t, err)
			require.Equal(t, concatContents, readResult)

			readResult, err = ioutil.ReadAll(l)
			require.NoError(t, err)
			require.Equal(t, 0, len(readResult))
		}
	})
}
