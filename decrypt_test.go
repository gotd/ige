package ige

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"testing"
)

func TestNewIGEDecrypter(t *testing.T) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("NewIGEEncrypter didn't panic with bad iv")
		}
	}()

	_ = NewIGEDecrypter(c, []byte{})
}

func TestDecrypterBlockSize(t *testing.T) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}

	i := NewIGEDecrypter(c, make([]byte, 32))

	if i.BlockSize() != 16 {
		t.Fatalf("decrypter.BlockSize() != 16, got %d instead\n", i.BlockSize())
	}
}

func TestDecrypterCryptBlocks(t *testing.T) {
	for a, v := range TestVectors {
		out := make([]byte, len(v.Ciphertext))

		c, err := aes.NewCipher(v.Key)
		if err != nil {
			t.Fatal(err)
		}

		i := NewIGEDecrypter(c, v.IV)
		i.CryptBlocks(out, v.Ciphertext)

		if !bytes.Equal(out, v.Plaintext) {
			t.Fatalf("test vector %d has wrong ciphertext\n", a+1)
		}
	}
}

func TestDecryptCryptBlocksPanicSrc(t *testing.T) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("decrypt.CryptBlocks() not panicking with bad src")
		}
	}()

	i := NewIGEDecrypter(c, make([]byte, 32))
	i.CryptBlocks(make([]byte, 16), make([]byte, 1))
}

func TestDecryptCryptBlocksPanicDst(t *testing.T) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("decrypt.CryptBlocks() not panicking with bad dst")
		}
	}()

	i := NewIGEDecrypter(c, make([]byte, 32))
	i.CryptBlocks(make([]byte, 1), make([]byte, 16))
}

func BenchmarkDecryptBlocks(b *testing.B) {
	for _, payload := range []int{
		16,
		128,
		1024,
		8192,
		64 * 1024,
		512 * 1024,
	} {
		b.Run(fmt.Sprintf("%d", payload), benchDecrypt(payload))
	}
}

func benchDecrypt(n int) func(b *testing.B) {
	return func(b *testing.B) {
		b.Helper()

		src := make([]byte, n)
		dst := make([]byte, n)

		b.ReportAllocs()
		b.SetBytes(int64(n))
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			c, err := aes.NewCipher(TestVectors[0].Key)
			if err != nil {
				b.Fatal(err)
			}

			DecryptBlocks(c, TestVectors[0].IV, dst, src)
		}
	}
}
