//go:build arm && cgo && (linux || android)
// +build arm
// +build cgo
// +build linux android

package ige

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestDecryptAES256BlocksHardware(t *testing.T) {
	key, iv, ciphertext := aes256IGEDecryptTestInput(16 * 16)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, len(ciphertext))
	DecryptBlocks(block, iv, want, ciphertext)

	got := make([]byte, len(ciphertext))
	if !decryptAES256BlocksHardware(key, iv, got, ciphertext) {
		t.Skip("ARMv8 AES extension is not available")
	}
	if !bytes.Equal(got, want) {
		t.Fatal("hardware AES-256 IGE decrypt result differs from DecryptBlocks")
	}
}

func BenchmarkDecryptAES256BlocksHardware(b *testing.B) {
	key, iv, ciphertext := aes256IGEDecryptTestInput(1024 * 1024)
	plaintext := make([]byte, len(ciphertext))
	if !decryptAES256BlocksHardware(key, iv, plaintext, ciphertext) {
		b.Skip("ARMv8 AES extension is not available")
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(ciphertext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !decryptAES256BlocksHardware(key, iv, plaintext, ciphertext) {
			b.Fatal("ARMv8 AES extension became unavailable")
		}
	}
}
