package ige

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestDecryptAES256Blocks(t *testing.T) {
	key, iv, ciphertext := aes256IGEDecryptTestInput(16 * 16)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, len(ciphertext))
	DecryptBlocks(block, iv, want, ciphertext)

	got := make([]byte, len(ciphertext))
	DecryptAES256Blocks(key, iv, got, ciphertext)
	if !bytes.Equal(got, want) {
		t.Fatal("AES-256 IGE decrypt result differs from DecryptBlocks")
	}
}

func aes256IGEDecryptTestInput(size int) (key, iv, ciphertext []byte) {
	key = make([]byte, 32)
	iv = make([]byte, 32)
	ciphertext = make([]byte, size)
	for i := range key {
		key[i] = byte(i*3 + 1)
	}
	for i := range iv {
		iv[i] = byte(i*5 + 2)
	}
	for i := range ciphertext {
		ciphertext[i] = byte(i*7 + 3)
	}
	return key, iv, ciphertext
}
