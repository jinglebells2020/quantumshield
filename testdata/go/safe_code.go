package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

func main() {
	// AES-256 is quantum-safe (256-bit key)
	key := make([]byte, 32) // 256-bit key
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}

	plaintext := []byte("quantum-safe encrypted data")
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)

	// SHA-256 is quantum-resistant
	hash := sha256.Sum256(ciphertext)
	fmt.Printf("Hash: %x\n", hash)
}
