package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

func main() {
	// Generate RSA key pair - QUANTUM VULNERABLE
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	message := []byte("secret data")

	// Encrypt with RSA-OAEP - vulnerable to Shor's algorithm
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &privateKey.PublicKey, message, nil)
	if err != nil {
		panic(err)
	}

	// Decrypt
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(plaintext))
}
