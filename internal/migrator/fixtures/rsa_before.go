package fixtures

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func generateRSAKey() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	fmt.Println(key)
}
