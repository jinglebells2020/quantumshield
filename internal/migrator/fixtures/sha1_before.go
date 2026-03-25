package fixtures

import (
	"crypto/sha1"
	"fmt"
)

func hashWithSHA1() {
	h := sha1.New()
	h.Write([]byte("data"))
	fmt.Printf("%x\n", h.Sum(nil))
}
