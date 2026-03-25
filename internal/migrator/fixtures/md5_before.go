package fixtures

import (
	"crypto/md5"
	"fmt"
)

func hashWithMD5() {
	h := md5.New()
	h.Write([]byte("data"))
	fmt.Printf("%x\n", h.Sum(nil))
}
