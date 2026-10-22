package firecracker

import (
	"crypto/rand"
	"encoding/hex"
)

func newCatalogToken() (string, error) {
	var b [16]byte
	_, e := rand.Read(b[:])
	return hex.EncodeToString(b[:]), e
}
