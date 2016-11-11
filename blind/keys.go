package blind

import (
	"crypto/ecdsa"
	"crypto/rand"
	"io"
)

// GenerateKey generates a public and private key pair
func GenerateKey(r io.Reader) (*ecdsa.PrivateKey, error) {
	if r == nil {
		r = rand.Reader
	}
	return ecdsa.GenerateKey(Secp256k1(), r)
}

func KeysEqual(a, b *ecdsa.PublicKey) bool {
	return a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0
}
