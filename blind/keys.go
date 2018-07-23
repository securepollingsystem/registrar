package blind

import (
	"crypto/ecdsa"
	"crypto/rand"
)

// GenerateKey generates a public and private key pair
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(Secp256k1(), rand.Reader)
}

func KeysEqual(a, b *ecdsa.PublicKey) bool {
	return a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0
}
