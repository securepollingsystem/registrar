package blind

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/elliptic"
)

// GenerateKey generates a public and private key pair
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(Secp256k1(), rand.Reader)
}

func MarshalPublicKey(pk *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(Secp256k1(), pk.X, pk.Y)
}

func UnmarshalPublicKey(b []byte) *ecdsa.PublicKey {
	Curve := Secp256k1()
	X, Y := elliptic.Unmarshal(Curve, b)
	return &ecdsa.PublicKey{Curve, X, Y}
}

func KeysEqual(a, b *ecdsa.PublicKey) bool {
	return a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0
}
