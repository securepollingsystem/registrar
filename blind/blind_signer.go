package blind

import (
	"crypto/ecdsa"
	"crypto/rand"
	"github.com/securepollingsystem/registrar/secp256k1"
	"math/big"
)

type BlindSigner struct {
	// secret stuff
	privateKey, privateSessionKey *big.Int

	// shareable stuff
	PublicKey, PublicSessionKey *ecdsa.PublicKey
	}

// Create a new signer
func NewSigner() *BlindSigner {
	PrivKey, _ := ecdsa.GenerateKey(secp256k1.Secp256k1(), rand.Reader)
	return &BlindSigner{privateKey: PrivKey.D, PublicKey: &PrivKey.PublicKey}
}

// Create new blinding factor for each session
func (bs *BlindSigner) NewSession() (signerKey, sessionKey *ecdsa.PublicKey) {
	PrivKey, _ := ecdsa.GenerateKey(secp256k1.Secp256k1(), rand.Reader)
	bs.privateSessionKey = PrivKey.D
	bs.PublicSessionKey = &PrivKey.PublicKey
	return bs.PublicKey, PrivKey.PublicKey
}

// Signs a blinded message
func (bs *BlindSigner) BlindSign(message *big.Int) *big.Int {
	crv := secp256k1.Secp256k1().Params()

	// verify that R matches our secret k
	R_ := ScalarBaseMult(bs.privateSessionKey)
	if !KeysEqual(bs.PublicSessionKey, R_) {
		panic("unknown R")
	}

	// signer generates signature (§4.3)
	sHat := new(big.Int).Mul(bs.d, mHat)
	sHat.Add(sHat, bs.k)
	sHat.Mod(sHat, crv.N)

	return sHat
}
