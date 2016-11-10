package blind

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"github.com/securepollingsystem/registrar/secp256k1"
	"math/big"
)

type BlindSigner struct {
	// secret stuff
	privateKey, privateSessionKey *big.Int

	// shareable stuff
	PublicKey *ecdsa.PublicKey
}

// Create a new signer
func NewSigner() *BlindSigner {
	PrivKey := ecdsa.GenerateKey(secp256k1.Secp256k1(), rand.Reader)
	return &BlindSigner{privateKey: PrivKey, PublicKey: PrivKey.PublicKey}
}

// Create new blinding factor for each session
func (bs *BlindSigner) NewSession() (signerKey, sessionKey *ecdsa.PublicKey) {
	PrivKey := ecdsa.GenerateKey(secp256k1.Secp256k1(), rand.Reader)
	bs.privateSessionKey = PrivKey
	return bs.PublicKey, PrivKey.PublicKey
}

// Signs a blinded message
func (bs *BlindSigner) BlindSign(message *big.Int) *big.Int {
	crv := secp256k1.Secp256k1().Params()

	// verify that R matches our secret k
	R_ := ScalarBaseMult(sState.k)
	if !KeysEqual(R, R_) {
		panic("unknown R")
	}

	// signer generates signature (§4.3)
	sHat := new(big.Int).Mul(sState.d, mHat)
	sHat.Add(sHat, sState.k)
	sHat.Mod(sHat, crv.N)

	return sHat
}
