package registrar

import "crypto/ecdsa"
import "crypto/rand"
import "fmt"
import "math/big"

type BlindSigner struct {
	// secret stuff
	d, k *big.Int

	// shareable stuff
	Q *ecdsa.PublicKey
}

// Create a new signer
func NewSigner() *BlindSigner {
	generate a s
	return sState.Q, R
}

// Create new blinding factor for each session
func NewSession() (signerKey, sessionKey *ecdsa.PublicKey) {
}


// Signs a blinded message
func BlindSign(sState *BlindSignerState, R *ecdsa.PublicKey, mHat *big.Int) *big.Int {
	crv := Secp256k1().Params()

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
