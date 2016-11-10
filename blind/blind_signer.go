package blind

import "crypto/ecdsa"
import "crypto/rand"
import "math/big"

type BlindSignerState struct {
	// secret stuff
	d, k *big.Int

	// shareable stuff
	Q *ecdsa.PublicKey
	PublickSessionKey *ecdsa.PublicKey
}

func NewSigner() *BlindSignerState {
		keys, _ := GenerateKey(rand.Reader)
		return &BlindSignerState{d: keys.D, Q: &keys.PublicKey}
}

// Request that the signer start a blind signature protocol.  Returns
// the signer's public key and an EC point named R.
func (bs * BlindSignerState) BlindSession() (*ecdsa.PublicKey, *ecdsa.PublicKey) {

	// generate k and R for each user request (§4.2)
	request, err := GenerateKey(rand.Reader)
	maybePanic(err)
	bs.k = request.D
	bs.PublickSessionKey = &request.PublicKey

	return bs.Q, bs.PublickSessionKey
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

// Signs a blinded message
func (bs * BlindSignerState) BlindSign(mHat *big.Int) *big.Int {
	crv := Secp256k1().Params()

	// verify that R matches our secret k
	R_ := ScalarBaseMult(bs.k)
	if !KeysEqual(bs.PublickSessionKey, R_) {
		panic("unknown R")
	}

	// signer generates signature (§4.3)
	sHat := new(big.Int).Mul(bs.d, mHat)
	sHat.Add(sHat, bs.k)
	sHat.Mod(sHat, crv.N)

	return sHat
}
