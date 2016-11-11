package blind

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"
)

type BlindSigner struct {
	// secret stuff
	d, k *big.Int

	// shareable stuff
	Q                 *ecdsa.PublicKey
	PublickSessionKey *ecdsa.PublicKey
}

func NewSigner() *BlindSigner {
	keys, _ := GenerateKey(rand.Reader)
	return &BlindSigner{d: keys.D, Q: &keys.PublicKey}
}

// Request that the signer start a blind signature protocol.  Returns
// the signer's public key and an EC point named R.
func (bs *BlindSigner) BlindSession() (*ecdsa.PublicKey, *ecdsa.PublicKey, error) {

	// generate k and R for each user request (§4.2)
	request, err := GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	bs.k = request.D
	bs.PublickSessionKey = &request.PublicKey

	return bs.Q, bs.PublickSessionKey, nil
}

// Signs a blinded message
func (bs *BlindSigner) BlindSign(mHat *big.Int) (*big.Int, error) {
	crv := Secp256k1().Params()

	// verify that R matches our secret k
	R_ := ScalarBaseMult(bs.k)
	if !KeysEqual(bs.PublickSessionKey, R_) {
		return nil, errors.New("Unkown session")
	}

	// signer generates signature (§4.3)
	sHat := new(big.Int).Mul(bs.d, mHat)
	sHat.Add(sHat, bs.k)
	sHat.Mod(sHat, crv.N)

	return sHat, nil
}
