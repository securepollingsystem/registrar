package blind

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"
)

type BlindRegistrar struct {
	// permenant keys
	privateKey *big.Int // registrars secret key d
	PublicKey  *ecdsa.PublicKey

	// sessions
	sessions map[ecdsa.PublicKey]*big.Int
}

func NewRegistrar() *BlindRegistrar {
	keys, _ := GenerateKey(rand.Reader)
	sessions := make(map[ecdsa.PublicKey]*big.Int)
	return &BlindRegistrar{privateKey: keys.D, PublicKey: &keys.PublicKey,
		sessions: sessions}
}

// Request that the registrar start a blind signature protocol.  Returns
// the registrar's public key and an EC point named R.
func (bs *BlindRegistrar) BlindSession() (*ecdsa.PublicKey, *ecdsa.PublicKey, error) {

	// generate k and R for each user request (§4.2)
	request, err := GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	bs.sessions[request.PublicKey] = request.D

	return bs.PublicKey, &request.PublicKey, nil
}

// Signs a blinded message
func (bs *BlindRegistrar) BlindSign(mHat *big.Int, key ecdsa.PublicKey) (*big.Int, error) {
	crv := Secp256k1().Params()
	sessionPrivKey, ok := bs.sessions[key]
	if !ok {
		return nil, errors.New("No session for this key")
	}

	// verify that R matches our secret k
	R_ := ScalarBaseMult(sessionPrivKey)
	if !KeysEqual(&key, R_) {
		return nil, errors.New("Unkown session")
	}

	// registrar generates signature (§4.3)
	sHat := new(big.Int).Mul(bs.privateKey, mHat)
	sHat.Add(sHat, sessionPrivKey)
	sHat.Mod(sHat, crv.N)

	return sHat, nil
}
