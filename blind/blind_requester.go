package blind

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
)

type BlindRequester struct {
	// secret stuff
	a, b, bInv, c, m *big.Int

	// shareable stuff
	F    *ecdsa.PublicKey
	Mhat *big.Int // called m̂ in the paper
}

func randFieldElementUnlessError(err error) (*big.Int, error) {
	if err != nil {
		return nil, err
	}
	return RandFieldElement(rand.Reader)
}

func NewRequest(Q, R *ecdsa.PublicKey, m *big.Int) (*BlindRequester, error) {
	var a, b, bInv, c *big.Int
	var err error
	crv := Secp256k1().Params()
	F := new(ecdsa.PublicKey)
	for F.X == nil && F.Y == nil {
		// requester's three blinding factors (§4.2)
		a, err = randFieldElementUnlessError(err)
		b, err = randFieldElementUnlessError(err)
		c, err = randFieldElementUnlessError(err)
		if err != nil {
			return nil, err
		}

		bInv = new(big.Int).ModInverse(b, crv.N)

		// requester calculates point F (§4.2)
		abInv := new(big.Int).Mul(a, bInv)
		abInv.Mod(abInv, crv.N)
		bInvR := ScalarMult(bInv, R)
		abInvQ := ScalarMult(abInv, Q)
		cG := ScalarBaseMult(c)
		F = Add(bInvR, abInvQ)
		F = Add(F, cG)
	}
	// calculate r and m̂
	r := new(big.Int).Mod(F.X, crv.N)
	mHat := new(big.Int).Mul(b, r)
	mHat.Mul(mHat, m)
	mHat.Add(mHat, a)
	mHat.Mod(mHat, crv.N)

	return &BlindRequester{a: a, b: b, c: c, bInv: bInv, m: m, Mhat: mHat, F: F}, nil
}

// Extract true signature from the blind signature
func (br *BlindRequester) BlindExtract(sHat *big.Int) *BlindSignature {
	crv := Secp256k1().Params()

	// requester extracts the real signature (§4.4)
	s := new(big.Int).Mul(br.bInv, sHat)
	s.Add(s, br.c)
	s.Mod(s, crv.N)
	sig := &BlindSignature{S: s, F: br.F}
	return sig
}
