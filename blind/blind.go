package blind

import "crypto/ecdsa"
import "math/big"

// Based on algorithm described in An Efficient Blind Signature Scheme
// Based on the Elliptic Curve Discrete Logarithm Problem by
// Nikooghadam and Zakerolhosseini

type BlindSignature struct {
	M, S *big.Int // called m and s in the paper
	F    *ecdsa.PublicKey
}

func BlindVerify(Q *ecdsa.PublicKey, sig *BlindSignature) bool {
	crv := Secp256k1().Params()

	// onlooker verifies signature (§4.5)
	sG := ScalarBaseMult(sig.S)
	rm := new(big.Int).Mul(new(big.Int).Mod(sig.F.X, crv.N), sig.M)
	rm.Mod(rm, crv.N)
	rmQ := ScalarMult(rm, Q)
	rmQplusF := Add(rmQ, sig.F)

	return KeysEqual(sG, rmQplusF)
}
