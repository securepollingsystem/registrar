package blind

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/rand"
	"math/big"
)

type Pollee struct {
	PublicKey *ecdsa.PublicKey
	privateKey *ecdsa.PrivateKey
	publicKeyBytes []byte
	PublicKeySig *BlindSignature
	// map of sessions to blindRequests
}

func NewPollee() (*Pollee, error) {
	keys, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	return &Pollee{privateKey: keys, PublicKey: &keys.PublicKey}, nil
}

func (p *Pollee) NewBlindRequest(session *BlindSession) (*BlindRequest, error) {
	// convert Pollee pubkey to bytes, then pass to NewBlindSession
	p.publicKeyBytes = MarshalPublicKey(p.PublicKey)
	return NewBlindRequest(session, new(big.Int).SetBytes(p.publicKeyBytes))
}

func (p *Pollee) BlindExtract(request *BlindRequest, blindedSignedSignature *big.Int) bool {
	PublicKeySig := request.BlindExtract(blindedSignedSignature)
	if BlindVerify(new(big.Int).SetBytes(p.publicKeyBytes), request.session.Q, PublicKeySig) {
		p.PublicKeySig = PublicKeySig
		return true
	}
	return false
}

func (p *Pollee) Sign(data []byte) ([]byte, error) {
	return Sign(data, p.privateKey)
}

func (p *Pollee) Verify(data, signature []byte) bool {
	return Verify(data, signature, p.PublicKey);
}

// Sign signs arbitrary data using ECDSA.
func Sign(data []byte, privkey *ecdsa.PrivateKey) ([]byte, error) {
	// hash message
	digest := sha256.Sum256(data)

	// sign the hash
	r, s, err := ecdsa.Sign(rand.Reader, privkey, digest[:])
	if err != nil {
		return nil, err
	}

	// encode the signature {R, S}
	// big.Int.Bytes() will need padding in the case of leading zero bytes
	params := privkey.Curve.Params()
	curveOrderByteSize := params.P.BitLen() / 8
	rBytes, sBytes := r.Bytes(), s.Bytes()
	signature := make([]byte, curveOrderByteSize*2)
	copy(signature[curveOrderByteSize-len(rBytes):], rBytes)
	copy(signature[curveOrderByteSize*2-len(sBytes):], sBytes)

	return signature, nil
}

func Verify(data, signature []byte, pubkey *ecdsa.PublicKey) bool {
	// hash message
	digest := sha256.Sum256(data)

	curveOrderByteSize := pubkey.Curve.Params().P.BitLen() / 8

	r, s := new(big.Int), new(big.Int)
	r.SetBytes(signature[:curveOrderByteSize])
	s.SetBytes(signature[curveOrderByteSize:])

	return ecdsa.Verify(pubkey, digest[:], r, s)
}

type BlindRequest struct {
	// secret stuff
	a, b, bInv, c, m *big.Int

	// shareable stuff
	F    *ecdsa.PublicKey
	Mhat *big.Int // called m̂ in the paper
	session *BlindSession
}

func randFieldElementUnlessError(err error) (*big.Int, error) {
	if err != nil {
		return nil, err
	}
	return RandFieldElement()
}

func NewBlindRequest(session *BlindSession, m *big.Int) (*BlindRequest, error) {
	var a, b, bInv, c *big.Int
	var err error
	crv := Secp256k1().Params()
	F := new(ecdsa.PublicKey)
	for F.X == nil && F.Y == nil {
		// pollee's three blinding factors (§4.2)
		a, err = randFieldElementUnlessError(err)
		b, err = randFieldElementUnlessError(err)
		c, err = randFieldElementUnlessError(err)
		if err != nil {
			return nil, err
		}

		bInv = new(big.Int).ModInverse(b, crv.N)

		// pollee calculates point F (§4.2)
		abInv := new(big.Int).Mul(a, bInv)
		abInv.Mod(abInv, crv.N)
		bInvR := ScalarMult(bInv, session.R)
		abInvQ := ScalarMult(abInv, session.Q)
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

	return &BlindRequest{a: a, b: b, c: c, bInv: bInv, m: m, Mhat: mHat, F: F, session: session}, nil
}

// Extract true signature from the blind signature
func (br *BlindRequest) BlindExtract(sHat *big.Int) *BlindSignature {
	crv := Secp256k1().Params()

	// pollee extracts the real signature (§4.4)
	s := new(big.Int).Mul(br.bInv, sHat)
	s.Add(s, br.c)
	s.Mod(s, crv.N)
	sig := &BlindSignature{S: s, F: br.F}
	return sig
}
