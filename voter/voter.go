package voter

import (
	"crypto/sha256"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"github.com/securepollingsystem/registrar/blind"
)

type Voter struct {
	privateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey

	pubhash    *big.Int  // hash of the voters public key, this gets signed by registrar

	// these will eventually be per registrar
	sig        *blind.BlindSignature
	requester *blind.BlindRequester
	//registrar signer's publickey
	//registration session info from blinding
}

type VoterSignature struct {
	R *big.Int
	S *big.Int
}

func NewVoter() *Voter {
	keys, _ := blind.GenerateKey(nil)
	return &Voter{privateKey: keys,
		PublicKey: &keys.PublicKey}
}

// get response from signer.BlindSession, return blinded v.PublicKey
func (v * Voter) RequestRegistration(pub, session *ecdsa.PublicKey) (blinded *big.Int, err error) {
	key, err := json.Marshal(v.PublicKey)
	if err != nil {
		return nil, err
	}
	hasher := sha256.New()
	hasher.Write(key)
	hashed := hasher.Sum(nil)
	v.pubhash = new(big.Int).SetBytes(hashed)

	v.requester, err = blind.NewRequest(pub, session, v.pubhash)
	if err != nil {
		return nil, err
	}
	return v.requester.Mhat, nil
}

// get sig from signer, unblind and store it
func (v *Voter) Register(blindsig *big.Int) {
	v.sig = v.requester.BlindExtract(blindsig)
	v.sig.M = v.pubhash
}

// sign a thing
func (v *Voter) Sign(msg []byte) (*VoterSignature, error) {
	hasher := sha256.New()
	hasher.Write(msg)
	hashed := hasher.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, v.privateKey, hashed)
	if err != nil {
		return nil, err
	}
	return &VoterSignature{R: r, S: s}, nil
}
