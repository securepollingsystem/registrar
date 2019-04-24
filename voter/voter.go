package voter

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"github.com/securepollingsystem/registrar/blind"
	"math/big"
)

type Voter struct {
	privateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey

	pubhash *big.Int // hash of the voters public key, this gets signed by registrar

	// these will eventually be per registrar
	sig    *blind.BlindSignature
	pollee *blind.BlindRequest
	//registrar registrar's publickey
	//registration session info from blinding
}

type VoterSignature struct {
	R *big.Int
	S *big.Int
}

func NewVoter() *Voter {
	keys, _ := blind.GenerateKey()
	return &Voter{privateKey: keys,
		PublicKey: &keys.PublicKey}
}

// get response from registrar.BlindSession, return blinded v.PublicKey
func (v *Voter) RequestRegistration(pub, session *ecdsa.PublicKey) (blinded *big.Int, err error) {
	key, err := json.Marshal(v.PublicKey)
	if err != nil {
		return nil, err
	}
	hasher := sha256.New()
	hasher.Write(key)
	hashed := hasher.Sum(nil)
	v.pubhash = new(big.Int).SetBytes(hashed)

	v.pollee, err = blind.NewPollee(pub, session, v.pubhash)
	if err != nil {
		return nil, err
	}
	return v.pollee.Mhat, nil
}

// get sig from registrar, unblind and store it
func (v *Voter) Register(blindsig *big.Int) {
	v.sig = v.pollee.BlindExtract(blindsig)
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

func (v *Voter) String() (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}
