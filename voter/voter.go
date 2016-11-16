/* TODO:
implement stuff for one registrar
then make it work multiple
*/
package voter

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"github.com/securepollingsystem/registrar/blind"
	"math/big"
)

type Voter struct {
	privateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	pubhash    *big.Int
	// these will eventually be per registrar
	sig       *blind.BlindSignature
	requester *blind.BlindRequester
	//registrar signer's publickey
	//registration session info from blinding
}

func NewVoter() *Voter {
	keys, _ := blind.GenerateKey(nil)
	return &Voter{privateKey: keys,
		PublicKey: &keys.PublicKey}
}

// get response from signer.BlindSession, return blinded v.PublicKey
func (v *Voter) RequestRegistration(pub, session *ecdsa.PublicKey) (blinded *big.Int) {
	key, _ := json.Marshal(v.PublicKey)
	hasher := sha256.New()
	hasher.Write(key)
	hashed := hasher.Sum(nil)
	v.pubhash = new(big.Int).SetBytes(hashed)

	v.requester, _ = blind.NewRequest(pub, session, v.pubhash)
	return v.requester.Mhat
}

// get sig from signer, unblind and store it
func (v *Voter) Register(blindsig *big.Int) {
	v.sig = v.requester.BlindExtract(blindsig)
	v.sig.M = v.pubhash
}
