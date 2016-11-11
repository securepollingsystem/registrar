/* TODO:
implement stuff for one registrar
then make it work multiple
*/
package voter

import (
	"crypto/ecdsa"
	"github.com/securepollingsystem/registrar/blind"
)

type Voter struct {
	privateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	// these will eventually be per registrar
	sig        *blind.BlindSignature
	//registrar signer's publickey
	//registration session info from blinding
}

func NewVoter() *Voter {
	keys, _ := blind.GenerateKey(nil)
	return &Voter{privateKey: keys,
		PublicKey: &keys.PublicKey}
}

/*
// get response from signer.BlindSession, return blinded v.PublicKey
func (v * Voter) RequestRegistration(registrar * blind.Registrar) (blindedmessage *big.Int) {
}

// get sig from signer, unblind and store it
func (v *Voter) Register(blindsig) err {
}
*/
