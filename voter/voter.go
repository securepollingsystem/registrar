package voter

import (
	"crypto/ecdsa"
	"github.com/securepollingsystem/registrar/blind"
)

type Voter struct {
	privateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	sig        *blind.BlindSignature
}

func NewVoter() *Voter {
	keys, _ := blind.GenerateKey(nil)
	return &Voter{privateKey: keys,
		PublicKey: &keys.PublicKey}
}
