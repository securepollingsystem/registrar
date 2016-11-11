package blind

import (
	"math/big"
	"testing"
)

func TestMain(t *testing.T) {
	signer := NewSigner() // init w/Q (*pubkey) and later, d (secret), k (secret for request) but R (pubkey for request) is returned by BlindSession

	// requester: message that needs to be blind signed
	m := new(big.Int).SetBytes([]byte("this is the message to blind-sign"))
	//m, err := RandFieldElement(rand.Reader)
	//maybePanic(err)

	// requester: ask signer to start the protocol
	Q, R, err := signer.BlindSession() // generates signer keypair once, and makes a pair for this request (stores signer pair and request.secret, returns both publics)
	if err != nil {
		t.Fatal()
	}
	// fmt.Println(len)

	// requester: blind message
	requester, err := NewRequest(Q, R, m)
	if err != nil {
		t.Fatal()
	}

	// signer: create blind signature
	sHat, err := signer.BlindSign(requester.Mhat)
	if err != nil {
		t.Fatal()
	}

	// requester extracts real signature
	sig := requester.BlindExtract(sHat)

	// onlooker verifies signature
	sig.M = m
	if !BlindVerify(Q, sig) {
		t.Fatal("valid signature\n")
	}
}
