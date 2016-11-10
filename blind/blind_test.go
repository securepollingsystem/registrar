package blind


import (
	"testing"
	"fmt"
    "math/big"
)

func TestMain(t * testing.T) {
	signer := NewSigner() // init w/Q (*pubkey) and later, d (secret), k (secret for request) but R (pubkey for request) is returned by BlindSession

	// requester: message that needs to be blind signed
	m:= new(big.Int).SetBytes([]byte("this is the message to blind-sign"))
	//m, err := RandFieldElement(rand.Reader)
	//maybePanic(err)
	fmt.Printf("m (message to be signed) = %x\n", m)

	// requester: ask signer to start the protocol
	Q, R := signer.BlindSession() // generates signer keypair once, and makes a pair for this request (stores signer pair and request.secret, returns both publics)
	// fmt.Println(len)

	// requester: blind message
	request := NewRequest(Q, R, m)

	// signer: create blind signature
	sHat := signer.BlindSign(request.Mhat)

	// requester extracts real signature
	sig := request.BlindExtract(sHat)
	//fmt.Printf("sig =\t%x\n\t%x\n", sig.S, sig.F.X)

	// onlooker verifies signature
	sig.M = m
	if BlindVerify(Q, sig) {
		fmt.Printf("valid signature\n")
	}
}
