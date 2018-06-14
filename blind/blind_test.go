package blind

import (
	"math/big"
	"testing"
//	"fmt"
)

func TestMain(t *testing.T) {
	// Create a signer
	signer := NewSigner()

	// Requester's message that needs to be blind-signed
	m := new(big.Int).SetBytes([]byte("this is the message to blind-sign"))

	// Requester gets the signer's session key and publick key
	pub, session, err := signer.BlindSession()
	if err != nil {
		t.Fatal()
	}

	// Requester blinds her message
	// nb: the blinded message is the Mhat field on the requester
	requester, err := NewRequest(pub, session, m)
	if err != nil {
		t.Fatal()
	}

	// Signer signs the message
	sHat, err := signer.BlindSign(requester.Mhat, *session)
	if err != nil {
		t.Fatal()
	}

	// Requester unblinds the signature
	sig := requester.BlindExtract(sHat)

	// Onlooker verifies signature
	sig.M = m
	if !BlindVerify(pub, sig) {
		t.Fatal("valid signature\n")
	}
}

func TestNoSession(t *testing.T) {
	signer := NewSigner()
	somekey, _ := GenerateKey(nil)
	_, err := signer.BlindSign(somekey.D, somekey.PublicKey)
	if err == nil {
		t.Fatal()
	}
}

func TestBlindSignerSerialization(t *testing.T) {
	signer := NewSigner()
	s, err := signer.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	signer2 := NewSignerFromString(s)
	signer2bytes, _ := signer2.Marshal()
	if string(signer2bytes) != string(s) {
		t.Fatal("different values")
	}
}
