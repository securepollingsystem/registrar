package blind

import (
	"math/big"
	"testing"
)

func TestMain(t *testing.T) {
	// Create a registrar
	registrar := NewRegistrar()

	// Pollee's message that needs to be blind-signed
	m := new(big.Int).SetBytes([]byte("this is the message to blind-sign"))

	// Pollee gets the registrar's session key and publick key
	session, err := registrar.NewBlindSession()
	if err != nil {
		t.Fatal()
	}

	// Pollee blinds her message
	// nb: the blinded message is the Mhat field on the request
	request, err := NewBlindRequest(session, m)
	if err != nil {
		t.Fatal()
	}

	// Registrar signs the message
	sHat, err := registrar.BlindSign(request.Mhat, *session.R)
	if err != nil {
		t.Fatal()
	}

	// Pollee unblinds the signature
	sig := request.BlindExtract(sHat)

	// Onlooker verifies signature
	sig.M = m
	if !BlindVerify(session.Q, sig) {
		t.Fatal("valid signature\n")
	}
}

func TestNoSession(t *testing.T) {
	registrar := NewRegistrar()
	somekey, _ := GenerateKey(nil)
	_, err := registrar.BlindSign(somekey.D, somekey.PublicKey)
	if err == nil {
		t.Fatal()
	}
}
