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
	pub, session, err := registrar.BlindSession()
	if err != nil {
		t.Fatal()
	}

	// Pollee blinds her message
	// nb: the blinded message is the Mhat field on the pollee
	pollee, err := NewRequest(pub, session, m)
	if err != nil {
		t.Fatal()
	}

	// Registrar signs the message
	sHat, err := registrar.BlindSign(pollee.Mhat, *session)
	if err != nil {
		t.Fatal()
	}

	// Pollee unblinds the signature
	sig := pollee.BlindExtract(sHat)

	// Onlooker verifies signature
	sig.M = m
	if !BlindVerify(pub, sig) {
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
