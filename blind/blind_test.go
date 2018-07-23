package blind
/*
* Refactor NewBlindRequest to always blind its own public key
* Is it okay to blind multiple things with one public key?
* Create a `session` struct that is the registrar's pub key and the session
*/

import (
	"math/big"
	"testing"
//	"fmt"
//	"encoding/json"
)

/*
func TestTwo(t *testing.T) {
	// Create a registrar
	registrar := NewRegistrar()

	// Create a pollee
	pollee := NewPollee()

	// Registrar creates a new blinding session for pollee
	session, err := registrar.BlindSession()
	if err != nil {
		t.Fatal()
	}

	// Pollee blinds it's public key for the registrar
	polleeBlindedPubKey := pollee.BlindPublicKey(session)

	// Registrar signs the pollee's blinded public key
	polleeBlindedPubKeySig, err := registrar.BlindSign(polleeBlindedPubKey, *session)

	polleePubKeySig := pollee.ExtractAndSaveSignature(session, polleeBlindedPubKeySig)

	m := new(big.Int).SetBytes([]byte("this is the message to sign"))
	mSig := pollee.Sign(session, m)

	if !VerifySig(m, mSig, polleePubKey, polleeBlindedPubKeySig, session.registrarPubKey) {
		t.Fatal()
	}
}
*/

func TestMain(t *testing.T) {
	// Create a registrar
	registrar := NewRegistrar()

	// Create a pollee
	pollee, err := NewPollee()
	if err != nil {
		t.Fatal()
	}

	// Pollee gets the registrar's session key and publick key
	session, err := registrar.NewBlindSession()
	if err != nil {
		t.Fatal()
	}

	// Pollee blinds her message
	// nb: the blinded message is the Mhat field on the request
	request, err := pollee.NewBlindRequest(session)
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
	message := new(big.Int).SetBytes(MarshalPublicKey(pollee.PublicKey))
	if !BlindVerify(message, session.Q, sig) {
		t.Fatal("valid signature\n")
	}
}

func TestNoSession(t *testing.T) {
	registrar := NewRegistrar()
	somekey, _ := GenerateKey()
	_, err := registrar.BlindSign(somekey.D, somekey.PublicKey)
	if err == nil {
		t.Fatal()
	}
}
