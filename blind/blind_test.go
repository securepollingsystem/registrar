package blind
/*
* Refactor NewBlindRequest to always blind its own public key
* Is it okay to blind multiple things with one public key?
* Create a `session` struct that is the registrar's pub key and the session
*/

import (
	"testing"
)

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
	blindedSignature, err := registrar.BlindSign(request.Mhat, *session.R)
	if err != nil {
		t.Fatal()
	}

	// Pollee extracts the blinded signature and stores it
	if !pollee.BlindExtract(request, blindedSignature) {
		t.Fatal("invalid signature");
	}

	// Pollee signs some message
	msg := []byte("This is a message I want to sign.");
	sig, err := pollee.Sign(msg);
	if err != nil {
		t.Fatal("signing error");
	}

	// Pollee verifies the signature to the message
	if !pollee.Verify(msg, sig) {
		t.Fatal("verification failed");
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
