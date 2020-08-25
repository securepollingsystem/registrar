package blind
/*
* Refactor NewBlindRequest to always blind its own public key
* Is it okay to blind multiple things with one public key?
* Create a `session` struct that is the registrar's pub key and the session
*/

import (
	"testing"
)

// This test documents the steps of a Pollee getting their key signed and 
// using it to create a signed scree.
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
	
	// Pollee brings her blinded message to the registrar
        // Registar verifies the pollee's identity, and receives her blinded message

	// Registrar signs the message
	blindedSignature, err := registrar.BlindSign(request.Mhat, *session.R)
	if err != nil {
		t.Fatal()
	}

	// Registar gives the signature of the blinded message to the Pollee

	// Pollee extracts the blinded signature and stores it
	if !pollee.BlindExtract(request, blindedSignature) {
		t.Fatal("invalid signature");
	}

	// The Pollee then finds opinions and collects them as a screed
	msg := []byte("This is a message I want to sign.");
	
	// Pollee signs her screed
	sig, err := pollee.Sign(msg);
	if err != nil {
		t.Fatal("signing error");
	}

	// Anyone can verify the signed screed (`sig` + `msg`), but this next line just
	// demonstrates the pollee can verify her own message
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
