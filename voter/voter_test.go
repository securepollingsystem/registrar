package voter

import (
	"fmt"
	"github.com/securepollingsystem/registrar/blind"
	"testing"
)

func TestVoter(t *testing.T) {
	registrar := blind.NewRegistrar()
	pub, session, _ := registrar.BlindSession()

	voter := NewVoter()
	message, err := voter.RequestRegistration(pub, session)
	if err != nil {
		t.Fatal()
	}
	sig, err := registrar.BlindSign(message, *session)
	if err != nil {
		t.Fatal()
	}
	voter.Register(sig)

	msg := []byte("A screed")
	_, err = voter.Sign(msg)
	if err != nil {
		t.Fatal()
	}
	fmt.Println(sig)
}

func TestVoterString(t *testing.T) {
	voter := NewVoter()
	_, err := voter.String()
	if err != nil {
		t.Fatal()
	}
}
