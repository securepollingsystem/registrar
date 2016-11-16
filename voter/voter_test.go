package voter

import (
	"fmt"
	"github.com/securepollingsystem/registrar/blind"
	"testing"
)

func TestVoter(t *testing.T) {
	signer := blind.NewSigner()
	pub, session, _ := signer.BlindSession()

	voter := NewVoter()
	message := voter.RequestRegistration(pub, session)
	sig, err := signer.BlindSign(message, *session)
	if err != nil {
		t.Fatal()
	}
	voter.Register(sig)
	fmt.Println(sig)
}
