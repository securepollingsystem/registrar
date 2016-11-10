package main

//import "crypto/rand"
import "fmt"
import "github.com/mndrix/btcutil"
//import "encoding/hex"
import "math/big"

func main() {
	signer := new(btcutil.BlindSignerState) // init w/Q (*pubkey) and later, d (secret), k (secret for request) but R (pubkey for request) is returned by BlindSession
	requester := new(btcutil.BlindRequesterState) // contains F (pubkey), X0 (bigint) and Mhat (bigint)

	// requester: message that needs to be blind signed
	m:= new(big.Int).SetBytes([]byte("this is the message to blind-sign"))
	//m, err := btcutil.RandFieldElement(rand.Reader)
	//maybePanic(err)
	fmt.Printf("m (message to be signed) = %x\n", m)

	// requester: ask signer to start the protocol
	Q, R := btcutil.BlindSession(signer) // generates signer keypair once, and makes a pair for this request (stores signer pair and request.secret, returns both publics)
	// fmt.Println(len)

	// requester: blind message
	mHat := btcutil.BlindMessage(requester, Q, R, m) // 

	// signer: create blind signature
	sHat := btcutil.BlindSign(signer, R, mHat)

	// requester extracts real signature
	sig := btcutil.BlindExtract(requester, sHat)
	fmt.Printf("sig =\t%x\n\t%x\n", sig.S, sig.F.X)

	// onlooker verifies signature
	sig.M = m
	if btcutil.BlindVerify(Q, sig) {
		fmt.Printf("valid signature\n")
	}
}

func maybePanic(err error) {
	if err != nil {
		panic(err)
	}
}
