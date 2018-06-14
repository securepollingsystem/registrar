package blind

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"encoding/json"
)

func tostring(obj interface{}) string {
	b, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}
	return string(b)
}

type Sessions map[ecdsa.PublicKey]*big.Int

func NewSessios() *Sessions {
	return Sessions(make(map[ecdsa.PublicKey]*big.Int))
}

func (s *Sessions) MarshalJSON([]byte, error) {
	datas := make(map[string]string)
	for k, v := range s {
		datas[tostring(k)] = tostring(v)
	}
	return json.Marshal(datas)
}

type BlindSigner struct {
	// permenant keys
	privateKey *big.Int // signers secret key d
	PublicKey  *ecdsa.PublicKey

	// sessions
	sessions *Sessions
}

type jsonData struct {
	PrivateKey *big.Int
	PublicKey *ecdsa.PublicKey
	Sessions map[ecdsa.PublicKey]*big.Int
}

func NewSigner() *BlindSigner {
	keys, _ := GenerateKey(rand.Reader)
	sessions := make(map[ecdsa.PublicKey]*big.Int)
	return &BlindSigner{privateKey: keys.D, PublicKey: &keys.PublicKey,
		sessions: sessions}
}

func NewSignerFromString(b []byte) *BlindSigner {
	signer := NewSigner()
	json.Unmarshal(b, signer)
	return signer
}

func Print(b []byte) {
	fmt.Println(string(b))
}

func tostring(obj interface{}) () {
	s, _ := json.Marshal(obj)
	Print(s)
}

func (bs *BlindSigner) Marshal() ([]byte, error) {
	jd := &jsonData{
		PrivateKey: bs.privateKey,
		PublicKey: bs.PublicKey,
		Sessions: bs.sessions}
	return json.Marshal(jd)
}

// Request that the signer start a blind signature protocol.  Returns
// the signer's public key and an EC point named R.
func (bs *BlindSigner) BlindSession() (*ecdsa.PublicKey, *ecdsa.PublicKey, error) {

	// generate k and R for each user request (§4.2)
	request, err := GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	bs.sessions[request.PublicKey] = request.D

	return bs.PublicKey, &request.PublicKey, nil
}

// Signs a blinded message
func (bs *BlindSigner) BlindSign(mHat *big.Int, key ecdsa.PublicKey) (*big.Int, error) {
	crv := Secp256k1().Params()
	sessionPrivKey, ok := bs.sessions[key]
	if !ok {
		return nil, errors.New("No session for this key")
	}

	// verify that R matches our secret k
	R_ := ScalarBaseMult(sessionPrivKey)
	if !KeysEqual(&key, R_) {
		return nil, errors.New("Unkown session")
	}

	// signer generates signature (§4.3)
	sHat := new(big.Int).Mul(bs.privateKey, mHat)
	sHat.Add(sHat, sessionPrivKey)
	sHat.Mod(sHat, crv.N)

	return sHat, nil
}
