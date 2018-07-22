package blind

import (
	"encoding/hex"
	"errors"
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/elliptic"
	"math/big"
	"testing"
	"encoding/json"
	"fmt"
)

func Print(b ...interface{}) {
	fmt.Println(b)
}

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

func TestJsonBigInt(t *testing.T) {
	var x = new(big.Int).SetInt64(1337)
	b, _ := json.Marshal(x)
	Print(string(b))
	var decoded big.Int
	json.Unmarshal(b, &decoded)
	if decoded.Cmp(x) != 0 {
		t.Fatal()
	}
}

func MarshalPublicKey(pub *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

var badPublicKeyData = errors.New("cannot decode public key")

func UnmarshalPublicKey(b []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(Secp256k1(), b)
	if x == nil {
		return nil, badPublicKeyData
	}
	return &ecdsa.PublicKey{Curve: Secp256k1(), X: x, Y: y}, nil
}

func TestJsonEcdsaPublicKey(t *testing.T) {
	keys, _ := GenerateKey(rand.Reader)
	pub := &keys.PublicKey
	b := MarshalPublicKey(pub)

	newpub, _ := UnmarshalPublicKey(b)
	if (pub.X.Cmp(newpub.X) != 0) && (pub.Y.Cmp(newpub.Y) != 0) {
		t.Fatal()
	}
	newb := MarshalPublicKey(newpub)
	if bytes.Compare(b, newb) != 0 {
		t.Fatal()
	}
}

type Sessions map[ecdsa.PublicKey]*big.Int

func MarshalSessions(s Sessions) []byte {
	buffer := bytes.NewBufferString("{\n")
	length := len(s)
	count := 0
	for key, value := range s {
		bkey := MarshalPublicKey(&key)
		bvalue, _ := json.Marshal(value)
		buffer.WriteString(fmt.Sprintf("\"%x\": \"%x\"", bkey, bvalue))
		count++
		if count < length {
			buffer.WriteString(",")
		}
		buffer.WriteString("\n")
	}
	buffer.WriteString("}")
	return buffer.Bytes()
}

func UnmarshalSessions(b []byte) Sessions {
	stringsessions := make(map[string]string)
	out := make(Sessions)
	err := json.Unmarshal(b, &stringsessions)
	if err != nil {
		panic(err)
	}
	for key, value := range stringsessions {
		bpub, _ := hex.DecodeString(key)
		bnum, _ := hex.DecodeString(value)
		pub, _ := UnmarshalPublicKey(bpub)
		var num big.Int
		err := json.Unmarshal(bnum, &num)
		if err != nil {
			panic(err)
		}
		out[*pub] = &num
	}
	return out
}

func NewPublicKey() ecdsa.PublicKey {
	keys, _ := GenerateKey(rand.Reader)
	return keys.PublicKey
}

func TestMarshalSessions(t *testing.T) {
	s1 := make(Sessions)
	s1[NewPublicKey()] = new(big.Int).SetInt64(1111)
	s1[NewPublicKey()] = new(big.Int).SetInt64(2222)
	s1[NewPublicKey()] = new(big.Int).SetInt64(4444)
	b := MarshalSessions(s1)
	s2 := UnmarshalSessions(b)
	for key1, val1 := range s1 {
		Print(key1)
		Print(s1[key1])
		Print(s2[key1])
		if val2, ok := s2[key1]; ok {
			if val1.Cmp(val2) != 0 {
				t.Fatal()
			}
		} else {
			t.Fatal()
		}
	}
	Print(string(MarshalSessions(s2)))
	if bytes.Compare(b, MarshalSessions(s2)) != 0 {
		t.Fatal()
	}
}
