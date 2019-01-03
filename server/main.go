package main

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"strings"

	"github.com/ugorji/go/codec"

	"golang.org/x/crypto/chacha20poly1305"
)

func ecdh(pubBytes []byte, privBytes []byte) (shared []byte, err error) {
	var curve = elliptic.P256
	//create the ecdsa pub/priv key types
	kb := new(big.Int)
	kb.SetBytes(privBytes)

	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = curve()
	priv.D = kb
	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(kb.Bytes())

	pubX := new(big.Int)
	pubY := new(big.Int)
	// TODO verify these are the right order of ranges for X/Y
	pubX.SetBytes(pubBytes[:32])
	pubY.SetBytes(pubBytes[32:])

	// pubY.SetBytes(pubBytes[:32])
	// pubX.SetBytes(pubBytes[32:])

	pub := new(ecdsa.PublicKey)
	pub.Curve = curve()
	pub.X = pubX
	pub.Y = pubY
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		log.Fatal("invalid public key")
	}

	x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	if x == nil {
		return shared, errors.New("Failed to generate encryption key")
	}
	shared = x.Bytes()
	return shared, nil
}

type MessageParser struct {
	cborHandle codec.CborHandle
	privateKey []byte
	chacha     cipher.AEAD //actually may not be able to easily reuse
	// TODO
	// client-keys  cacheMap of client id to shared key (should this actually be the map of chachas? more memory overhead)
	//firestore client (mock for now?)

}

func NewMessageParser(key []byte) (m *MessageParser, err error) {
	m = &MessageParser{privateKey: key}
	return m, nil
}

func (m *MessageParser) decodeCbor(msg []byte) (data map[string]interface{}, err error) {
	// func (m *MessageParser) Process() {
	dec := codec.NewDecoderBytes(msg, &m.cborHandle)
	data = make(map[string]interface{})
	// TODO note default cbor encoding uses uint64 for integers, which firestore golang
	// SDK does not handle for ambiguity reasons in Firestore itself.
	err = dec.Decode(data)
	return data, nil
}

func (m *MessageParser) getClientDecrypt(clientID []byte) (secret []byte, err error) {
	// get publickey
	clientPubStr := "96:7e:b9:87:3e:f1:7e:95:4c:3d:9c:ed:62:e3:6c:d2:28:1f:c1:56:e6:1a:62:6d:72:2d:0d:db:25:48:cf:1c:87:66:5e:de:3e:00:14:97:be:7a:c5:61:4b:e5:54:d7:e3:a1:d7:88:da:6b:51:6e:94:01:01:79:f9:d3:a3:94"

	clientPubStr = strings.Replace(clientPubStr, ":", "", -1)
	pubKeyBytes, err := hex.DecodeString(clientPubStr)
	sk, err := ecdh(pubKeyBytes, m.privateKey)
	return sk, nil
}

func (m *MessageParser) Decode(msg []byte) (data map[string]interface{}, err error) {
	parsedMsg, err := m.decodeCbor(msg)
	if err != nil {
		return nil, err
	}
	sk, err := m.getClientDecrypt(parsedMsg["a"].([]byte))
	if err != nil {
		return nil, err
	}
	chacha, err := chacha20poly1305.New(sk[:])
	if err != nil {
		return nil, err
	}
	plaintext, err := chacha.Open(nil, parsedMsg["n"].([]byte), parsedMsg["c"].([]byte), parsedMsg["a"].([]byte))
	if err != nil {
		return nil, err
	}
	parsedPayload, err := m.decodeCbor(plaintext)
	if err != nil {
		return nil, err
	}
	return parsedPayload, err
}

func parseECPrivateKeyFromPEM(key []byte) ([]byte, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, errors.New("key must be PEM encoded")
	}

	// Parse the key
	var parsedKey *ecdsa.PrivateKey
	if parsedKey, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
		return nil, err
	}
	return parsedKey.D.Bytes(), nil
}

func main() {
	hexmsg := "A4 61 74 01 61 6E 4C 73 D7 B8 A0 D7 00 4B 16 79 72 CF E7 61 61 44 01 01 01 01 61 63 5F 4B 61 98 AC 1F F5 B6 CD CF 88 28 5A 50 EF 75 14 04 55 A6 84 D9 A8 4C AB 97 50 A5 7B E0 FF"
	hexmsg = strings.Replace(hexmsg, " ", "", -1)
	cborbytes, err := hex.DecodeString(hexmsg)
	if err != nil {
		log.Fatal("decode failed")
	}

	privateKey := "/Users/ptone/dev/tiny-crypto/keys/server/ec_private.pem"
	keyBytes, err := ioutil.ReadFile(privateKey)
	if err != nil {
		log.Fatal(err)
	}

	key, err := parseECPrivateKeyFromPEM(keyBytes)
	if err != nil {
		log.Fatal(err)
	}
	decoder, _ := NewMessageParser(key)

	m, err := decoder.Decode(cborbytes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(m)
}
