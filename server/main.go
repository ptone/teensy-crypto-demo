package main

import (
	"bufio"
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
	"os"

	"github.com/tarm/serial"
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
	//db client key lookup (mock for now?)

}

// Create a decrypting message parser
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
	// This would normally be looked up from a database based on the clientID sent
	clientPubStr := "967EB9873EF17E954C3D9CED62E36CD2281FC156E61A626D722D0DDB2548CF1C87665EDE3E001497BE7AC5614BE554D7E3A1D788DA6B516E94010179F9D3A394"
	pubKeyBytes, err := hex.DecodeString(clientPubStr)
	sk, err := ecdh(pubKeyBytes, m.privateKey)
	return sk, nil
}

// decode a message from client
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

	privateKey := "../keys/server/ec_private.pem"
	keyBytes, err := ioutil.ReadFile(privateKey)
	if err != nil {
		log.Fatal(err)
	}

	key, err := parseECPrivateKeyFromPEM(keyBytes)
	if err != nil {
		log.Fatal(err)
	}
	decoder, _ := NewMessageParser(key)

	c := &serial.Config{Name: "/dev/cu.usbmodem22398701", Baud: 9600}
	s, err := serial.OpenPort(c)
	if err != nil {
		log.Fatal(err)
	}

	r := bufio.NewReader(s)
	scanner := bufio.NewScanner(r)
	// TODO use SLIPMUX for packets instead of hex lines https://github.com/lobaro/slip
	for scanner.Scan() {
		cborbytes, err := hex.DecodeString(scanner.Text())
		m, err := decoder.Decode(cborbytes)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(m)
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}

}
