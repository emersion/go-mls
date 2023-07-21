package mls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/sign/ed448"
	"golang.org/x/crypto/cryptobyte"
)

type cipherSuite uint16

const (
	cipherSuiteMLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519        cipherSuite = 0x0001
	cipherSuiteMLS_128_DHKEMP256_AES128GCM_SHA256_P256             cipherSuite = 0x0002
	cipherSuiteMLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 cipherSuite = 0x0003
	cipherSuiteMLS_256_DHKEMX448_AES256GCM_SHA512_Ed448            cipherSuite = 0x0004
	cipherSuiteMLS_256_DHKEMP521_AES256GCM_SHA512_P521             cipherSuite = 0x0005
	cipherSuiteMLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448     cipherSuite = 0x0006
	cipherSuiteMLS_256_DHKEMP384_AES256GCM_SHA384_P384             cipherSuite = 0x0007
)

func (cs cipherSuite) hash() crypto.Hash {
	switch cs {
	case cipherSuiteMLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519:
		return crypto.SHA256
	case cipherSuiteMLS_128_DHKEMP256_AES128GCM_SHA256_P256:
		return crypto.SHA256
	case cipherSuiteMLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519:
		return crypto.SHA256
	case cipherSuiteMLS_256_DHKEMX448_AES256GCM_SHA512_Ed448:
		return crypto.SHA512
	case cipherSuiteMLS_256_DHKEMP521_AES256GCM_SHA512_P521:
		return crypto.SHA512
	case cipherSuiteMLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448:
		return crypto.SHA512
	case cipherSuiteMLS_256_DHKEMP384_AES256GCM_SHA384_P384:
		return crypto.SHA384
	}
	panic(fmt.Errorf("mls: invalid cipher suite %d", cs))
}

func (cs cipherSuite) hpke() hpke.Suite {
	switch cs {
	case cipherSuiteMLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519:
		return hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	case cipherSuiteMLS_128_DHKEMP256_AES128GCM_SHA256_P256:
		return hpke.NewSuite(hpke.KEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	case cipherSuiteMLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519:
		return hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305)
	case cipherSuiteMLS_256_DHKEMX448_AES256GCM_SHA512_Ed448:
		return hpke.NewSuite(hpke.KEM_X448_HKDF_SHA512, hpke.KDF_HKDF_SHA512, hpke.AEAD_AES256GCM)
	case cipherSuiteMLS_256_DHKEMP521_AES256GCM_SHA512_P521:
		return hpke.NewSuite(hpke.KEM_P521_HKDF_SHA512, hpke.KDF_HKDF_SHA512, hpke.AEAD_AES256GCM)
	case cipherSuiteMLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448:
		return hpke.NewSuite(hpke.KEM_X448_HKDF_SHA512, hpke.KDF_HKDF_SHA512, hpke.AEAD_ChaCha20Poly1305)
	case cipherSuiteMLS_256_DHKEMP384_AES256GCM_SHA384_P384:
		return hpke.NewSuite(hpke.KEM_P384_HKDF_SHA384, hpke.KDF_HKDF_SHA384, hpke.AEAD_AES256GCM)
	}
	panic(fmt.Errorf("mls: invalid cipher suite %d", cs))
}

func (cs cipherSuite) signatureScheme() signatureScheme {
	switch cs {
	case cipherSuiteMLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519:
		return ed25519SignatureScheme{}
	case cipherSuiteMLS_128_DHKEMP256_AES128GCM_SHA256_P256:
		return ecdsaSignatureScheme{elliptic.P256(), crypto.SHA256}
	case cipherSuiteMLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519:
		return ed25519SignatureScheme{}
	case cipherSuiteMLS_256_DHKEMX448_AES256GCM_SHA512_Ed448:
		return ed448SignatureScheme{}
	case cipherSuiteMLS_256_DHKEMP521_AES256GCM_SHA512_P521:
		return ecdsaSignatureScheme{elliptic.P521(), crypto.SHA512}
	case cipherSuiteMLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448:
		return ed448SignatureScheme{}
	case cipherSuiteMLS_256_DHKEMP384_AES256GCM_SHA384_P384:
		return ecdsaSignatureScheme{elliptic.P384(), crypto.SHA384}
	}
	panic(fmt.Errorf("mls: invalid cipher suite %d", cs))
}

func (cs cipherSuite) refHash(label, value []byte) ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	writeOpaque(b, label)
	writeOpaque(b, value)
	in, err := b.Bytes()
	if err != nil {
		return nil, err
	}

	h := cs.hash().New()
	h.Write(in)
	return h.Sum(nil), nil
}

func (cs cipherSuite) expandWithLabel(secret, label, context []byte, length uint16) ([]byte, error) {
	label = append([]byte("MLS 1.0 "), label...)

	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(length)
	writeOpaque(b, label)
	writeOpaque(b, context)
	kdfLabel, err := b.Bytes()
	if err != nil {
		return nil, err
	}

	_, kdf, _ := cs.hpke().Params()
	return kdf.Expand(secret, kdfLabel, uint(length)), nil
}

func (cs cipherSuite) deriveSecret(secret, label []byte) ([]byte, error) {
	_, kdf, _ := cs.hpke().Params()
	return cs.expandWithLabel(secret, label, nil, uint16(kdf.ExtractSize()))
}

func (cs cipherSuite) deriveTreeSecret(secret, label []byte, generation uint32, length uint16) ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint32(generation)
	return cs.expandWithLabel(secret, label, b.BytesOrPanic(), length)
}

func (cs cipherSuite) signWithLabel(signKey, label, content []byte) ([]byte, error) {
	signContent, err := marshalSignContent(label, content)
	if err != nil {
		return nil, err
	}

	return cs.signatureScheme().Sign(signKey, signContent)
}

func (cs cipherSuite) verifyWithLabel(verifKey, label, content, signValue []byte) bool {
	signContent, err := marshalSignContent(label, content)
	if err != nil {
		return false
	}

	return cs.signatureScheme().Verify(verifKey, signContent, signValue)
}

func (cs cipherSuite) encryptWithLabel(publicKey, label, context, plaintext []byte) (kemOutput, ciphertext []byte, err error) {
	encryptContext, err := marshalEncryptContext(label, context)
	if err != nil {
		return nil, nil, err
	}

	hpke := cs.hpke()
	kem, _, _ := hpke.Params()
	pub, err := kem.Scheme().UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}

	sender, err := hpke.NewSender(pub, encryptContext)
	if err != nil {
		return nil, nil, err
	}

	kemOutput, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	ciphertext, err = sealer.Seal(plaintext, nil)
	return kemOutput, ciphertext, err
}

func (cs cipherSuite) decryptWithLabel(privateKey, label, context, kemOutput, ciphertext []byte) ([]byte, error) {
	encryptContext, err := marshalEncryptContext(label, context)
	if err != nil {
		return nil, err
	}

	hpke := cs.hpke()
	kem, _, _ := hpke.Params()
	priv, err := kem.Scheme().UnmarshalBinaryPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	receiver, err := hpke.NewReceiver(priv, encryptContext)
	if err != nil {
		return nil, err
	}

	opener, err := receiver.Setup(kemOutput)
	if err != nil {
		return nil, err
	}

	return opener.Open(ciphertext, nil)
}

func marshalSignContent(label, content []byte) ([]byte, error) {
	label = append([]byte("MLS 1.0 "), label...)

	b := cryptobyte.NewBuilder(nil)
	writeOpaque(b, label)
	writeOpaque(b, content)
	return b.Bytes()
}

func marshalEncryptContext(label, context []byte) ([]byte, error) {
	label = append([]byte("MLS 1.0 "), label...)

	b := cryptobyte.NewBuilder(nil)
	writeOpaque(b, label)
	writeOpaque(b, context)
	return b.Bytes()
}

type signatureScheme interface {
	Sign(signKey, message []byte) ([]byte, error)
	Verify(publicKey, message, sig []byte) bool
}

type ed25519SignatureScheme struct{}

func (ed25519SignatureScheme) Sign(signKey, message []byte) ([]byte, error) {
	if len(signKey) != ed25519.SeedSize {
		return nil, fmt.Errorf("mls: invalid Ed25519 private key size")
	}
	priv := ed25519.NewKeyFromSeed(signKey)
	return ed25519.Sign(priv, message), nil
}

func (ed25519SignatureScheme) Verify(publicKey, message, sig []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), message, sig)
}

type ecdsaSignatureScheme struct {
	curve elliptic.Curve
	hash  crypto.Hash
}

func (scheme ecdsaSignatureScheme) hashSum(message []byte) []byte {
	h := scheme.hash.New()
	h.Write(message)
	return h.Sum(nil)
}

func (scheme ecdsaSignatureScheme) Sign(signKey, message []byte) ([]byte, error) {
	d := new(big.Int).SetBytes(signKey)
	x, y := scheme.curve.ScalarBaseMult(signKey)
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: scheme.curve, X: x, Y: y},
		D:         d,
	}
	return ecdsa.SignASN1(rand.Reader, priv, scheme.hashSum(message))
}

func (scheme ecdsaSignatureScheme) Verify(publicKey, message, sig []byte) bool {
	x, y := elliptic.Unmarshal(scheme.curve, publicKey)
	pub := &ecdsa.PublicKey{Curve: scheme.curve, X: x, Y: y}
	return ecdsa.VerifyASN1(pub, scheme.hashSum(message), sig)
}

type ed448SignatureScheme struct{}

func (ed448SignatureScheme) Sign(signKey, message []byte) ([]byte, error) {
	if len(signKey) != ed448.SeedSize {
		return nil, fmt.Errorf("mls: invalid Ed448 private key size")
	}
	priv := ed448.NewKeyFromSeed(signKey)
	return ed448.Sign(priv, message, ""), nil
}

func (ed448SignatureScheme) Verify(publicKey, message, sig []byte) bool {
	if len(publicKey) != ed448.PublicKeySize {
		return false
	}
	return ed448.Verify(ed448.PublicKey(publicKey), message, sig, "")
}
