package mls

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// A KeyPackage provides some public information about a user, such as
// a supported protocol version and cipher suite, public keys, and credentials.
//
// Key packages should not be used more than once.
type KeyPackage struct {
	version     protocolVersion
	cipherSuite CipherSuite
	initKey     hpkePublicKey
	leafNode    leafNode
	extensions  []extension
	signature   []byte
}

// UnmarshalKeyPackage reads a key package encoded as an MLS message.
func UnmarshalKeyPackage(raw []byte) (*KeyPackage, error) {
	var msg mlsMessage
	if err := unmarshal(raw, &msg); err != nil {
		return nil, err
	} else if msg.wireFormat != wireFormatMLSKeyPackage {
		return nil, fmt.Errorf("mls: expected a key package message, got wire format %v", msg.wireFormat)
	}
	return msg.keyPackage, nil
}

// Bytes encodes the key package.
func (pkg *KeyPackage) Bytes() []byte {
	raw, err := marshal(&mlsMessage{
		version:    protocolVersionMLS10,
		wireFormat: wireFormatMLSKeyPackage,
		keyPackage: pkg,
	})
	if err != nil {
		// should never happen
		panic(fmt.Errorf("mls: failed to marshal key package message: %v", err))
	}
	return raw
}

func (pkg *KeyPackage) unmarshal(s *cryptobyte.String) error {
	*pkg = KeyPackage{}

	ok := s.ReadUint16((*uint16)(&pkg.version)) &&
		s.ReadUint16((*uint16)(&pkg.cipherSuite)) &&
		readOpaqueVec(s, (*[]byte)(&pkg.initKey))
	if !ok {
		return io.ErrUnexpectedEOF
	}

	if pkg.version != protocolVersionMLS10 {
		return fmt.Errorf("mls: invalid protocol version %d", pkg.version)
	}

	if err := pkg.leafNode.unmarshal(s); err != nil {
		return err
	}

	exts, err := unmarshalExtensionVec(s)
	if err != nil {
		return err
	}
	pkg.extensions = exts

	if !readOpaqueVec(s, &pkg.signature) {
		return err
	}

	return nil
}

func (pkg *KeyPackage) marshalTBS(b *cryptobyte.Builder) {
	b.AddUint16(uint16(pkg.version))
	b.AddUint16(uint16(pkg.cipherSuite))
	writeOpaqueVec(b, []byte(pkg.initKey))
	pkg.leafNode.marshal(b)
	marshalExtensionVec(b, pkg.extensions)
}

func (pkg *KeyPackage) marshal(b *cryptobyte.Builder) {
	pkg.marshalTBS(b)
	writeOpaqueVec(b, pkg.signature)
}

func (pkg *KeyPackage) sign(signerPriv []byte) error {
	var b cryptobyte.Builder
	pkg.marshalTBS(&b)
	rawTBS, err := b.Bytes()
	if err != nil {
		return err
	}

	sig, err := pkg.cipherSuite.signWithLabel(signerPriv, []byte("KeyPackageTBS"), rawTBS)
	if err != nil {
		return err
	}

	pkg.signature = sig
	return nil
}

func (pkg *KeyPackage) verifySignature() bool {
	var b cryptobyte.Builder
	pkg.marshalTBS(&b)
	rawTBS, err := b.Bytes()
	if err != nil {
		return false
	}

	return pkg.cipherSuite.verifyWithLabel(pkg.leafNode.signatureKey, []byte("KeyPackageTBS"), rawTBS, pkg.signature)
}

// verify performs KeyPackage verification as described in RFC 9420 section 10.1.
func (pkg *KeyPackage) verify(ctx *groupContext) error {
	if pkg.version != ctx.version {
		return fmt.Errorf("mls: key package version doesn't match group context")
	}
	if pkg.cipherSuite != ctx.cipherSuite {
		return fmt.Errorf("mls: cipher suite doesn't match group context")
	}
	if pkg.leafNode.leafNodeSource != leafNodeSourceKeyPackage {
		return fmt.Errorf("mls: key package contains a leaf node with an invalid source")
	}
	if !pkg.verifySignature() {
		return fmt.Errorf("mls: invalid key package signature")
	}
	if bytes.Equal(pkg.leafNode.encryptionKey, pkg.initKey) {
		return fmt.Errorf("mls: key package encryption key and init key are identical")
	}
	return nil
}

// GenerateRef generates this key package's reference.
func (pkg *KeyPackage) GenerateRef() (KeyPackageRef, error) {
	var b cryptobyte.Builder
	pkg.marshal(&b)
	raw, err := b.Bytes()
	if err != nil {
		return nil, err
	}

	hash, err := pkg.cipherSuite.refHash([]byte("MLS 1.0 KeyPackage Reference"), raw)
	if err != nil {
		return nil, err
	}

	return KeyPackageRef(hash), nil
}

// KeyPackageRef is a hash uniquely identifying a key package.
type KeyPackageRef []byte

// Equal checks whether two key package references are equal.
func (ref KeyPackageRef) Equal(other KeyPackageRef) bool {
	return bytes.Equal([]byte(ref), []byte(other))
}

// PrivateKeyPackage holds private information about a user.
type PrivateKeyPackage struct {
	InitKey       []byte
	EncryptionKey []byte
	SignatureKey  []byte
}

// KeyPairPackage holds both public and private information about a user.
type KeyPairPackage struct {
	Public  KeyPackage
	Private PrivateKeyPackage
}

// GenerateKeyPairPackage generates a new key pair package.
func GenerateKeyPairPackage(cs CipherSuite) (*KeyPairPackage, error) {
	// TODO: add options to configure the new key package

	initPub, initPriv, err := cs.generateEncryptionKeyPair()
	if err != nil {
		return nil, err
	}

	encPub, encPriv, err := cs.generateEncryptionKeyPair()
	if err != nil {
		return nil, err
	}

	sigPub, sigPriv, err := cs.signatureScheme().GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	keyPkg := KeyPackage{
		version:     protocolVersionMLS10,
		cipherSuite: cs,
		initKey:     initPub,
		leafNode: leafNode{
			encryptionKey:  encPub,
			signatureKey:   sigPub,
			leafNodeSource: leafNodeSourceKeyPackage,
			credential: Credential{
				credentialType: credentialTypeBasic,
				identity:       []byte{},
			},
			capabilities: capabilities{
				versions:     []protocolVersion{protocolVersionMLS10},
				cipherSuites: []CipherSuite{cs},
				extensions:   []extensionType{extensionTypeRatchetTree},
				proposals:    []proposalType{proposalTypeAdd, proposalTypeUpdate, proposalTypeRemove},
				credentials:  []credentialType{credentialTypeBasic},
			},
			lifetime: newLifetime(time.Now(), time.Now().Add(30*24*time.Hour)),
		},
	}

	if err := keyPkg.leafNode.sign(cs, nil, 0, sigPriv); err != nil {
		return nil, fmt.Errorf("failed to sign leaf node: %v", err)
	}
	if err := keyPkg.sign(sigPriv); err != nil {
		return nil, fmt.Errorf("failed to sign key package: %v", err)
	}

	return &KeyPairPackage{
		Public: keyPkg,
		Private: PrivateKeyPackage{
			InitKey:       initPriv,
			EncryptionKey: encPriv,
			SignatureKey:  sigPriv,
		},
	}, nil
}
