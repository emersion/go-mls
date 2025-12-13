package mls

import (
	"bytes"
	"fmt"
	"io"

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

func (pkg *KeyPackage) unmarshal(s *cryptobyte.String) error {
	*pkg = KeyPackage{}

	ok := s.ReadUint16((*uint16)(&pkg.version)) &&
		s.ReadUint16((*uint16)(&pkg.cipherSuite)) &&
		readOpaqueVec(s, (*[]byte)(&pkg.initKey))
	if !ok {
		return io.ErrUnexpectedEOF
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

func (pkg *KeyPackage) generateRef() (keyPackageRef, error) {
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

	return keyPackageRef(hash), nil
}

type keyPackageRef []byte

func (ref keyPackageRef) Equal(other keyPackageRef) bool {
	return bytes.Equal([]byte(ref), []byte(other))
}
