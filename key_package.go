package mls

import (
	"bytes"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

type keyPackage struct {
	version     protocolVersion
	cipherSuite cipherSuite
	initKey     hpkePublicKey
	leafNode    leafNode
	extensions  []extension
	signature   []byte
}

func (pkg *keyPackage) unmarshal(s *cryptobyte.String) error {
	*pkg = keyPackage{}

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

func (pkg *keyPackage) marshal(b *cryptobyte.Builder) {
	b.AddUint16(uint16(pkg.version))
	b.AddUint16(uint16(pkg.cipherSuite))
	writeOpaqueVec(b, []byte(pkg.initKey))
	pkg.leafNode.marshal(b)
	marshalExtensionVec(b, pkg.extensions)
	writeOpaqueVec(b, pkg.signature)
}

func (pkg *keyPackage) generateRef() (keyPackageRef, error) {
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
