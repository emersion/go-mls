package mls

import (
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

type keyPackageRef []byte
