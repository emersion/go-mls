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

func unmarshalKeyPackage(s *cryptobyte.String) (*keyPackage, error) {
	var pkg keyPackage
	ok := s.ReadUint16((*uint16)(&pkg.version)) &&
		s.ReadUint16((*uint16)(&pkg.cipherSuite)) &&
		readOpaque(s, (*[]byte)(&pkg.initKey))
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}

	leafNode, err := unmarshalLeafNode(s)
	if err != nil {
		return nil, err
	}
	pkg.leafNode = *leafNode

	exts, err := unmarshalExtensionVec(s)
	if err != nil {
		return nil, err
	}
	pkg.extensions = exts

	if !readOpaque(s, &pkg.signature) {
		return nil, err
	}

	return &pkg, nil
}

type keyPackageRef []byte
