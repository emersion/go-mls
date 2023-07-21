package mls

import (
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

type leafNodeSource uint8

const (
	leafNodeSourceKeyPackage leafNodeSource = 1
	leafNodeSourceUpdate     leafNodeSource = 2
	leafNodeSourceCommit     leafNodeSource = 3
)

type capabilities struct {
	versions     []protocolVersion
	cipherSuites []cipherSuite
	extensions   []extensionType
	proposals    []proposalType
	credentials  []credentialType
}

func unmarshalCapabilities(s *cryptobyte.String) (*capabilities, error) {
	var caps capabilities

	err := readVector(s, func(s *cryptobyte.String) error {
		var ver protocolVersion
		if !s.ReadUint16((*uint16)(&ver)) {
			return io.ErrUnexpectedEOF
		}
		caps.versions = append(caps.versions, ver)
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = readVector(s, func(s *cryptobyte.String) error {
		var cs cipherSuite
		if !s.ReadUint16((*uint16)(&cs)) {
			return io.ErrUnexpectedEOF
		}
		caps.cipherSuites = append(caps.cipherSuites, cs)
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = readVector(s, func(s *cryptobyte.String) error {
		var et extensionType
		if !s.ReadUint16((*uint16)(&et)) {
			return io.ErrUnexpectedEOF
		}
		caps.extensions = append(caps.extensions, et)
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = readVector(s, func(s *cryptobyte.String) error {
		var pt proposalType
		if !s.ReadUint16((*uint16)(&pt)) {
			return io.ErrUnexpectedEOF
		}
		caps.proposals = append(caps.proposals, pt)
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = readVector(s, func(s *cryptobyte.String) error {
		var ct credentialType
		if !s.ReadUint16((*uint16)(&ct)) {
			return io.ErrUnexpectedEOF
		}
		caps.credentials = append(caps.credentials, ct)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &caps, nil
}

type lifetime struct {
	notBefore, notAfter uint64
}

func unmarshalLifetime(s *cryptobyte.String) (*lifetime, error) {
	var lifetime lifetime
	if !s.ReadUint64(&lifetime.notBefore) || !s.ReadUint64(&lifetime.notAfter) {
		return nil, io.ErrUnexpectedEOF
	}
	return &lifetime, nil
}

type extensionType uint16

// http://www.iana.org/assignments/mls/mls.xhtml#mls-extension-types
const (
	extensionTypeApplicationID        extensionType = 0x0001
	extensionTypeRatchetTree          extensionType = 0x0002
	extensionTypeRequiredCapabilities extensionType = 0x0003
	extensionTypeExternalPub          extensionType = 0x0004
	extensionTypeExternalSenders      extensionType = 0x0005
)

type extension struct {
	extensionType extensionType
	extensionData []byte
}

func unmarshalExtensionVec(s *cryptobyte.String) ([]extension, error) {
	var exts []extension
	err := readVector(s, func(s *cryptobyte.String) error {
		var ext extension
		if !s.ReadUint16((*uint16)(&ext.extensionType)) || !readOpaqueVec(s, &ext.extensionData) {
			return io.ErrUnexpectedEOF
		}
		exts = append(exts, ext)
		return nil
	})
	return exts, err
}

type leafNode struct {
	encryptionKey hpkePublicKey
	signatureKey  signaturePublicKey
	credential    credential
	capabilities  capabilities

	leafNodeSource leafNodeSource
	lifetime       *lifetime // for leafNodeSourceKeyPackage
	parentHash     []byte    // for leafNodeSourceCommit

	extensions []extension
	signature  []byte
}

func unmarshalLeafNode(s *cryptobyte.String) (*leafNode, error) {
	var node leafNode

	if !readOpaqueVec(s, (*[]byte)(&node.encryptionKey)) || !readOpaqueVec(s, (*[]byte)(&node.signatureKey)) {
		return nil, io.ErrUnexpectedEOF
	}

	cred, err := unmarshalCredential(s)
	if err != nil {
		return nil, err
	}
	node.credential = *cred

	caps, err := unmarshalCapabilities(s)
	if err != nil {
		return nil, err
	}
	node.capabilities = *caps

	if !s.ReadUint8((*uint8)(&node.leafNodeSource)) {
		return nil, io.ErrUnexpectedEOF
	}

	switch node.leafNodeSource {
	case leafNodeSourceKeyPackage:
		node.lifetime, err = unmarshalLifetime(s)
	case leafNodeSourceUpdate:
		// nothing to do
	case leafNodeSourceCommit:
		if !readOpaqueVec(s, &node.parentHash) {
			err = io.ErrUnexpectedEOF
		}
	default:
		err = fmt.Errorf("mls: invalid leaf node source %d", node.leafNodeSource)
	}
	if err != nil {
		return nil, err
	}

	exts, err := unmarshalExtensionVec(s)
	if err != nil {
		return nil, err
	}
	node.extensions = exts

	if !readOpaqueVec(s, &node.signature) {
		return nil, io.ErrUnexpectedEOF
	}

	return &node, nil
}

type hpkeCiphertext struct {
	kemOutput  []byte
	ciphertext []byte
}

func unmarshalHPKECiphertext(s *cryptobyte.String) (*hpkeCiphertext, error) {
	var hpke hpkeCiphertext
	if !readOpaqueVec(s, &hpke.kemOutput) || !readOpaqueVec(s, &hpke.ciphertext) {
		return nil, io.ErrUnexpectedEOF
	}
	return &hpke, nil
}
