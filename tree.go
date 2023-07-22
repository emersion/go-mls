package mls

import (
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

type parentNode struct {
	encryptionKey  hpkePublicKey
	parentHash     []byte
	unmergedLeaves []uint32
}

func (node *parentNode) unmarshal(s *cryptobyte.String) error {
	*node = parentNode{}
	if !readOpaqueVec(s, (*[]byte)(&node.encryptionKey)) || !readOpaqueVec(s, &node.parentHash) {
		return io.ErrUnexpectedEOF
	}
	return readVector(s, func(s *cryptobyte.String) error {
		var i uint32
		if !s.ReadUint32(&i) {
			return io.ErrUnexpectedEOF
		}
		node.unmergedLeaves = append(node.unmergedLeaves, i)
		return nil
	})
}

type leafNodeSource uint8

const (
	leafNodeSourceKeyPackage leafNodeSource = 1
	leafNodeSourceUpdate     leafNodeSource = 2
	leafNodeSourceCommit     leafNodeSource = 3
)

func (src *leafNodeSource) unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint8((*uint8)(src)) {
		return io.ErrUnexpectedEOF
	}
	switch *src {
	case leafNodeSourceKeyPackage, leafNodeSourceUpdate, leafNodeSourceCommit:
		return nil
	default:
		return fmt.Errorf("mls: invalid leaf node source %d", *src)
	}
}

type capabilities struct {
	versions     []protocolVersion
	cipherSuites []cipherSuite
	extensions   []extensionType
	proposals    []proposalType
	credentials  []credentialType
}

func (caps *capabilities) unmarshal(s *cryptobyte.String) error {
	*caps = capabilities{}

	// Note: all unknown values here must be ignored

	err := readVector(s, func(s *cryptobyte.String) error {
		var ver protocolVersion
		if !s.ReadUint16((*uint16)(&ver)) {
			return io.ErrUnexpectedEOF
		}
		caps.versions = append(caps.versions, ver)
		return nil
	})
	if err != nil {
		return err
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
		return err
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
		return err
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
		return err
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
		return err
	}

	return nil
}

type lifetime struct {
	notBefore, notAfter uint64
}

func (lt *lifetime) unmarshal(s *cryptobyte.String) error {
	*lt = lifetime{}
	if !s.ReadUint64(&lt.notBefore) || !s.ReadUint64(&lt.notAfter) {
		return io.ErrUnexpectedEOF
	}
	return nil
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

func (node *leafNode) unmarshal(s *cryptobyte.String) error {
	*node = leafNode{}

	if !readOpaqueVec(s, (*[]byte)(&node.encryptionKey)) || !readOpaqueVec(s, (*[]byte)(&node.signatureKey)) {
		return io.ErrUnexpectedEOF
	}

	if err := node.credential.unmarshal(s); err != nil {
		return err
	}
	if err := node.capabilities.unmarshal(s); err != nil {
		return err
	}
	if err := node.leafNodeSource.unmarshal(s); err != nil {
		return err
	}

	var err error
	switch node.leafNodeSource {
	case leafNodeSourceKeyPackage:
		node.lifetime = new(lifetime)
		err = node.lifetime.unmarshal(s)
	case leafNodeSourceCommit:
		if !readOpaqueVec(s, &node.parentHash) {
			err = io.ErrUnexpectedEOF
		}
	}
	if err != nil {
		return err
	}

	exts, err := unmarshalExtensionVec(s)
	if err != nil {
		return err
	}
	node.extensions = exts

	if !readOpaqueVec(s, &node.signature) {
		return io.ErrUnexpectedEOF
	}

	return nil
}

type hpkeCiphertext struct {
	kemOutput  []byte
	ciphertext []byte
}

func (hpke *hpkeCiphertext) unmarshal(s *cryptobyte.String) error {
	*hpke = hpkeCiphertext{}
	if !readOpaqueVec(s, &hpke.kemOutput) || !readOpaqueVec(s, &hpke.ciphertext) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

type updatePathNode struct {
	encryptionKey       hpkePublicKey
	encryptedPathSecret []hpkeCiphertext
}

func (node *updatePathNode) unmarshal(s *cryptobyte.String) error {
	*node = updatePathNode{}

	if !readOpaqueVec(s, (*[]byte)(&node.encryptionKey)) {
		return io.ErrUnexpectedEOF
	}

	return readVector(s, func(s *cryptobyte.String) error {
		var ciphertext hpkeCiphertext
		if err := ciphertext.unmarshal(s); err != nil {
			return err
		}
		node.encryptedPathSecret = append(node.encryptedPathSecret, ciphertext)
		return nil
	})
}

type updatePath struct {
	leafNode leafNode
	nodes    []updatePathNode
}

func (up *updatePath) unmarshal(s *cryptobyte.String) error {
	*up = updatePath{}

	if err := up.leafNode.unmarshal(s); err != nil {
		return err
	}

	return readVector(s, func(s *cryptobyte.String) error {
		var node updatePathNode
		if err := node.unmarshal(s); err != nil {
			return err
		}
		up.nodes = append(up.nodes, node)
		return nil
	})
}

type nodeType uint8

const (
	nodeTypeLeaf   nodeType = 1
	nodeTypeParent nodeType = 2
)

func (t *nodeType) unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint8((*uint8)(t)) {
		return io.ErrUnexpectedEOF
	}
	switch *t {
	case nodeTypeLeaf, nodeTypeParent:
		return nil
	default:
		return fmt.Errorf("mls: invalid node type %d", *t)
	}
}

type node struct {
	nodeType   nodeType
	leafNode   *leafNode   // for nodeTypeLeaf
	parentNode *parentNode // for nodeTypeParent
}

func (n *node) unmarshal(s *cryptobyte.String) error {
	*n = node{}

	if err := n.nodeType.unmarshal(s); err != nil {
		return err
	}

	switch n.nodeType {
	case nodeTypeLeaf:
		n.leafNode = new(leafNode)
		return n.leafNode.unmarshal(s)
	case nodeTypeParent:
		n.parentNode = new(parentNode)
		return n.parentNode.unmarshal(s)
	default:
		panic("unreachable")
	}
}

type ratchetTree []*node

func (tree *ratchetTree) unmarshal(s *cryptobyte.String) error {
	*tree = ratchetTree{}
	return readVector(s, func(s *cryptobyte.String) error {
		var n *node
		var hasNode bool
		if !readOptional(s, &hasNode) {
			return io.ErrUnexpectedEOF
		} else if hasNode {
			n = new(node)
			if err := n.unmarshal(s); err != nil {
				return err
			}
		}
		*tree = append(*tree, n)
		return nil
	})
}
