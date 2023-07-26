package mls

import (
	"bytes"
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

type parentNode struct {
	encryptionKey  hpkePublicKey
	parentHash     []byte
	unmergedLeaves []leafIndex
}

func (node *parentNode) unmarshal(s *cryptobyte.String) error {
	*node = parentNode{}
	if !readOpaqueVec(s, (*[]byte)(&node.encryptionKey)) || !readOpaqueVec(s, &node.parentHash) {
		return io.ErrUnexpectedEOF
	}
	return readVector(s, func(s *cryptobyte.String) error {
		var i leafIndex
		if !s.ReadUint32((*uint32)(&i)) {
			return io.ErrUnexpectedEOF
		}
		node.unmergedLeaves = append(node.unmergedLeaves, i)
		return nil
	})
}

func (node *parentNode) marshal(b *cryptobyte.Builder) {
	writeOpaqueVec(b, []byte(node.encryptionKey))
	writeOpaqueVec(b, node.parentHash)
	writeVector(b, len(node.unmergedLeaves), func(b *cryptobyte.Builder, i int) {
		b.AddUint32(uint32(node.unmergedLeaves[i]))
	})
}

func (node *parentNode) computeParentHash(cs cipherSuite, originalSiblingTreeHash []byte) ([]byte, error) {
	rawInput, err := marshalParentHashInput(node.encryptionKey, node.parentHash, originalSiblingTreeHash)
	if err != nil {
		return nil, err
	}
	h := cs.hash().New()
	h.Write(rawInput)
	return h.Sum(nil), nil
}

func marshalParentHashInput(encryptionKey hpkePublicKey, parentHash, originalSiblingTreeHash []byte) ([]byte, error) {
	var b cryptobyte.Builder
	writeOpaqueVec(&b, []byte(encryptionKey))
	writeOpaqueVec(&b, parentHash)
	writeOpaqueVec(&b, originalSiblingTreeHash)
	return b.Bytes()
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

func (src leafNodeSource) marshal(b *cryptobyte.Builder) {
	b.AddUint8(uint8(src))
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

func (caps *capabilities) marshal(b *cryptobyte.Builder) {
	writeVector(b, len(caps.versions), func(b *cryptobyte.Builder, i int) {
		b.AddUint16(uint16(caps.versions[i]))
	})

	writeVector(b, len(caps.cipherSuites), func(b *cryptobyte.Builder, i int) {
		b.AddUint16(uint16(caps.cipherSuites[i]))
	})

	writeVector(b, len(caps.extensions), func(b *cryptobyte.Builder, i int) {
		b.AddUint16(uint16(caps.extensions[i]))
	})

	writeVector(b, len(caps.proposals), func(b *cryptobyte.Builder, i int) {
		b.AddUint16(uint16(caps.proposals[i]))
	})

	writeVector(b, len(caps.credentials), func(b *cryptobyte.Builder, i int) {
		b.AddUint16(uint16(caps.credentials[i]))
	})
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

func (lt *lifetime) marshal(b *cryptobyte.Builder) {
	b.AddUint64(lt.notBefore)
	b.AddUint64(lt.notAfter)
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

func marshalExtensionVec(b *cryptobyte.Builder, exts []extension) {
	writeVector(b, len(exts), func(b *cryptobyte.Builder, i int) {
		ext := exts[i]
		b.AddUint16(uint16(ext.extensionType))
		writeOpaqueVec(b, ext.extensionData)
	})
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

func (node *leafNode) marshalBase(b *cryptobyte.Builder) {
	writeOpaqueVec(b, []byte(node.encryptionKey))
	writeOpaqueVec(b, []byte(node.signatureKey))
	node.credential.marshal(b)
	node.capabilities.marshal(b)
	node.leafNodeSource.marshal(b)
	switch node.leafNodeSource {
	case leafNodeSourceKeyPackage:
		node.lifetime.marshal(b)
	case leafNodeSourceCommit:
		writeOpaqueVec(b, node.parentHash)
	}
	marshalExtensionVec(b, node.extensions)
}

func (node *leafNode) marshal(b *cryptobyte.Builder) {
	node.marshalBase(b)
	writeOpaqueVec(b, []byte(node.signature))
}

type leafNodeTBS struct {
	*leafNode

	// for leafNodeSourceUpdate and leafNodeSourceCommit
	groupID   GroupID
	leafIndex leafIndex
}

func (node *leafNodeTBS) marshal(b *cryptobyte.Builder) {
	node.leafNode.marshalBase(b)
	switch node.leafNode.leafNodeSource {
	case leafNodeSourceUpdate, leafNodeSourceCommit:
		writeOpaqueVec(b, []byte(node.groupID))
		b.AddUint32(uint32(node.leafIndex))
	}
}

func (node *leafNode) verifySignature(cs cipherSuite, groupID GroupID, li leafIndex) bool {
	leafNodeTBS, err := marshal(&leafNodeTBS{
		leafNode:  node,
		groupID:   groupID,
		leafIndex: li,
	})
	if err != nil {
		return false
	}
	return cs.verifyWithLabel([]byte(node.signatureKey), []byte("LeafNodeTBS"), leafNodeTBS, node.signature)
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

func (node *updatePathNode) marshal(b *cryptobyte.Builder) {
	writeOpaqueVec(b, []byte(node.encryptionKey))
	writeVector(b, len(node.encryptedPathSecret), func(b *cryptobyte.Builder, i int) {
		node.encryptedPathSecret[i].marshal(b)
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

func (up *updatePath) marshal(b *cryptobyte.Builder) {
	up.leafNode.marshal(b)
	writeVector(b, len(up.nodes), func(b *cryptobyte.Builder, i int) {
		up.nodes[i].marshal(b)
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

func (t nodeType) marshal(b *cryptobyte.Builder) {
	b.AddUint8(uint8(t))
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

func (n *node) marshal(b *cryptobyte.Builder) {
	n.nodeType.marshal(b)
	switch n.nodeType {
	case nodeTypeLeaf:
		n.leafNode.marshal(b)
	case nodeTypeParent:
		n.parentNode.marshal(b)
	default:
		panic("unreachable")
	}
}

type ratchetTree []*node

func (tree *ratchetTree) unmarshal(s *cryptobyte.String) error {
	*tree = ratchetTree{}
	err := readVector(s, func(s *cryptobyte.String) error {
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
	if err != nil {
		return err
	}

	// The raw tree doesn't include blank nodes at the end, fill it until next
	// power of 2
	for !isPowerOf2(uint32(len(*tree) + 1)) {
		*tree = append(*tree, nil)
	}

	return nil
}

func (tree ratchetTree) marshal(b *cryptobyte.Builder) {
	end := len(tree)
	for end > 0 && tree[end-1] == nil {
		end--
	}

	writeVector(b, len(tree[:end]), func(b *cryptobyte.Builder, i int) {
		n := tree[i]
		writeOptional(b, n != nil)
		if n != nil {
			n.marshal(b)
		}
	})
}

// get returns the node at the provided index.
//
// nil is returned for blank nodes. get panics if the index is out of range.
func (tree ratchetTree) get(i nodeIndex) *node {
	return tree[int(i)]
}

func (tree ratchetTree) set(i nodeIndex, node *node) {
	tree[int(i)] = node
}

func (tree ratchetTree) getLeaf(li leafIndex) *leafNode {
	node := tree.get(li.nodeIndex())
	if node == nil {
		return nil
	}
	if node.nodeType != nodeTypeLeaf {
		panic("unreachable")
	}
	return node.leafNode
}

// resolve computes the resolution of a node.
func (tree ratchetTree) resolve(x nodeIndex) []nodeIndex {
	n := tree.get(x)
	if n == nil {
		l, r, ok := x.children()
		if !ok {
			return nil // leaf
		}
		return append(tree.resolve(l), tree.resolve(r)...)
	} else {
		res := []nodeIndex{x}
		if n.nodeType == nodeTypeParent {
			for _, leafIndex := range n.parentNode.unmergedLeaves {
				res = append(res, leafIndex.nodeIndex())
			}
		}
		return res
	}
}

// verifyIntegrity verifies the integrity of the ratchet tree, as described in
// section 12.4.3.1.
//
// This function does not perform full leaf node validation. In particular:
//
//   - It doesn't check that credentials are valid.
//   - It doesn't check the lifetime field.
func (tree ratchetTree) verifyIntegrity(ctx *groupContext) error {
	cs := ctx.cipherSuite
	numLeaves := tree.numLeaves()

	if h, err := tree.computeTreeHash(cs, numLeaves.root(), nil); err != nil {
		return err
	} else if !bytes.Equal(h, ctx.treeHash) {
		return fmt.Errorf("mls: tree hash verification failed")
	}

	if !tree.verifyParentHashes(cs) {
		return fmt.Errorf("mls: parent hashes verification failed")
	}

	numMembers := 0
	supportedCreds := make(map[credentialType]int)
	for li := leafIndex(0); li < leafIndex(numLeaves); li++ {
		node := tree.getLeaf(li)
		if node == nil {
			continue
		}

		numMembers++
		for _, ct := range node.capabilities.credentials {
			supportedCreds[ct]++
		}
	}

	signatureKeys := make(map[string]struct{})
	encryptionKeys := make(map[string]struct{})
	for li := leafIndex(0); li < leafIndex(numLeaves); li++ {
		node := tree.getLeaf(li)
		if node == nil {
			continue
		}

		if !node.verifySignature(cs, ctx.groupID, li) {
			return fmt.Errorf("mls: signature verification failed for leaf node at index %v", li)
		}

		// TODO: check required_capabilities group extension

		if supportedCreds[node.credential.credentialType] != numMembers {
			return fmt.Errorf("mls: credential type %v used by leaf node at index %v not supported by all members", node.credential.credentialType, li)
		}

		// TODO: consider checking lifetime

		supportedExts := make(map[extensionType]struct{})
		for _, et := range node.capabilities.extensions {
			supportedExts[et] = struct{}{}
		}
		for _, ext := range node.extensions {
			if _, ok := supportedExts[ext.extensionType]; !ok {
				return fmt.Errorf("mls: extension type %d used by leaf node at index %v not supported by that leaf node", ext.extensionType, li)
			}
		}

		if _, dup := signatureKeys[string(node.signatureKey)]; dup {
			return fmt.Errorf("mls: duplicate signature key in ratchet tree")
		}
		if _, dup := encryptionKeys[string(node.encryptionKey)]; dup {
			return fmt.Errorf("mls: duplicate encryption key in ratchet tree")
		}
		signatureKeys[string(node.signatureKey)] = struct{}{}
		encryptionKeys[string(node.encryptionKey)] = struct{}{}
	}

	for i, node := range tree {
		if node == nil || node.nodeType != nodeTypeParent {
			continue
		}
		p := nodeIndex(i)
		for _, unmergedLeaf := range node.parentNode.unmergedLeaves {
			x := unmergedLeaf.nodeIndex()
			for {
				var ok bool
				if x, ok = numLeaves.parent(x); !ok {
					return fmt.Errorf("mls: unmerged leaf %v is not a descendant of the parent node at index %v", unmergedLeaf, p)
				}

				intermediateNode := tree.get(x)
				if intermediateNode != nil && !hasUnmergedLeaf(intermediateNode.parentNode, unmergedLeaf) {
					return fmt.Errorf("mls: non-blank intermediate node at index %v is missing unmerged leaf %v", x, unmergedLeaf)
				}
			}
		}

		if _, dup := encryptionKeys[string(node.parentNode.encryptionKey)]; dup {
			return fmt.Errorf("mls: duplicate encryption key in ratchet tree")
		}
		encryptionKeys[string(node.parentNode.encryptionKey)] = struct{}{}
	}

	return nil
}

func hasUnmergedLeaf(node *parentNode, unmergedLeaf leafIndex) bool {
	for _, li := range node.unmergedLeaves {
		if li == unmergedLeaf {
			return true
		}
	}
	return false
}

func (tree ratchetTree) computeTreeHash(cs cipherSuite, x nodeIndex, exclude map[leafIndex]struct{}) ([]byte, error) {
	n := tree.get(x)

	var b cryptobyte.Builder
	if li, ok := x.leafIndex(); ok {
		_, excluded := exclude[li]

		var l *leafNode
		if n != nil && !excluded {
			l = n.leafNode
			if l == nil {
				panic("unreachable")
			}
		}

		marshalLeafNodeHashInput(&b, li, l)
	} else {
		left, right, ok := x.children()
		if !ok {
			panic("unreachable")
		}

		leftHash, err := tree.computeTreeHash(cs, left, exclude)
		if err != nil {
			return nil, err
		}
		rightHash, err := tree.computeTreeHash(cs, right, exclude)
		if err != nil {
			return nil, err
		}

		var p *parentNode
		if n != nil {
			p = n.parentNode
			if p == nil {
				panic("unreachable")
			}

			if len(p.unmergedLeaves) > 0 && len(exclude) > 0 {
				unmergedLeaves := make([]leafIndex, 0, len(p.unmergedLeaves))
				for _, li := range p.unmergedLeaves {
					if _, excluded := exclude[li]; !excluded {
						unmergedLeaves = append(unmergedLeaves, li)
					}
				}

				filteredParent := *p
				filteredParent.unmergedLeaves = unmergedLeaves
				p = &filteredParent
			}
		}

		marshalParentNodeHashInput(&b, p, leftHash, rightHash)
	}
	in, err := b.Bytes()
	if err != nil {
		return nil, err
	}

	h := cs.hash().New()
	h.Write(in)
	return h.Sum(nil), nil
}

func marshalLeafNodeHashInput(b *cryptobyte.Builder, i leafIndex, node *leafNode) {
	b.AddUint8(uint8(nodeTypeLeaf))
	b.AddUint32(uint32(i))
	writeOptional(b, node != nil)
	if node != nil {
		node.marshal(b)
	}
}

func marshalParentNodeHashInput(b *cryptobyte.Builder, node *parentNode, leftHash, rightHash []byte) {
	b.AddUint8(uint8(nodeTypeParent))
	writeOptional(b, node != nil)
	if node != nil {
		node.marshal(b)
	}
	writeOpaqueVec(b, leftHash)
	writeOpaqueVec(b, rightHash)
}

func (tree ratchetTree) verifyParentHashes(cs cipherSuite) bool {
	for i, node := range tree {
		if node == nil {
			continue
		}

		x := nodeIndex(i)
		l, r, ok := x.children()
		if !ok {
			continue
		}

		parentNode := node.parentNode
		exclude := make(map[leafIndex]struct{}, len(parentNode.unmergedLeaves))
		for _, li := range parentNode.unmergedLeaves {
			exclude[li] = struct{}{}
		}

		leftTreeHash, err := tree.computeTreeHash(cs, l, exclude)
		if err != nil {
			return false
		}
		rightTreeHash, err := tree.computeTreeHash(cs, r, exclude)
		if err != nil {
			return false
		}

		leftParentHash, err := parentNode.computeParentHash(cs, rightTreeHash)
		if err != nil {
			return false
		}
		rightParentHash, err := parentNode.computeParentHash(cs, leftTreeHash)
		if err != nil {
			return false
		}

		isLeftDescendant := tree.findParentHash(tree.resolve(l), leftParentHash)
		isRightDescendant := tree.findParentHash(tree.resolve(r), rightParentHash)
		if isLeftDescendant == isRightDescendant {
			return false
		}
	}
	return true
}

func (tree ratchetTree) findParentHash(nodeIndices []nodeIndex, parentHash []byte) bool {
	for _, x := range nodeIndices {
		node := tree.get(x)
		if node == nil {
			continue
		}
		var h []byte
		switch node.nodeType {
		case nodeTypeLeaf:
			h = node.leafNode.parentHash
		case nodeTypeParent:
			h = node.parentNode.parentHash
		}
		if bytes.Equal(h, parentHash) {
			return true
		}
	}
	return false
}

func (tree ratchetTree) numLeaves() numLeaves {
	return numLeavesFromWidth(uint32(len(tree)))
}

func (tree ratchetTree) findLeaf(node *leafNode) (leafIndex, bool) {
	for li := leafIndex(0); li < leafIndex(tree.numLeaves()); li++ {
		n := tree.getLeaf(li)
		if n == nil {
			continue
		}

		// Encryption keys are unique
		if !bytes.Equal(n.encryptionKey, node.encryptionKey) {
			continue
		}

		// Make sure both nodes are identical
		raw1, err1 := marshal(node)
		raw2, err2 := marshal(n)
		return li, err1 == nil && err2 == nil && bytes.Equal(raw1, raw2)
	}
	return 0, false
}

func (tree *ratchetTree) add(leafNode *leafNode) {
	li := leafIndex(0)
	var ni nodeIndex
	found := false
	for {
		ni = li.nodeIndex()
		if int(ni) >= len(*tree) {
			break
		}
		if tree.get(ni) == nil {
			found = true
			break
		}
		li++
	}
	if !found {
		ni = nodeIndex(len(*tree) + 1)
		newLen := ((len(*tree) + 1) * 2) - 1
		for len(*tree) < newLen {
			*tree = append(*tree, nil)
		}
	}

	numLeaves := tree.numLeaves()
	p := ni
	for {
		var ok bool
		p, ok = numLeaves.parent(p)
		if !ok {
			break
		}
		node := tree.get(p)
		if node != nil {
			node.parentNode.unmergedLeaves = append(node.parentNode.unmergedLeaves, li)
		}
	}

	tree.set(ni, &node{
		nodeType: nodeTypeLeaf,
		leafNode: leafNode,
	})
}

func (tree ratchetTree) update(li leafIndex, leafNode *leafNode) {
	ni := li.nodeIndex()

	tree.set(ni, &node{
		nodeType: nodeTypeLeaf,
		leafNode: leafNode,
	})

	numLeaves := tree.numLeaves()
	for {
		var ok bool
		ni, ok = numLeaves.parent(ni)
		if !ok {
			break
		}

		tree.set(ni, nil)
	}
}

func (tree *ratchetTree) remove(li leafIndex) {
	ni := li.nodeIndex()

	numLeaves := tree.numLeaves()
	for {
		tree.set(ni, nil)

		var ok bool
		ni, ok = numLeaves.parent(ni)
		if !ok {
			break
		}
	}

	li = leafIndex(numLeaves - 1)
	lastPowerOf2 := len(*tree)
	for {
		ni = li.nodeIndex()
		if tree.get(ni) != nil {
			break
		}

		if isPowerOf2(uint32(ni)) {
			lastPowerOf2 = int(ni)
		}

		if li == 0 {
			*tree = nil
			return
		}
		li--
	}

	if lastPowerOf2 < len(*tree) {
		*tree = (*tree)[:lastPowerOf2]
	}
}
