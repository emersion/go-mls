package mls

import (
	"golang.org/x/crypto/cryptobyte"
)

type ratchetLabel []byte

var (
	ratchetLabelHandshake   = ratchetLabel("handshake")
	ratchetLabelApplication = ratchetLabel("application")
)

func ratchetLabelFromContentType(ct contentType) ratchetLabel {
	switch ct {
	case contentTypeApplication:
		return ratchetLabelApplication
	case contentTypeProposal, contentTypeCommit:
		return ratchetLabelHandshake
	default:
		panic("unreachable")
	}
}

type secretTree [][]byte

func deriveSecretTree(cs cipherSuite, n numLeaves, encryptionSecret []byte) (secretTree, error) {
	tree := make(secretTree, int(n.width()))
	tree.set(n.root(), encryptionSecret)
	err := tree.deriveChildren(cs, n.root())
	return tree, err
}

func (tree secretTree) deriveChildren(cs cipherSuite, x nodeIndex) error {
	l, r, ok := x.children()
	if !ok {
		return nil
	}

	parentSecret := tree.get(x)
	_, kdf, _ := cs.hpke().Params()
	nh := uint16(kdf.ExtractSize())
	leftSecret, err := cs.expandWithLabel(parentSecret, []byte("tree"), []byte("left"), nh)
	if err != nil {
		return err
	}
	rightSecret, err := cs.expandWithLabel(parentSecret, []byte("tree"), []byte("right"), nh)
	if err != nil {
		return err
	}

	tree.set(l, leftSecret)
	tree.set(r, rightSecret)

	if err := tree.deriveChildren(cs, l); err != nil {
		return err
	}
	if err := tree.deriveChildren(cs, r); err != nil {
		return err
	}

	return nil
}

func (tree secretTree) get(ni nodeIndex) []byte {
	secret := tree[int(ni)]
	if secret == nil {
		panic("empty node in secret tree")
	}
	return secret
}

func (tree secretTree) set(ni nodeIndex, secret []byte) {
	tree[int(ni)] = secret
}

func (tree secretTree) deriveRatchetRoot(cs cipherSuite, ni nodeIndex, label ratchetLabel) (ratchetSecret, error) {
	_, kdf, _ := cs.hpke().Params()
	nh := uint16(kdf.ExtractSize())
	root, err := cs.expandWithLabel(tree.get(ni), []byte(label), nil, nh)
	return ratchetSecret{root, 0}, err
}

type ratchetSecret struct {
	secret     []byte
	generation uint32
}

func (secret ratchetSecret) deriveNonce(cs cipherSuite) ([]byte, error) {
	_, _, aead := cs.hpke().Params()
	nn := uint16(aead.NonceSize())
	return deriveTreeSecret(cs, secret.secret, []byte("nonce"), secret.generation, nn)
}

func (secret ratchetSecret) deriveKey(cs cipherSuite) ([]byte, error) {
	_, _, aead := cs.hpke().Params()
	nk := uint16(aead.KeySize())
	return deriveTreeSecret(cs, secret.secret, []byte("key"), secret.generation, nk)
}

func (secret ratchetSecret) deriveNext(cs cipherSuite) (ratchetSecret, error) {
	_, kdf, _ := cs.hpke().Params()
	nh := uint16(kdf.ExtractSize())
	next, err := deriveTreeSecret(cs, secret.secret, []byte("secret"), secret.generation, nh)
	return ratchetSecret{next, secret.generation + 1}, err
}

func deriveTreeSecret(cs cipherSuite, secret, label []byte, generation uint32, length uint16) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint32(generation)
	context := b.BytesOrPanic()

	return cs.expandWithLabel(secret, label, context, length)
}
