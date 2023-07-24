package mls

import (
	"bytes"
	"fmt"
	"testing"
)

type secretTreeTest struct {
	CipherSuite cipherSuite `json:"cipher_suite"`

	SenderData struct {
		SenderDataSecret testBytes `json:"sender_data_secret"`
		Ciphertext       testBytes `json:"ciphertext"`
		Key              testBytes `json:"key"`
		Nonce            testBytes `json:"nonce"`
	} `json:"sender_data"`

	EncryptionSecret testBytes             `json:"encryption_secret"`
	Leaves           [][]secretTreeTestGen `json:"leaves"`
}

type secretTreeTestGen struct {
	Generation       uint32    `json:"generation"`
	HandshakeKey     testBytes `json:"handshake_key"`
	HandshakeNonce   testBytes `json:"handshake_nonce"`
	ApplicationKey   testBytes `json:"application_key"`
	ApplicationNonce testBytes `json:"application_nonce"`
}

func testSecretTree(t *testing.T, tc *secretTreeTest) {
	senderDataSecret := []byte(tc.SenderData.SenderDataSecret)
	ciphertext := []byte(tc.SenderData.Ciphertext)

	key, err := expandSenderDataKey(tc.CipherSuite, senderDataSecret, ciphertext)
	if err != nil {
		t.Errorf("expandSenderDataKey() = %v", err)
	} else if !bytes.Equal(key, []byte(tc.SenderData.Key)) {
		t.Errorf("expandSenderDataKey() = %v, want %v", key, tc.SenderData.Key)
	}

	nonce, err := expandSenderDataNonce(tc.CipherSuite, senderDataSecret, ciphertext)
	if err != nil {
		t.Errorf("expandSenderDataNonce() = %v", err)
	} else if !bytes.Equal(nonce, []byte(tc.SenderData.Nonce)) {
		t.Errorf("expandSenderDataNonce() = %v, want %v", nonce, tc.SenderData.Nonce)
	}

	tree, err := deriveSecretTree(tc.CipherSuite, numLeaves(len(tc.Leaves)), []byte(tc.EncryptionSecret))
	if err != nil {
		t.Fatalf("generateSecretTree() = %v", err)
	}

	for i, gens := range tc.Leaves {
		li := leafIndex(i)
		t.Run(fmt.Sprintf("leaf-%v/handshake", li), func(t *testing.T) {
			testRatchetSecret(t, tc.CipherSuite, tree, li, ratchetLabelHandshake, gens)
		})
		t.Run(fmt.Sprintf("leaf-%v/application", li), func(t *testing.T) {
			testRatchetSecret(t, tc.CipherSuite, tree, li, ratchetLabelApplication, gens)
		})
	}
}

func testRatchetSecret(t *testing.T, cs cipherSuite, tree secretTree, li leafIndex, label ratchetLabel, gens []secretTreeTestGen) {
	secret, err := tree.deriveRatchetRoot(cs, li.nodeIndex(), label)
	if err != nil {
		t.Fatalf("deriveRatchetRoot() = %v", err)
	}

	for _, gen := range gens {
		if gen.Generation < secret.generation {
			panic("unreachable")
		}

		for secret.generation != gen.Generation {
			secret, err = secret.deriveNext(cs)
			if err != nil {
				t.Fatalf("deriveNext() = %v", err)
			}
		}

		var wantKey, wantNonce testBytes
		switch string(label) {
		case string(ratchetLabelHandshake):
			wantKey, wantNonce = gen.HandshakeKey, gen.HandshakeNonce
		case string(ratchetLabelApplication):
			wantKey, wantNonce = gen.ApplicationKey, gen.ApplicationNonce
		default:
			panic("unreachable")
		}

		key, err := secret.deriveKey(cs)
		if err != nil {
			t.Fatalf("deriveKey() = %v", err)
		} else if !bytes.Equal(key, []byte(wantKey)) {
			t.Errorf("deriveKey() = %v, want %v", key, wantKey)
		}

		nonce, err := secret.deriveNonce(cs)
		if err != nil {
			t.Fatalf("deriveNonce() = %v", err)
		} else if !bytes.Equal(nonce, []byte(wantNonce)) {
			t.Errorf("deriveNonce() = %v, want %v", nonce, wantNonce)
		}
	}
}

func TestSecretTree(t *testing.T) {
	var tests []secretTreeTest
	loadTestVector(t, "testdata/secret-tree.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			testSecretTree(t, &tc)
		})
	}
}
