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

	EncryptionSecret testBytes `json:"encryption_secret"`
	Leaves           [][]struct {
		Generation       uint32    `json:"generation"`
		HandshakeKey     testBytes `json:"handshake_key"`
		HandshakeNonce   testBytes `json:"handshake_nonce"`
		ApplicationKey   testBytes `json:"applicationKey"`
		ApplicationNonce testBytes `json:"application_nonce"`
	} `json:"leaves"`
}

func testSecretTree(t *testing.T, tc *secretTreeTest) {
	// TODO: test leaves

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
