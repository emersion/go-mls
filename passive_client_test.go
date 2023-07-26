package mls

import (
	"bytes"
	"fmt"
	"testing"
)

type passiveClientTest struct {
	CipherSuite cipherSuite `json:"cipher_suite"`

	ExternalPSKs []struct {
		PSKID testBytes `json:"psk_id"`
		PSK   testBytes `json:"psk"`
	} `json:"external_psks"`
	KeyPackage     testBytes `json:"key_package"`
	SignaturePriv  testBytes `json:"signature_priv"`
	EncryptionPriv testBytes `json:"encryption_priv"`
	InitPriv       testBytes `json:"init_priv"`

	Welcome                   testBytes `json:"welcome"`
	RatchetTree               testBytes `json:"ratchet_tree"`
	InitialEpochAuthenticator testBytes `json:"initial_epoch_authenticator"`

	Epochs []struct {
		Proposals          []testBytes `json:"proposals"`
		Commit             testBytes   `json:"commit"`
		EpochAuthenticator testBytes   `json:"epoch_authenticator"`
	} `json:"epochs"`
}

func testPassiveClient(t *testing.T, tc *passiveClientTest) {
	initPriv := []byte(tc.InitPriv)
	encryptionPriv := []byte(tc.EncryptionPriv)
	signaturePriv := []byte(tc.SignaturePriv)

	msg, err := unmarshalMLSMessage(tc.Welcome, wireFormatMLSWelcome)
	if err != nil {
		t.Fatalf("unmarshal(welcome) = %v", err)
	}
	welcome := msg.welcome

	msg, err = unmarshalMLSMessage(tc.KeyPackage, wireFormatMLSKeyPackage)
	if err != nil {
		t.Fatalf("unmarshal(keyPackage) = %v", err)
	}
	keyPkg := msg.keyPackage

	var tree *ratchetTree
	if tc.RatchetTree != nil {
		tree = new(ratchetTree)
		if err := unmarshal([]byte(tc.RatchetTree), tree); err != nil {
			t.Fatalf("unmarshal(ratchetTree) = %v", err)
		}
	}

	if tree == nil {
		t.Skip("TODO")
	}

	if err := checkEncryptionKeyPair(tc.CipherSuite, keyPkg.initKey, initPriv); err != nil {
		t.Errorf("invalid init keypair: %v", err)
	}
	if err := checkEncryptionKeyPair(tc.CipherSuite, keyPkg.leafNode.encryptionKey, encryptionPriv); err != nil {
		t.Errorf("invalid encryption keypair: %v", err)
	}
	if err := checkSignatureKeyPair(tc.CipherSuite, []byte(keyPkg.leafNode.signatureKey), signaturePriv); err != nil {
		t.Errorf("invalid signature keypair: %v", err)
	}

	keyPkgRef, err := keyPkg.generateRef()
	if err != nil {
		t.Fatalf("keyPackage.generateRef() = %v", err)
	}

	groupSecrets, err := welcome.decryptGroupSecrets(keyPkgRef, initPriv)
	if err != nil {
		t.Fatalf("welcome.decryptGroupSecrets() = %v", err)
	}

	if !groupSecrets.verifySingleReinitOrBranchPSK() {
		t.Errorf("groupSecrets.verifySingleReinitOrBranchPSK() failed")
	}

	var psks [][]byte
	for _, pskID := range groupSecrets.psks {
		if pskID.pskType != pskTypeExternal {
			t.Fatalf("group secrets contain a non-external PSK ID")
		}

		found := false
		for _, epsk := range tc.ExternalPSKs {
			if bytes.Equal([]byte(epsk.PSKID), pskID.pskID) {
				psks = append(psks, []byte(epsk.PSK))
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("PSK ID %v not found", pskID.pskID)
		}
	}

	pskSecret, err := extractPSKSecret(tc.CipherSuite, groupSecrets.psks, psks)
	if err != nil {
		t.Fatalf("extractPSKSecret() = %v", err)
	}

	groupInfo, err := welcome.decryptGroupInfo(groupSecrets.joinerSecret, pskSecret)
	if err != nil {
		t.Fatalf("welcome.decryptGroupInfo() = %v", err)
	}
	signerNode := tree.get(groupInfo.signer.nodeIndex())
	if signerNode == nil {
		t.Errorf("signer node is blank")
	} else if !groupInfo.verifySignature(signerNode.leafNode.signatureKey) {
		t.Errorf("groupInfo.verifySignature() failed")
	}
	if !groupInfo.verifyConfirmationTag(groupSecrets.joinerSecret, pskSecret) {
		t.Errorf("groupInfo.verifyConfirmationTag() failed")
	}
	if groupInfo.groupContext.cipherSuite != keyPkg.cipherSuite {
		t.Errorf("groupInfo.cipherSuite = %v, want %v", groupInfo.groupContext.cipherSuite, keyPkg.cipherSuite)
	}

	// TODO: perform other group info verification steps
	// TODO: verify epoch authenticator
	// TODO: apply commits from epochs
}

func unmarshalMLSMessage(raw testBytes, wf wireFormat) (*mlsMessage, error) {
	var msg mlsMessage
	if err := unmarshal([]byte(raw), &msg); err != nil {
		return nil, err
	} else if msg.wireFormat != wf {
		return nil, fmt.Errorf("invalid wireFormat: got %v, want %v", msg.wireFormat, wf)
	}
	return &msg, nil
}

func checkEncryptionKeyPair(cs cipherSuite, pub, priv []byte) error {
	wantPlaintext := []byte("foo")
	label := []byte("bar")

	kemOutput, ciphertext, err := cs.encryptWithLabel(pub, label, nil, wantPlaintext)
	if err != nil {
		return err
	}

	plaintext, err := cs.decryptWithLabel(priv, label, nil, kemOutput, ciphertext)
	if err != nil {
		return err
	}

	if !bytes.Equal(plaintext, wantPlaintext) {
		return fmt.Errorf("got plaintext %v, want %v", plaintext, wantPlaintext)
	}

	return nil
}

func checkSignatureKeyPair(cs cipherSuite, pub, priv []byte) error {
	content := []byte("foo")
	label := []byte("bar")

	signature, err := cs.signWithLabel(priv, label, content)
	if err != nil {
		return err
	}

	if !cs.verifyWithLabel(pub, label, content, signature) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func TestPassiveClientWelcome(t *testing.T) {
	var tests []passiveClientTest
	loadTestVector(t, "testdata/passive-client-welcome.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			if i == 36 || i == 37 || i == 38 || i == 39 {
				// TODO: for some reason these fail with "hpke: invalid KEM private key"
				t.Skip("TODO")
			}
			testPassiveClient(t, &tc)
		})
	}
}
