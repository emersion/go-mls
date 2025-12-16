package mls

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

type passiveClientTest struct {
	CipherSuite CipherSuite `json:"cipher_suite"`

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
	cs := tc.CipherSuite
	initPriv := []byte(tc.InitPriv)
	encryptionPriv := []byte(tc.EncryptionPriv)
	signaturePriv := []byte(tc.SignaturePriv)

	if !cs.Supported() {
		t.Skipf("unsupported cipher suite %v", cs)
	}

	welcome, err := UnmarshalWelcome(tc.Welcome)
	if err != nil {
		t.Fatalf("UnmarshalWelcome() = %v", err)
	}
	if welcome.cipherSuite != cs {
		t.Fatalf("welcome.cipherSuite = %v, want %v", welcome.cipherSuite, cs)
	}

	keyPkg, err := UnmarshalKeyPackage([]byte(tc.KeyPackage))
	if err != nil {
		t.Fatalf("UnmarshalKeyPackage() = %v", err)
	}
	if keyPkg.cipherSuite != welcome.cipherSuite {
		t.Fatalf("keyPkg.cipherSuite = %v, want %v", keyPkg.cipherSuite, welcome.cipherSuite)
	}

	if err := checkEncryptionKeyPair(cs, keyPkg.initKey, initPriv); err != nil {
		t.Errorf("invalid init keypair: %v", err)
	}
	if err := checkEncryptionKeyPair(cs, keyPkg.leafNode.encryptionKey, encryptionPriv); err != nil {
		t.Errorf("invalid encryption keypair: %v", err)
	}
	if err := checkSignatureKeyPair(cs, []byte(keyPkg.leafNode.signatureKey), signaturePriv); err != nil {
		t.Errorf("invalid signature keypair: %v", err)
	}

	keyPkgRef, err := keyPkg.GenerateRef()
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

	keyPairPkg := KeyPairPackage{
		Public: *keyPkg,
		Private: PrivateKeyPackage{
			InitKey:       initPriv,
			EncryptionKey: encryptionPriv,
			SignatureKey:  signaturePriv,
		},
	}
	disableLifetimeCheck := func() time.Time { return time.Time{} }
	group, err := groupFromSecrets(welcome, &keyPairPkg, groupSecrets, &groupFromSecretsOptions{
		rawTree: []byte(tc.RatchetTree),
		psks:    psks,
		now:     disableLifetimeCheck,
	})
	if err != nil {
		t.Errorf("groupFromWelcomeAndSecrets() = %v", err)
	}

	epochAuthenticator, err := cs.deriveSecret(group.epochSecret, secretLabelAuthentication)
	if err != nil {
		t.Errorf("deriveSecret(authentication) = %v", err)
	} else if !bytes.Equal(epochAuthenticator, []byte(tc.InitialEpochAuthenticator)) {
		t.Errorf("deriveSecret(authentication) = %v, want %v", epochAuthenticator, tc.InitialEpochAuthenticator)
	}

	for i, epoch := range tc.Epochs {
		t.Logf("epoch %v", i)

		for _, rawProposal := range epoch.Proposals {
			var msg mlsMessage
			if err := unmarshal([]byte(rawProposal), &msg); err != nil {
				t.Fatalf("unmarshal(proposal) = %v", err)
			} else if msg.wireFormat != wireFormatMLSPublicMessage {
				t.Fatalf("TODO: wireFormat = %v", msg.wireFormat)
			}
			pubMsg := msg.publicMessage

			// TODO: public message checks

			authContent := pubMsg.authenticatedContent()

			if err := group.processProposal(authContent); err != nil {
				t.Errorf("processProposal() = %v", err)
			}
		}

		var msg mlsMessage
		if err := unmarshal([]byte(epoch.Commit), &msg); err != nil {
			t.Fatalf("unmarshal(commit) = %v", err)
		} else if msg.wireFormat != wireFormatMLSPublicMessage {
			t.Fatalf("TODO: wireFormat = %v", msg.wireFormat)
		}
		pubMsg := msg.publicMessage

		authContent, err := group.verifyPublicMessage(pubMsg)
		if err != nil {
			t.Errorf("verifyPublicMessage() = %v", err)
		}
		senderLeafIndex := pubMsg.content.sender.leafIndex

		if authContent.content.contentType != contentTypeCommit {
			t.Errorf("contentType = %v, want %v", authContent.content.contentType, contentTypeCommit)
		}
		commit := authContent.content.commit

		proposals, _, err := resolveProposals(commit.proposals, senderLeafIndex, group.pendingProposals)
		for _, prop := range proposals {
			switch prop.proposalType {
			case proposalTypeAdd, proposalTypeRemove, proposalTypeUpdate:
				// handled by ratchetTree.apply
			case proposalTypePSK:
				// handled below
			default:
				t.Skipf("TODO: proposal type = %v", prop.proposalType)
			}
		}

		var (
			pskIDs []preSharedKeyID
			psks   [][]byte
		)
		for _, prop := range proposals {
			if prop.proposalType != proposalTypePSK {
				continue
			}

			pskID := prop.preSharedKey.psk
			if pskID.pskType != pskTypeExternal {
				t.Skipf("TODO: PSK ID type = %v", pskID.pskType)
			}

			found := false
			for _, epsk := range tc.ExternalPSKs {
				if bytes.Equal([]byte(epsk.PSKID), pskID.pskID) {
					pskIDs = append(pskIDs, pskID)
					psks = append(psks, []byte(epsk.PSK))
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("PSK ID %v not found", pskID.pskID)
			}
		}

		err = group.processCommit(authContent, pskIDs, psks, disableLifetimeCheck)
		if err != nil {
			t.Errorf("processCommit() = %v", err)
		}
	}
}

func checkEncryptionKeyPair(cs CipherSuite, pub, priv []byte) error {
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

func checkSignatureKeyPair(cs CipherSuite, pub, priv []byte) error {
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
			testPassiveClient(t, &tc)
		})
	}
}

func TestPassiveClientCommit(t *testing.T) {
	var tests []passiveClientTest
	loadTestVector(t, "testdata/passive-client-handling-commit.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			testPassiveClient(t, &tc)
		})
	}
}

func TestPassiveClientRandom(t *testing.T) {
	var tests []passiveClientTest
	loadTestVector(t, "testdata/passive-client-random.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			testPassiveClient(t, &tc)
		})
	}
}
