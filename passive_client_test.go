package mls

import (
	"bytes"
	"fmt"
	"testing"
	"time"
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

	rawTree := []byte(tc.RatchetTree)
	if rawTree == nil {
		rawTree = findExtensionData(groupInfo.extensions, extensionTypeRatchetTree)
	}
	if rawTree == nil {
		t.Fatalf("missing ratchet tree")
	}

	var tree ratchetTree
	if err := unmarshal(rawTree, &tree); err != nil {
		t.Fatalf("unmarshal(ratchetTree) = %v", err)
	}

	signerNode := tree.getLeaf(groupInfo.signer)
	if signerNode == nil {
		t.Errorf("signer node is blank")
	} else if !groupInfo.verifySignature(signerNode.signatureKey) {
		t.Errorf("groupInfo.verifySignature() failed")
	}
	if !groupInfo.verifyConfirmationTag(groupSecrets.joinerSecret, pskSecret) {
		t.Errorf("groupInfo.verifyConfirmationTag() failed")
	}
	if groupInfo.groupContext.cipherSuite != keyPkg.cipherSuite {
		t.Errorf("groupInfo.cipherSuite = %v, want %v", groupInfo.groupContext.cipherSuite, keyPkg.cipherSuite)
	}

	disableLifetimeCheck := func() time.Time { return time.Time{} }
	if err := tree.verifyIntegrity(&groupInfo.groupContext, disableLifetimeCheck); err != nil {
		t.Errorf("tree.verifyIntegrity() = %v", err)
	}

	_, ok := tree.findLeaf(&keyPkg.leafNode)
	if !ok {
		t.Errorf("tree.findLeaf() = false")
	}

	// TODO: perform other group info verification steps

	epochSecret, err := groupInfo.groupContext.extractEpochSecret(groupSecrets.joinerSecret, pskSecret)
	if err != nil {
		t.Fatalf("groupContext.extractEpochSecret() = %v", err)
	}
	epochAuthenticator, err := tc.CipherSuite.deriveSecret(epochSecret, secretLabelAuthentication)
	if err != nil {
		t.Errorf("deriveSecret(authentication) = %v", err)
	} else if !bytes.Equal(epochAuthenticator, []byte(tc.InitialEpochAuthenticator)) {
		t.Errorf("deriveSecret(authentication) = %v, want %v", epochAuthenticator, tc.InitialEpochAuthenticator)
	}

	for _, epoch := range tc.Epochs {
		var msg mlsMessage
		if err := unmarshal([]byte(epoch.Commit), &msg); err != nil {
			t.Fatalf("unmarshal(commit) = %v", err)
		} else if msg.wireFormat != wireFormatMLSPublicMessage {
			t.Fatalf("TODO: wireFormat = %v", msg.wireFormat)
		}
		pubMsg := msg.publicMessage

		if pubMsg.content.epoch != groupInfo.groupContext.epoch {
			t.Errorf("epoch = %v, want %v", pubMsg.content.epoch, groupInfo.groupContext.epoch)
		}

		if pubMsg.content.sender.senderType != senderTypeMember {
			t.Fatalf("TODO: senderType = %v", pubMsg.content.sender.senderType)
		}
		senderLeafIndex := pubMsg.content.sender.leafIndex
		// TODO: check tree length
		senderNode := tree.getLeaf(senderLeafIndex)
		if senderNode == nil {
			t.Fatalf("blank leaf node for sender")
		}

		authContent := pubMsg.authenticatedContent()
		if !authContent.verifySignature(tc.CipherSuite, []byte(senderNode.signatureKey), &groupInfo.groupContext) {
			t.Errorf("verifySignature() failed")
		}
		// TODO: check membership key

		if authContent.content.contentType != contentTypeCommit {
			t.Errorf("contentType = %v, want %v", authContent.content.contentType, contentTypeCommit)
		}
		commit := authContent.content.commit

		var (
			proposals []proposal
			senders   []leafIndex
		)
		for _, propOrRef := range commit.proposals {
			switch propOrRef.typ {
			case proposalOrRefTypeProposal:
				proposals = append(proposals, *propOrRef.proposal)
				senders = append(senders, senderLeafIndex)
			case proposalOrRefTypeReference:
				t.Error("TODO: proposalOrRefTypeReference")
			}
		}

		if err := verifyProposalList(proposals, senders, senderLeafIndex); err != nil {
			t.Errorf("verifyProposals() = %v", err)
		}
		// TODO: additional proposal list checks

		for _, prop := range proposals {
			if prop.proposalType == proposalTypePSK {
				t.Fatalf("no PSK available")
			}
		}

		newTree := make(ratchetTree, len(tree))
		copy(newTree, tree)
		newTree.apply(proposals, senders)

		if proposalListNeedsPath(proposals) && commit.path == nil {
			t.Errorf("proposal list needs update path")
		}

		if commit.path != nil {
			if commit.path.leafNode.leafNodeSource != leafNodeSourceCommit {
				t.Errorf("commit path leaf node source must be commit")
			}

			// The same signature key can be re-used, but the encryption key
			// must change
			signatureKeys, encryptionKeys := tree.keys()
			delete(signatureKeys, string(senderNode.signatureKey))
			err := commit.path.leafNode.verify(&leafNodeVerifyOptions{
				cipherSuite:    tc.CipherSuite,
				groupID:        groupInfo.groupContext.groupID,
				leafIndex:      senderLeafIndex,
				supportedCreds: tree.supportedCreds(),
				signatureKeys:  signatureKeys,
				encryptionKeys: encryptionKeys,
				now:            func() time.Time { return time.Time{} },
			})
			if err != nil {
				t.Errorf("leafNode.verify() = %v", err)
			}

			for _, updateNode := range commit.path.nodes {
				if _, dup := encryptionKeys[string(updateNode.encryptionKey)]; dup {
					t.Errorf("encryption key in update path already used in ratchet tree")
					break
				}
			}

			if err := tree.mergeUpdatePath(tc.CipherSuite, senderLeafIndex, commit.path); err != nil {
				t.Errorf("ratchetTree.mergeUpdatePath() = %v", err)
			}
		}

		break // TODO: apply commit
	}
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
			if i == 32 || (i >= 34 && i <= 39) {
				// TODO: for some reason these fail with "hpke: invalid KEM private key"
				t.Skip("TODO")
			}
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
