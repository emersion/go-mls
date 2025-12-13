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

type pendingProposal struct {
	ref      proposalRef
	proposal *proposal
	sender   leafIndex
}

func testPassiveClient(t *testing.T, tc *passiveClientTest) {
	cs := tc.CipherSuite
	initPriv := []byte(tc.InitPriv)
	encryptionPriv := []byte(tc.EncryptionPriv)
	signaturePriv := []byte(tc.SignaturePriv)

	// TODO: drop the seed size check, see:
	// https://github.com/cloudflare/circl/issues/486
	kem, kdf, _ := cs.hpke().Params()
	if kem.Scheme().SeedSize() != kdf.ExtractSize() {
		t.Skip("TODO: kem.Scheme().SeedSize() != kdf.ExtractSize()")
	}

	msg, err := unmarshalMLSMessage(tc.Welcome, wireFormatMLSWelcome)
	if err != nil {
		t.Fatalf("unmarshal(welcome) = %v", err)
	}
	welcome := msg.welcome
	if welcome.cipherSuite != cs {
		t.Fatalf("welcome.cipherSuite = %v, want %v", welcome.cipherSuite, cs)
	}

	msg, err = unmarshalMLSMessage(tc.KeyPackage, wireFormatMLSKeyPackage)
	if err != nil {
		t.Fatalf("unmarshal(keyPackage) = %v", err)
	}
	keyPkg := msg.keyPackage
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

	pskSecret, err := extractPSKSecret(cs, groupSecrets.psks, psks)
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

	myLeafIndex, ok := tree.findLeaf(&keyPkg.leafNode)
	if !ok {
		t.Errorf("tree.findLeaf() = false")
	}

	privTree := make([][]byte, len(tree))
	privTree[int(myLeafIndex.nodeIndex())] = encryptionPriv

	if groupSecrets.pathSecret != nil {
		nodeIndex := commonAncestor(myLeafIndex.nodeIndex(), groupInfo.signer.nodeIndex())
		nodePriv, err := nodePrivFromPathSecret(cs, groupSecrets.pathSecret, tree.get(nodeIndex).encryptionKey())
		if err != nil {
			t.Fatalf("failed to derive node %v private key from path secret: %v", nodeIndex, err)
		}
		privTree[int(nodeIndex)] = nodePriv

		pathSecret := groupSecrets.pathSecret
		for {
			nodeIndex, ok = tree.numLeaves().parent(nodeIndex)
			if !ok {
				break
			}

			pathSecret, err := cs.deriveSecret(pathSecret, []byte("path"))
			if err != nil {
				t.Fatalf("deriveSecret(pathSecret[n-1]) = %v", err)
			}

			nodePriv, err := nodePrivFromPathSecret(cs, pathSecret, tree.get(nodeIndex).encryptionKey())
			if err != nil {
				t.Fatalf("failed to derive node %v private key from path secret: %v", nodeIndex, err)
			}
			privTree[int(nodeIndex)] = nodePriv
		}
	}

	// TODO: perform other group info verification steps

	groupCtx := groupInfo.groupContext

	epochSecret, err := groupCtx.extractEpochSecret(groupSecrets.joinerSecret, pskSecret)
	if err != nil {
		t.Fatalf("groupContext.extractEpochSecret() = %v", err)
	}
	epochAuthenticator, err := cs.deriveSecret(epochSecret, secretLabelAuthentication)
	if err != nil {
		t.Errorf("deriveSecret(authentication) = %v", err)
	} else if !bytes.Equal(epochAuthenticator, []byte(tc.InitialEpochAuthenticator)) {
		t.Errorf("deriveSecret(authentication) = %v, want %v", epochAuthenticator, tc.InitialEpochAuthenticator)
	}

	initSecret, err := cs.deriveSecret(epochSecret, secretLabelInit)
	if err != nil {
		t.Errorf("deriveSecret(init) = %v", err)
	}

	interimTranscriptHash, err := nextInterimTranscriptHash(cs, groupCtx.confirmedTranscriptHash, groupInfo.confirmationTag)
	if err != nil {
		t.Errorf("nextInterimTranscriptHash() = %v", err)
	}

	for i, epoch := range tc.Epochs {
		t.Logf("epoch %v", i)

		var pendingProposals []pendingProposal
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

			if authContent.content.contentType != contentTypeProposal {
				t.Errorf("contentType = %v, want %v", authContent.content.contentType, contentTypeProposal)
			}
			proposal := authContent.content.proposal

			ref, err := authContent.generateProposalRef(cs)
			if err != nil {
				t.Fatalf("proposal.generateRef() = %v", err)
			}

			pendingProposals = append(pendingProposals, pendingProposal{
				ref:      ref,
				proposal: proposal,
				sender:   pubMsg.content.sender.leafIndex,
			})
		}

		var msg mlsMessage
		if err := unmarshal([]byte(epoch.Commit), &msg); err != nil {
			t.Fatalf("unmarshal(commit) = %v", err)
		} else if msg.wireFormat != wireFormatMLSPublicMessage {
			t.Fatalf("TODO: wireFormat = %v", msg.wireFormat)
		}
		pubMsg := msg.publicMessage

		if pubMsg.content.epoch != groupCtx.epoch {
			t.Errorf("epoch = %v, want %v", pubMsg.content.epoch, groupCtx.epoch)
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
		if !authContent.verifySignature(cs, []byte(senderNode.signatureKey), &groupCtx) {
			t.Errorf("verifySignature() failed")
		}

		membershipKey, err := cs.deriveSecret(epochSecret, secretLabelMembership)
		if err != nil {
			t.Errorf("deriveSecret(membership) = %v", err)
		} else if !pubMsg.verifyMembershipTag(cs, membershipKey, &groupCtx) {
			t.Errorf("publicMessage.verifyMembershipTag() failed")
		}

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
				var found bool
				for _, pp := range pendingProposals {
					if pp.ref.Equal(propOrRef.reference) {
						found = true
						proposals = append(proposals, *pp.proposal)
						senders = append(senders, pp.sender)
						break
					}
				}
				if !found {
					t.Fatalf("cannot find proposal reference %v", propOrRef.reference)
				}
			}
		}

		if err := verifyProposalList(proposals, senders, senderLeafIndex); err != nil {
			t.Errorf("verifyProposals() = %v", err)
		}
		// TODO: additional proposal list checks

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

		newTree := make(ratchetTree, len(tree))
		copy(newTree, tree)
		newTree.apply(proposals, senders)

		newPrivTree := make([][]byte, len(newTree))
		for i := range tree {
			if i < len(newPrivTree) {
				newPrivTree[i] = privTree[i]
			}
		}

		if proposalListNeedsPath(proposals) && commit.path == nil {
			t.Errorf("proposal list needs update path")
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

		newGroupCtx := groupCtx
		newGroupCtx.epoch++

		_, kdf, _ := cs.hpke().Params()
		commitSecret := make([]byte, kdf.ExtractSize())
		if commit.path != nil {
			if commit.path.leafNode.leafNodeSource != leafNodeSourceCommit {
				t.Errorf("commit path leaf node source must be commit")
			}

			// The same signature key can be re-used, but the encryption key
			// must change
			signatureKeys, encryptionKeys := newTree.keys()
			delete(signatureKeys, string(senderNode.signatureKey))
			err := commit.path.leafNode.verify(&leafNodeVerifyOptions{
				cipherSuite:    cs,
				groupID:        groupCtx.groupID,
				leafIndex:      senderLeafIndex,
				supportedCreds: newTree.supportedCreds(),
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

			if err := newTree.mergeUpdatePath(cs, senderLeafIndex, commit.path); err != nil {
				t.Errorf("ratchetTree.mergeUpdatePath() = %v", err)
			}

			newGroupCtx.treeHash, err = newTree.computeRootTreeHash(cs)
			if err != nil {
				t.Fatalf("ratchetTree.computeRootTreeHash() = %v", err)
			}

			// TODO: update group context extensions

			commitSecret, err = newTree.decryptPathSecrets(cs, &newGroupCtx, senderLeafIndex, myLeafIndex, commit.path, newPrivTree)
			if err != nil {
				t.Fatalf("ratchetTree.decryptPathSecrets() = %v", err)
			}
		} else {
			// TODO: only recompute parts of the tree affected by proposals
			newGroupCtx.treeHash, err = newTree.computeRootTreeHash(cs)
			if err != nil {
				t.Fatalf("ratchetTree.computeRootTreeHash() = %v", err)
			}
		}

		newGroupCtx.confirmedTranscriptHash, err = authContent.confirmedTranscriptHashInput().hash(cs, interimTranscriptHash)
		if err != nil {
			t.Fatalf("confirmedTranscriptHashInput.hash() = %v", err)
		}

		newInterimTranscriptHash, err := nextInterimTranscriptHash(cs, newGroupCtx.confirmedTranscriptHash, authContent.auth.confirmationTag)
		if err != nil {
			t.Fatalf("nextInterimTranscriptHash() = %v", err)
		}

		newPSKSecret, err := extractPSKSecret(cs, pskIDs, psks)
		if err != nil {
			t.Fatalf("extractPSKSecret() = %v", err)
		}

		newJoinerSecret, err := newGroupCtx.extractJoinerSecret(initSecret, commitSecret)
		if err != nil {
			t.Fatalf("groupContext.extractJoinerSecret() = %v", err)
		}

		newEpochSecret, err := newGroupCtx.extractEpochSecret(newJoinerSecret, newPSKSecret)
		if err != nil {
			t.Fatalf("groupContext.extractEpochSecret() = %v", err)
		}
		epochAuthenticator, err := cs.deriveSecret(newEpochSecret, secretLabelAuthentication)
		if err != nil {
			t.Fatalf("deriveSecret(authentication) = %v", err)
		} else if !bytes.Equal(epochAuthenticator, []byte(epoch.EpochAuthenticator)) {
			t.Errorf("deriveSecret(authentication) = %v, want %v", epochAuthenticator, epoch.EpochAuthenticator)
		}

		newInitSecret, err := cs.deriveSecret(newEpochSecret, secretLabelInit)
		if err != nil {
			t.Fatalf("deriveSecret(init) = %v", err)
		}

		confirmationKey, err := cs.deriveSecret(newEpochSecret, secretLabelConfirm)
		if err != nil {
			t.Fatalf("deriveSecret(confirm) = %v", err)
		}
		confirmationTag := cs.signMAC(confirmationKey, newGroupCtx.confirmedTranscriptHash)
		if !bytes.Equal(confirmationTag, authContent.auth.confirmationTag) {
			t.Errorf("invalid confirmation tag: got %v, want %v", confirmationTag, authContent.auth.confirmationTag)
		}

		tree = newTree
		privTree = newPrivTree
		groupCtx = newGroupCtx
		interimTranscriptHash = newInterimTranscriptHash
		pskSecret = newPSKSecret
		epochSecret = newEpochSecret
		initSecret = newInitSecret
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
