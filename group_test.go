package mls

import (
	"bytes"
	"fmt"
	"testing"
)

type welcomeTest struct {
	CipherSuite cipherSuite `json:"cipher_suite"`

	InitPriv  testBytes `json:"init_priv"`
	SignerPub testBytes `json:"signer_pub"`

	KeyPackage testBytes `json:"key_package"`
	Welcome    testBytes `json:"welcome"`
}

func testWelcome(t *testing.T, tc *welcomeTest) {
	var welcomeMsg mlsMessage
	if err := welcomeMsg.unmarshal(tc.Welcome.ByteString()); err != nil {
		t.Fatalf("unmarshal(welcome) = %v", err)
	} else if welcomeMsg.wireFormat != wireFormatMLSWelcome {
		t.Fatalf("wireFormat = %v, want %v", welcomeMsg.wireFormat, wireFormatMLSWelcome)
	}
	welcome := welcomeMsg.welcome

	var keyPackageMsg mlsMessage
	if err := keyPackageMsg.unmarshal(tc.KeyPackage.ByteString()); err != nil {
		t.Fatalf("unmarshal(keyPackage) = %v", err)
	} else if keyPackageMsg.wireFormat != wireFormatMLSKeyPackage {
		t.Fatalf("wireFormat = %v, want %v", keyPackageMsg.wireFormat, wireFormatMLSKeyPackage)
	}
	keyPackage := keyPackageMsg.keyPackage

	keyPackageRef, err := keyPackage.generateRef()
	if err != nil {
		t.Fatalf("keyPackage.generateRef() = %v", err)
	}

	groupSecrets, err := welcome.decryptGroupSecrets(keyPackageRef, []byte(tc.InitPriv))
	if err != nil {
		t.Fatalf("welcome.decryptGroupSecrets() = %v", err)
	}

	groupInfo, err := welcome.decryptGroupInfo(groupSecrets.joinerSecret, nil)
	if err != nil {
		t.Fatalf("welcome.decryptGroupInfo() = %v", err)
	}
	if !groupInfo.verifySignature(signaturePublicKey(tc.SignerPub)) {
		t.Errorf("groupInfo.verifySignature() failed")
	}
	if !groupInfo.verifyConfirmationTag(groupSecrets.joinerSecret, nil) {
		t.Errorf("groupInfo.verifyConfirmationTag() failed")
	}
}

func TestWelcome(t *testing.T) {
	var tests []welcomeTest
	loadTestVector(t, "testdata/welcome.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			testWelcome(t, &tc)
		})
	}
}

type messageProtectionTest struct {
	CipherSuite cipherSuite `json:"cipher_suite"`

	GroupID                 testBytes `json:"group_id"`
	Epoch                   uint64    `json:"epoch"`
	TreeHash                testBytes `json:"tree_hash"`
	ConfirmedTranscriptHash testBytes `json:"confirmed_transcript_hash"`

	SignaturePriv testBytes `json:"signature_priv"`
	SignaturePub  testBytes `json:"signature_pub"`

	EncryptionSecret testBytes `json:"encryption_secret"`
	SenderDataSecret testBytes `json:"sender_data_secret"`
	MembershipKey    testBytes `json:"membership_key"`

	Proposal     testBytes `json:"proposal"`
	ProposalPub  testBytes `json:"proposal_pub"`
	ProposalPriv testBytes `json:"proposal_priv"`

	Commit     testBytes `json:"commit"`
	CommitPub  testBytes `json:"commit_pub"`
	CommitPriv testBytes `json:"commit_priv"`

	Application     testBytes `json:"application"`
	ApplicationPriv testBytes `json:"application_priv"`
}

func testMessageProtectionPub(t *testing.T, tc *messageProtectionTest, ctx *groupContext, wantRaw, rawPub []byte) {
	// TODO: test roundtrip

	var msg mlsMessage
	if err := unmarshal(rawPub, &msg); err != nil {
		t.Fatalf("unmarshal() = %v", err)
	} else if msg.wireFormat != wireFormatMLSPublicMessage {
		t.Fatalf("unmarshal(): wireFormat = %v, want %v", msg.wireFormat, wireFormatMLSPublicMessage)
	}
	pubMsg := msg.publicMessage

	authContent := pubMsg.authenticatedContent()
	if !authContent.verifySignature(tc.CipherSuite, []byte(tc.SignaturePub), ctx) {
		t.Errorf("verifySignature() failed")
	}

	if pubMsg.content.sender.senderType == senderTypeMember {
		if !pubMsg.verifyMembershipTag(tc.CipherSuite, []byte(tc.MembershipKey), ctx) {
			t.Errorf("verifyMembershipTag() failed")
		}
	}

	var (
		raw []byte
		err error
	)
	switch pubMsg.content.contentType {
	case contentTypeApplication:
		raw = pubMsg.content.applicationData
	case contentTypeProposal:
		raw, err = marshal(pubMsg.content.proposal)
	case contentTypeCommit:
		raw, err = marshal(pubMsg.content.commit)
	default:
		t.Errorf("unexpected content type %v", pubMsg.content.contentType)
	}
	if err != nil {
		t.Errorf("marshal() = %v", err)
	} else if !bytes.Equal(raw, wantRaw) {
		t.Errorf("marshal() = %v, want %v", raw, wantRaw)
	}
}

func testMessageProtectionPriv(t *testing.T, tc *messageProtectionTest, ctx *groupContext, wantRaw, rawPriv []byte) {
	// TODO: test roundtrip

	var msg mlsMessage
	if err := unmarshal(rawPriv, &msg); err != nil {
		t.Fatalf("unmarshal() = %v", err)
	} else if msg.wireFormat != wireFormatMLSPrivateMessage {
		t.Fatalf("unmarshal(): wireFormat = %v, want %v", msg.wireFormat, wireFormatMLSPrivateMessage)
	}
	privMsg := msg.privateMessage

	senderData, err := privMsg.decryptSenderData(tc.CipherSuite, []byte(tc.SenderDataSecret))
	if err != nil {
		t.Fatalf("decryptSenderData() = %v", err)
	}

	tree, err := deriveSecretTree(tc.CipherSuite, numLeaves(2), []byte(tc.EncryptionSecret))
	if err != nil {
		t.Fatalf("deriveSecretTree() = %v", err)
	}

	label := ratchetLabelFromContentType(privMsg.contentType)
	li := leafIndex(1)
	secret, err := tree.deriveRatchetRoot(tc.CipherSuite, li.nodeIndex(), label)
	if err != nil {
		t.Fatalf("deriveRatchetRoot() = %v", err)
	}
	for secret.generation != senderData.generation {
		secret, err = secret.deriveNext(tc.CipherSuite)
		if err != nil {
			t.Fatalf("deriveNext() = %v", err)
		}
	}

	content, err := privMsg.decryptContent(tc.CipherSuite, secret, senderData.reuseGuard)
	if err != nil {
		t.Fatalf("decryptContent() = %v", err)
	}

	authContent := privMsg.authenticatedContent(senderData, content)
	if !authContent.verifySignature(tc.CipherSuite, []byte(tc.SignaturePub), ctx) {
		t.Errorf("verifySignature() failed")
	}

	var raw []byte
	switch privMsg.contentType {
	case contentTypeApplication:
		raw = content.applicationData
	case contentTypeProposal:
		raw, err = marshal(content.proposal)
	case contentTypeCommit:
		raw, err = marshal(content.commit)
	default:
		t.Errorf("unexpected content type %v", privMsg.contentType)
	}
	if err != nil {
		t.Errorf("marshal() = %v", err)
	} else if !bytes.Equal(raw, wantRaw) {
		t.Errorf("marshal() = %v, want %v", raw, wantRaw)
	}
}

func testMessageProtection(t *testing.T, tc *messageProtectionTest) {
	ctx := groupContext{
		version:                 protocolVersionMLS10,
		cipherSuite:             tc.CipherSuite,
		groupID:                 GroupID(tc.GroupID),
		epoch:                   tc.Epoch,
		treeHash:                []byte(tc.TreeHash),
		confirmedTranscriptHash: []byte(tc.ConfirmedTranscriptHash),
	}

	wireFormats := []struct {
		name           string
		raw, pub, priv testBytes
	}{
		{"proposal", tc.Proposal, tc.ProposalPub, tc.ProposalPriv},
		{"commit", tc.Commit, tc.CommitPub, tc.CommitPriv},
		{"application", tc.Application, nil, tc.ApplicationPriv},
	}
	for _, wireFormat := range wireFormats {
		t.Run(wireFormat.name, func(t *testing.T) {
			raw := []byte(wireFormat.raw)
			pub := []byte(wireFormat.pub)
			priv := []byte(wireFormat.priv)
			if wireFormat.pub != nil {
				t.Run("pub", func(t *testing.T) {
					testMessageProtectionPub(t, tc, &ctx, raw, pub)
				})
			}
			t.Run("priv", func(t *testing.T) {
				testMessageProtectionPriv(t, tc, &ctx, raw, priv)
			})
		})
	}
}

func TestMessageProtection(t *testing.T) {
	var tests []messageProtectionTest
	loadTestVector(t, "testdata/message-protection.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			testMessageProtection(t, &tc)
		})
	}
}
