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

	if err := welcome.process(keyPackageRef, []byte(tc.InitPriv), signaturePublicKey(tc.SignerPub)); err != nil {
		t.Fatalf("welcome.process() = %v", err)
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

func testMessageProtectionWireFormat(t *testing.T, tc *messageProtectionTest, ctx *groupContext, wantRaw, rawPub, rawPriv []byte) {
	// TODO: check raw matches, roundtrip pub, rawPriv, roundtrip priv

	if len(rawPub) == 0 {
		return
	}

	var msg mlsMessage
	if err := unmarshal(rawPub, &msg); err != nil {
		t.Fatalf("unmarshal(pub) = %v", err)
	} else if msg.wireFormat != wireFormatMLSPublicMessage {
		t.Fatalf("unmarshal(pub): wireFormat = %v, want %v", msg.wireFormat, wireFormatMLSPublicMessage)
	}
	pubMsg := msg.publicMessage

	framedContentTBS := framedContentTBS{
		version:    msg.version,
		wireFormat: msg.wireFormat,
		content:    pubMsg.content,
		context:    ctx,
	}
	if !pubMsg.auth.verify(tc.CipherSuite, []byte(tc.SignaturePub), &framedContentTBS) {
		t.Errorf("verify(pub) failed")
	}
	// TODO: check membership tag

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
		t.Errorf("marshal(pub) = %v", err)
	} else if !bytes.Equal(raw, wantRaw) {
		t.Errorf("marshal(pub) = %v, want %v", raw, wantRaw)
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
			testMessageProtectionWireFormat(t, tc, &ctx, []byte(wireFormat.raw), []byte(wireFormat.pub), []byte(wireFormat.priv))
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
