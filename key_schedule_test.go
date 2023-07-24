package mls

import (
	"bytes"
	"fmt"
	"testing"
)

type pskSecretTest struct {
	CipherSuite cipherSuite `json:"cipher_suite"`

	PSKs []struct {
		PSKID    testBytes `json:"psk_id"`
		PSK      testBytes `json:"psk"`
		PSKNonce testBytes `json:"psk_nonce"`
	} `json:"psks"`

	PSKSecret testBytes `json:"psk_secret"`
}

func testPSKSecret(t *testing.T, tc *pskSecretTest) {
	var (
		pskIDs []preSharedKeyID
		psks   [][]byte
	)
	for _, psk := range tc.PSKs {
		pskIDs = append(pskIDs, preSharedKeyID{
			pskType:  pskTypeExternal,
			pskID:    []byte(psk.PSKID),
			pskNonce: []byte(psk.PSKNonce),
		})
		psks = append(psks, []byte(psk.PSK))
	}

	pskSecret, err := extractPSKSecret(tc.CipherSuite, pskIDs, psks)
	if err != nil {
		t.Fatalf("extractPSKSecret() = %v", err)
	}
	if !bytes.Equal(pskSecret, []byte(tc.PSKSecret)) {
		t.Errorf("extractPSKSecret() = %v, want %v", pskSecret, tc.PSKSecret)
	}
}

func TestPSKSecret(t *testing.T) {
	var tests []pskSecretTest
	loadTestVector(t, "testdata/psk_secret.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			testPSKSecret(t, &tc)
		})
	}
}

type keyScheduleTest struct {
	CipherSuite cipherSuite `json:"cipher_suite"`

	GroupID           testBytes `json:"group_id"`
	InitialInitSecret testBytes `json:"initial_init_secret"`

	Epochs []struct {
		TreeHash                testBytes `json:"tree_hash"`
		CommitSecret            testBytes `json:"commit_secret"`
		PSKSecret               testBytes `json:"psk_secret"`
		ConfirmedTranscriptHash testBytes `json:"confirmed_transcript_hash"`

		GroupContext testBytes `json:"group_context"`

		JoinerSecret  testBytes `json:"joiner_secret"`
		WelcomeSecret testBytes `json:"welcome_secret"`
		InitSecret    testBytes `json:"init_secret"`

		SenderDataSecret   testBytes `json:"sender_data_secret"`
		EncryptionSecret   testBytes `json:"encryption_secret"`
		ExporterSecret     testBytes `json:"exporter_secret"`
		EpochAuthenticator testBytes `json:"epoch_authenticator"`
		ExternalSecret     testBytes `json:"external_secret"`
		ConfirmationKey    testBytes `json:"confirmation_key"`
		MembershipKey      testBytes `json:"membership_key"`
		ResumptionPSK      testBytes `json:"resumption_psk"`

		ExternalPub testBytes `json:"external_pub"`
		Exporter    struct {
			Label   string    `json:"label"`
			Context testBytes `json:"context"`
			Length  uint32    `json:"length"`
			Secret  testBytes `json:"secret"`
		} `json:"exporter"`
	} `json:"epochs"`
}

func testKeySchedule(t *testing.T, tc *keyScheduleTest) {
	for i, epoch := range tc.Epochs {
		ctx := groupContext{
			version:                 protocolVersionMLS10,
			cipherSuite:             tc.CipherSuite,
			groupID:                 GroupID(tc.GroupID),
			epoch:                   uint64(i),
			treeHash:                []byte(epoch.TreeHash),
			confirmedTranscriptHash: []byte(epoch.ConfirmedTranscriptHash),
		}
		rawCtx, err := marshal(&ctx)
		if err != nil {
			t.Fatalf("marshal(groupContext) = %v", err)
		} else if !bytes.Equal(rawCtx, []byte(epoch.GroupContext)) {
			t.Errorf("marshal(groupContext) = %v, want %v", rawCtx, epoch.GroupContext)
		}

		// TODO: verify key schedule outputs, external pub, exporter secret
	}
}

func TestKeySchedule(t *testing.T) {
	var tests []keyScheduleTest
	loadTestVector(t, "testdata/key-schedule.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			testKeySchedule(t, &tc)
		})
	}
}
