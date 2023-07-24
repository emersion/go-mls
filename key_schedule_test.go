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
