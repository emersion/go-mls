package mls

import (
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

	if err := welcome.process(keyPackageRef, []byte(tc.InitPriv), []byte(tc.SignerPub)); err != nil {
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
