package mls

import (
	"bytes"
	"fmt"
	"testing"
)

type cryptoBasicsTest struct {
	CipherSuite      cipherSuite          `json:"cipher_suite"`
	RefHash          refHashTest          `json:"ref_hash"`
	ExpandWithLabel  expandWithLabelTest  `json:"expand_with_label"`
	DeriveSecret     deriveSecretTest     `json:"derive_secret"`
	DeriveTreeSecret deriveTreeSecretTest `json:"derive_tree_secret"`
	SignWithLabel    signWithLabelTest    `json:"sign_with_label"`
	EncryptWithLabel encryptWithLabelTest `json:"encrypt_with_label"`
}

type refHashTest struct {
	Label string    `json:"label"`
	Out   testBytes `json:"out"`
	Value testBytes `json:"value"`
}

func testRefHash(t *testing.T, cs cipherSuite, tc *refHashTest) {
	out, err := cs.refHash([]byte(tc.Label), []byte(tc.Value))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal([]byte(tc.Out), out) {
		t.Errorf("got %v, want %v", out, tc.Out)
	}
}

type expandWithLabelTest struct {
	Secret  testBytes `json:"secret"`
	Label   string    `json:"label"`
	Context testBytes `json:"context"`
	Length  uint16    `json:"length"`
	Out     testBytes `json:"out"`
}

func testExpandWithLabel(t *testing.T, cs cipherSuite, tc *expandWithLabelTest) {
	out, err := cs.expandWithLabel([]byte(tc.Secret), []byte(tc.Label), []byte(tc.Context), tc.Length)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal([]byte(tc.Out), out) {
		t.Errorf("got %v, want %v", out, tc.Out)
	}
}

type deriveSecretTest struct {
	Label  string    `json:"label"`
	Out    testBytes `json:"out"`
	Secret testBytes `json:"secret"`
}

func testDeriveSecret(t *testing.T, cs cipherSuite, tc *deriveSecretTest) {
	out, err := cs.deriveSecret([]byte(tc.Secret), []byte(tc.Label))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal([]byte(tc.Out), out) {
		t.Errorf("got %v, want %v", out, tc.Out)
	}
}

type deriveTreeSecretTest struct {
	Secret     testBytes `json:"secret"`
	Label      string    `json:"label"`
	Generation uint32    `json:"generation"`
	Length     uint16    `json:"length"`
	Out        testBytes `json:"out"`
}

func testDeriveTreeSecret(t *testing.T, cs cipherSuite, tc *deriveTreeSecretTest) {
	out, err := cs.deriveTreeSecret([]byte(tc.Secret), []byte(tc.Label), tc.Generation, tc.Length)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal([]byte(tc.Out), out) {
		t.Errorf("got %v, want %v", out, tc.Out)
	}
}

type signWithLabelTest struct {
	Priv      testBytes `json:"priv"`
	Pub       testBytes `json:"pub"`
	Content   testBytes `json:"content"`
	Label     string    `json:"label"`
	Signature testBytes `json:"signature"`
}

func testSignWithLabel(t *testing.T, cs cipherSuite, tc *signWithLabelTest) {
	if !cs.verifyWithLabel([]byte(tc.Pub), []byte(tc.Label), []byte(tc.Content), []byte(tc.Signature)) {
		t.Error("reference signature did not verify")
	}

	signValue, err := cs.signWithLabel([]byte(tc.Priv), []byte(tc.Label), []byte(tc.Content))
	if err != nil {
		t.Fatalf("signWithLabel() = %v", err)
	}
	if !cs.verifyWithLabel([]byte(tc.Pub), []byte(tc.Label), []byte(tc.Content), signValue) {
		t.Error("generated signature did not verify")
	}
}

type encryptWithLabelTest struct {
	Priv       testBytes `json:"priv"`
	Pub        testBytes `json:"pub"`
	Label      string    `json:"label"`
	Context    testBytes `json:"context"`
	Plaintext  testBytes `json:"plaintext"`
	KEMOutput  testBytes `json:"kem_output"`
	Ciphertext testBytes `json:"ciphertext"`
}

func testEncryptWithLabel(t *testing.T, cs cipherSuite, tc *encryptWithLabelTest) {
	plaintext, err := cs.decryptWithLabel([]byte(tc.Priv), []byte(tc.Label), []byte(tc.Context), []byte(tc.KEMOutput), []byte(tc.Ciphertext))
	if err != nil {
		t.Fatalf("decryptWithLabel() = %v", err)
	}
	if !bytes.Equal([]byte(tc.Plaintext), plaintext) {
		t.Fatalf("decrypting reference ciphertext: got %v, want %v", plaintext, tc.Plaintext)
	}

	kemOutput, ciphertext, err := cs.encryptWithLabel([]byte(tc.Pub), []byte(tc.Label), []byte(tc.Context), []byte(tc.Plaintext))
	if err != nil {
		t.Fatalf("encryptWithLabel() = %v", err)
	}
	plaintext, err = cs.decryptWithLabel([]byte(tc.Priv), []byte(tc.Label), []byte(tc.Context), kemOutput, ciphertext)
	if err != nil {
		t.Fatalf("decryptWithLabel() = %v", err)
	}
	if !bytes.Equal([]byte(tc.Plaintext), plaintext) {
		t.Fatalf("decrypting reference ciphertext: got %v, want %v", plaintext, tc.Plaintext)
	}
}

func TestCryptoBasics(t *testing.T) {
	var tests []cryptoBasicsTest
	loadTestVector(t, "testdata/crypto-basics.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			t.Run("ref_hash", func(t *testing.T) {
				testRefHash(t, tc.CipherSuite, &tc.RefHash)
			})
			t.Run("expand_with_label", func(t *testing.T) {
				testExpandWithLabel(t, tc.CipherSuite, &tc.ExpandWithLabel)
			})
			t.Run("derive_secret", func(t *testing.T) {
				testDeriveSecret(t, tc.CipherSuite, &tc.DeriveSecret)
			})
			t.Run("derive_tree_secret", func(t *testing.T) {
				testDeriveTreeSecret(t, tc.CipherSuite, &tc.DeriveTreeSecret)
			})
			t.Run("sign_with_label", func(t *testing.T) {
				testSignWithLabel(t, tc.CipherSuite, &tc.SignWithLabel)
			})
			t.Run("encrypt_with_label", func(t *testing.T) {
				testEncryptWithLabel(t, tc.CipherSuite, &tc.EncryptWithLabel)
			})
		})
	}
}
