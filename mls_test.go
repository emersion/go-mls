package mls

import (
	"encoding"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

type testBytes []byte

var _ encoding.TextUnmarshaler = (*testBytes)(nil)

func (out *testBytes) UnmarshalText(text []byte) error {
	*out = make([]byte, hex.DecodedLen(len(text)))
	_, err := hex.Decode(*out, text)
	return err
}

func (tb testBytes) ByteString() *cryptobyte.String {
	s := cryptobyte.String(tb)
	return &s
}

func loadTestVector(t *testing.T, filename string, v interface{}) {
	f, err := os.Open(filename)
	if err != nil {
		t.Fatalf("failed to open test vector %q: %v", filename, err)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(v); err != nil {
		t.Fatalf("failed to load test vector %q: %v", filename, err)
	}
}

type deserializationTest struct {
	VLBytesHeader testBytes `json:"vlbytes_header"`
	Length        uint32    `json:"length"`
}

func TestDeserialization(t *testing.T) {
	var tests []deserializationTest
	loadTestVector(t, "testdata/deserialization.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			var length uint32
			s := tc.VLBytesHeader.ByteString()
			if !readVarint(s, &length) {
				t.Fatalf("readVarint() = false")
			} else if !s.Empty() {
				t.Errorf("byte string should be empty after readVarint()")
			}
			if length != tc.Length {
				t.Errorf("got %v, want %v", length, tc.Length)
			}
		})
	}
}
