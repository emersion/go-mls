package mls

import (
	"encoding"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type testBytes []byte

var _ encoding.TextUnmarshaler = (*testBytes)(nil)

func (out *testBytes) UnmarshalText(text []byte) error {
	*out = make([]byte, hex.DecodedLen(len(text)))
	_, err := hex.Decode(*out, text)
	return err
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
