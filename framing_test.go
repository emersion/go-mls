package mls

import (
	"fmt"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

type unmarshaler interface {
	unmarshal(*cryptobyte.String) error
}

func testMessages(t *testing.T, tc map[string]testBytes) {
	// TODO: test decoding → encoding

	msgs := []struct {
		name string
		v    unmarshaler
	}{
		{"mls_welcome", new(mlsMessage)},
		{"mls_group_info", new(mlsMessage)},
		{"mls_key_package", new(mlsMessage)},
		{"public_message_application", new(mlsMessage)},
		{"public_message_proposal", new(mlsMessage)},
		{"public_message_commit", new(mlsMessage)},
		{"private_message", new(mlsMessage)},
		// TODO: other messages
	}
	for _, msg := range msgs {
		t.Run(msg.name, func(t *testing.T) {
			raw, ok := tc[msg.name]
			if !ok {
				t.Fatal("reference blob not found")
			}
			s := cryptobyte.String(raw)
			if err := msg.v.unmarshal(&s); err != nil {
				t.Fatal(err)
			}
			if !s.Empty() {
				t.Errorf("%v bytes unconsumed", len(s))
			}
		})
	}
}

func TestMessages(t *testing.T) {
	var tests []map[string]testBytes
	loadTestVector(t, "testdata/messages.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			testMessages(t, tc)
		})
	}
}
