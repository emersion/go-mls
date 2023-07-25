package mls

import (
	"bytes"
	"fmt"
	"testing"
)

func testMessages(t *testing.T, tc map[string]testBytes) {
	msgs := []struct {
		name string
		v    interface {
			unmarshaler
			marshaler
		}
	}{
		{"mls_welcome", new(mlsMessage)},
		{"mls_group_info", new(mlsMessage)},
		{"mls_key_package", new(mlsMessage)},

		{"ratchet_tree", new(ratchetTree)},
		{"group_secrets", new(groupSecrets)},

		{"add_proposal", new(add)},
		{"update_proposal", new(update)},
		{"remove_proposal", new(remove)},
		{"pre_shared_key_proposal", new(preSharedKey)},
		{"re_init_proposal", new(reInit)},
		{"external_init_proposal", new(externalInit)},
		{"group_context_extensions_proposal", new(groupContextExtensions)},

		{"commit", new(commit)},

		{"public_message_application", new(mlsMessage)},
		{"public_message_proposal", new(mlsMessage)},
		{"public_message_commit", new(mlsMessage)},
		{"private_message", new(mlsMessage)},
	}
	for _, msg := range msgs {
		t.Run(msg.name, func(t *testing.T) {
			raw, ok := tc[msg.name]
			if !ok {
				t.Fatal("reference blob not found")
			}
			if err := unmarshal(raw, msg.v); err != nil {
				t.Fatalf("unmarshal() = %v", err)
			}

			// TODO: enable for all messages
			switch msg.name {
			case "commit", "public_message_commit":
				return
			}

			out, err := marshal(msg.v)
			if err != nil {
				t.Errorf("marshal() = %v", err)
			} else if !bytes.Equal(out, raw) {
				t.Errorf("marshal() = \n%v\nbut want \n%v", out, raw)
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
