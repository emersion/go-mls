package mls

import (
	"fmt"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

type messagesTest struct {
	MLSWelcome    testBytes `json:"mls_welcome"`
	MLSGroupInfo  testBytes `json:"mls_group_info"`
	MLSKeyPackage testBytes `json:"mls_key_package"`

	RatchetTree  testBytes `json:"ratchet_tree"`
	GroupSecrets testBytes `json:"group_secrets"`

	AddProposal                    testBytes `json:"add_proposal"`
	UpdateProposal                 testBytes `json:"update_proposal"`
	RemoveProposal                 testBytes `json:"remove_proposal"`
	PreSharedKeyProposal           testBytes `json:"pre_shared_key_proposal"`
	ReInitProposal                 testBytes `json:"re_init_proposal"`
	ExternalInitProposal           testBytes `json:"external_init_proposal"`
	GroupContextExtensionsProposal testBytes `json:"group_context_extensions_proposal"`

	Commit testBytes `json:"commit"`

	PublicMessageApplication testBytes `json:"public_message_application"`
	PublicMessageProposal    testBytes `json:"public_message_proposal"`
	PublicMessageCommit      testBytes `json:"public_message_commit"`
	PrivateMessage           testBytes `json:"private_message"`
}

func testMessages(t *testing.T, tc *messagesTest) {
	msgs := []struct {
		name string
		b    []byte
	}{
		{"mls_welcome", []byte(tc.MLSWelcome)},
		//{"mls_group_info", []byte(tc.MLSGroupInfo)},
		//{"mls_key_package", []byte(tc.MLSKeyPackage)},
		{"public_message_application", []byte(tc.PublicMessageApplication)},
		//{"public_message_proposal", []byte(tc.PublicMessageProposal)},
		//{"public_message_commit", []byte(tc.PublicMessageCommit)},
		{"private_message", []byte(tc.PrivateMessage)},
	}

	for _, msg := range msgs {
		t.Run(msg.name, func(t *testing.T) {
			s := cryptobyte.String(msg.b)
			_, err := unmarshalMLSMessage(&s)
			if err != nil {
				t.Fatal(err)
			}
			if !s.Empty() {
				t.Errorf("%v bytes unconsumed", len(s))
			}
			// TODO: test decoding → encoding
		})
	}
}

func TestMessages(t *testing.T) {
	var tests []messagesTest
	loadTestVector(t, "testdata/messages.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			testMessages(t, &tc)
		})
	}
}
