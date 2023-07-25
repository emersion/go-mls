package mls

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

type treeValidationTest struct {
	CipherSuite cipherSuite `json:"cipher_suite"`

	Tree    testBytes `json:"tree"`
	GroupID testBytes `json:"group_id"`

	Resolutions [][]nodeIndex `json:"resolutions"`
	TreeHashes  []testBytes   `json:"tree_hashes"`
}

func testTreeValidation(t *testing.T, tc *treeValidationTest) {
	var tree ratchetTree
	if err := unmarshal([]byte(tc.Tree), &tree); err != nil {
		t.Fatalf("unmarshal(tree) = %v", err)
	}

	for i, want := range tc.Resolutions {
		x := nodeIndex(i)
		res := tree.resolve(x)
		if len(res) == 0 {
			res = make([]nodeIndex, 0)
		}
		if !reflect.DeepEqual(res, want) {
			t.Errorf("resolve(%v) = %v, want %v", x, res, want)
		}
	}

	for i, want := range tc.TreeHashes {
		x := nodeIndex(i)
		if h, err := tree.computeTreeHash(tc.CipherSuite, x, nil); err != nil {
			t.Errorf("computeTreeHash(%v) = %v", x, err)
		} else if !bytes.Equal(h, []byte(want)) {
			t.Errorf("computeTreeHash(%v) = %v, want %v", x, h, want)
		}
	}

	if !tree.verifyParentHashes(tc.CipherSuite) {
		t.Errorf("verifyParentHashes() failed")
	}

	groupID := GroupID(tc.GroupID)
	for i, node := range tree {
		if node == nil || node.nodeType != nodeTypeLeaf {
			continue
		}
		li, ok := nodeIndex(i).leafIndex()
		if !ok {
			t.Errorf("leafIndex(%v) = false", i)
			continue
		}
		if !node.leafNode.verifySignature(tc.CipherSuite, groupID, li) {
			t.Errorf("verify(%v) = false", li)
		}
	}
}

func TestTreeValidation(t *testing.T) {
	var tests []treeValidationTest
	loadTestVector(t, "testdata/tree-validation.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			testTreeValidation(t, &tc)
		})
	}
}
