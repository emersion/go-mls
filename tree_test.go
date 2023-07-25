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

type treeOperationsTest struct {
	TreeBefore     testBytes `json:"tree_before"`
	Proposal       testBytes `json:"proposal"`
	ProposalSender leafIndex `json:"proposal_sender"`

	TreeAfter testBytes `json:"tree_after"`
}

func testTreeOperations(t *testing.T, tc *treeOperationsTest) {
	var tree ratchetTree
	if err := unmarshal([]byte(tc.TreeBefore), &tree); err != nil {
		t.Fatalf("unmarshal(tree) = %v", err)
	}

	var prop proposal
	if err := unmarshal([]byte(tc.Proposal), &prop); err != nil {
		t.Fatalf("unmarshal(proposal) = %v", err)
	}

	switch prop.proposalType {
	case proposalTypeAdd:
		ctx := groupContext{
			version:     prop.add.keyPackage.version,
			cipherSuite: prop.add.keyPackage.cipherSuite,
		}
		if err := prop.add.keyPackage.verify(&ctx); err != nil {
			t.Errorf("keyPackage.verify() = %v", err)
		}
		tree.add(&prop.add.keyPackage.leafNode)
	case proposalTypeUpdate:
		// TODO: verify leaf node
		tree.update(tc.ProposalSender, &prop.update.leafNode)
	case proposalTypeRemove:
		// TODO: verify leaf index
		tree.remove(prop.remove.removed)
	default:
		panic("unreachable")
	}

	rawTree, err := marshal(&tree)
	if err != nil {
		t.Fatalf("marshal(tree) = %v", err)
	} else if !bytes.Equal(rawTree, []byte(tc.TreeAfter)) {
		t.Errorf("marshal(tree) = %v, want %v", rawTree, tc.TreeAfter)
	}
}

func TestTreeOperations(t *testing.T) {
	var tests []treeOperationsTest
	loadTestVector(t, "testdata/tree-operations.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			testTreeOperations(t, &tc)
		})
	}
}
