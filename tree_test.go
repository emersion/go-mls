package mls

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
	"time"
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

type treeKEMTest struct {
	CipherSuite cipherSuite `json:"cipher_suite"`

	GroupID                 testBytes `json:"group_id"`
	Epoch                   uint64    `json:"epoch"`
	ConfirmedTranscriptHash testBytes `json:"confirmed_transcript_hash"`

	RatchetTree testBytes `json:"ratchet_tree"`

	LeavesPrivate []struct {
		Index          leafIndex `json:"index"`
		EncryptionPriv testBytes `json:"encryption_priv"`
		SignaturePriv  testBytes `json:"signature_priv"`
		PathSecrets    []struct {
			Node       nodeIndex `json:"node"`
			PathSecret testBytes `json:"path_secret"`
		} `json:"path_secrets"`
	} `json:"leaves_private"`

	UpdatePaths []struct {
		Sender        leafIndex   `json:"sender"`
		UpdatePath    testBytes   `json:"update_path"`
		PathSecrets   []testBytes `json:"path_secrets"`
		CommitSecret  testBytes   `json:"commit_secret"`
		TreeHashAfter testBytes   `json:"tree_hash_after"`
	} `json:"update_paths"`
}

func testTreeKEM(t *testing.T, tc *treeKEMTest) {
	// TODO: test leaves_private

	for _, updatePathTest := range tc.UpdatePaths {
		var tree ratchetTree
		if err := unmarshal([]byte(tc.RatchetTree), &tree); err != nil {
			t.Fatalf("unmarshal(ratchetTree) = %v", err)
		}

		var up updatePath
		if err := unmarshal([]byte(updatePathTest.UpdatePath), &up); err != nil {
			t.Fatalf("unmarshal(updatePath) = %v", err)
		}

		// TODO: verify that UpdatePath is parent-hash valid relative to ratchet tree
		// TODO: process UpdatePath using private leaves

		if err := tree.mergeUpdatePath(tc.CipherSuite, updatePathTest.Sender, &up); err != nil {
			t.Fatalf("ratchetTree.mergeUpdatePath() = %v", err)
		}

		treeHash, err := tree.computeRootTreeHash(tc.CipherSuite)
		if err != nil {
			t.Errorf("ratchetTree.computeRootTreeHash() = %v", err)
		} else if !bytes.Equal(treeHash, []byte(updatePathTest.TreeHashAfter)) {
			t.Errorf("ratchetTree.computeRootTreeHash() = %v, want %v", treeHash, updatePathTest.TreeHashAfter)
		}

		// TODO: create and verify new update path
	}
}

func TestTreeKEM(t *testing.T) {
	var tests []treeKEMTest
	loadTestVector(t, "testdata/treekem.json", &tests)

	for i, tc := range tests {
		t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
			testTreeKEM(t, &tc)
		})
	}
}

type treeOperationsTest struct {
	CipherSuite cipherSuite `json:"cipher_suite"`

	TreeBefore     testBytes `json:"tree_before"`
	Proposal       testBytes `json:"proposal"`
	ProposalSender leafIndex `json:"proposal_sender"`

	TreeHashBefore testBytes `json:"tree_hash_before"`
	TreeAfter      testBytes `json:"tree_after"`
	TreeHashAfter  testBytes `json:"tree_hash_after"`
}

func testTreeOperations(t *testing.T, tc *treeOperationsTest) {
	var tree ratchetTree
	if err := unmarshal([]byte(tc.TreeBefore), &tree); err != nil {
		t.Fatalf("unmarshal(tree) = %v", err)
	}

	treeHash, err := tree.computeRootTreeHash(tc.CipherSuite)
	if err != nil {
		t.Errorf("ratchetTree.computeRootTreeHash() = %v", err)
	} else if !bytes.Equal(treeHash, []byte(tc.TreeHashBefore)) {
		t.Errorf("ratchetTree.computeRootTreeHash() = %v, want %v", treeHash, tc.TreeHashBefore)
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
		signatureKeys, encryptionKeys := tree.keys()
		err := prop.update.leafNode.verify(&leafNodeVerifyOptions{
			cipherSuite:    tc.CipherSuite,
			groupID:        nil,
			leafIndex:      tc.ProposalSender,
			supportedCreds: tree.supportedCreds(),
			signatureKeys:  signatureKeys,
			encryptionKeys: encryptionKeys,
			now:            func() time.Time { return time.Time{} },
		})
		if err != nil {
			t.Errorf("leafNode.verify() = %v", err)
		}
		tree.update(tc.ProposalSender, &prop.update.leafNode)
	case proposalTypeRemove:
		if tree.getLeaf(prop.remove.removed) == nil {
			t.Errorf("leaf node %v is blank", prop.remove.removed)
		}
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

	treeHash, err = tree.computeRootTreeHash(tc.CipherSuite)
	if err != nil {
		t.Errorf("ratchetTree.computeRootTreeHash() = %v", err)
	} else if !bytes.Equal(treeHash, []byte(tc.TreeHashAfter)) {
		t.Errorf("ratchetTree.computeRootTreeHash() = %v, want %v", treeHash, tc.TreeHashAfter)
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
