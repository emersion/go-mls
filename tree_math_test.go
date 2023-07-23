package mls

import (
	"fmt"
	"testing"
)

type treeMathTest struct {
	NLeaves numLeaves `json:"n_leaves"`

	NNodes  uint32       `json:"n_nodes"`
	Root    nodeIndex    `json:"root"`
	Left    []*nodeIndex `json:"left"`
	Right   []*nodeIndex `json:"right"`
	Parent  []*nodeIndex `json:"parent"`
	Sibling []*nodeIndex `json:"sibling"`
}

func testTreeMath(t *testing.T, tc *treeMathTest) {
	n := tc.NLeaves
	if w := n.width(); w != tc.NNodes {
		t.Errorf("width(%v) = %v, want %v", n, w, tc.NNodes)
	}
	if r := n.root(); r != tc.Root {
		t.Errorf("root(%v) = %v, want %v", n, r, tc.Root)
	}
	for i, want := range tc.Left {
		x := nodeIndex(i)
		l := newOptionalNodeIndex(x.left())
		if !optionalNodeIndexEqual(l, want) {
			t.Errorf("left(%v) = %v, want %v", x, l, want)
		}
	}
	for i, want := range tc.Right {
		x := nodeIndex(i)
		r := newOptionalNodeIndex(x.right())
		if !optionalNodeIndexEqual(r, want) {
			t.Errorf("right(%v) = %v, want %v", x, r, want)
		}
	}
	for i, want := range tc.Parent {
		x := nodeIndex(i)
		p := newOptionalNodeIndex(n.parent(x))
		if !optionalNodeIndexEqual(p, want) {
			t.Errorf("parent(%v) = %v, want %v", x, p, want)
		}
	}
	for i, want := range tc.Sibling {
		x := nodeIndex(i)
		s := newOptionalNodeIndex(n.sibling(x))
		if !optionalNodeIndexEqual(s, want) {
			t.Errorf("sibling(%v) = %v, want %v", x, s, want)
		}
	}
}

func newOptionalNodeIndex(x nodeIndex, ok bool) *nodeIndex {
	if !ok {
		return nil
	}
	return &x
}

func optionalNodeIndexEqual(x, y *nodeIndex) bool {
	if x == nil || y == nil {
		return x == nil && y == nil
	}
	return *x == *y
}

func TestTreeMath(t *testing.T) {
	var tests []treeMathTest
	loadTestVector(t, "testdata/tree-math.json", &tests)

	for _, tc := range tests {
		t.Run(fmt.Sprintf("numLeaves(%v)", tc.NLeaves), func(t *testing.T) {
			testTreeMath(t, &tc)
		})
	}
}
