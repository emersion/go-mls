package mls

// This package uses an array-based representation of complete balanced binary
// trees, as described in appendix C. For example, a tree with 8 leaves:
//
//                               X
//                               |
//                     .---------+---------.
//                    /                     \
//                   X                       X
//                   |                       |
//               .---+---.               .---+---.
//              /         \             /         \
//             X           X           X           X
//            / \         / \         / \         / \
//           /   \       /   \       /   \       /   \
//          X     X     X     X     X     X     X     X
//
//    Node: 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14
//
//    Leaf: 0     1     2     3     4     5     6     7

// numLeaves exposes operations on a tree with a given number of leaves.
type numLeaves uint32

func numLeavesFromWidth(w uint32) numLeaves {
	if w == 0 {
		return 0
	}
	return numLeaves((w-1)/2 + 1)
}

// width computes the minimum length of the array, ie. the number of nodes.
func (n numLeaves) width() uint32 {
	if n == 0 {
		return 0
	}
	return 2*(uint32(n)-1) + 1
}

// root returns the index of the root node.
func (n numLeaves) root() nodeIndex {
	return nodeIndex((1 << log2(n.width())) - 1)
}

// parent returns the index of the parent node for a non-root node index.
func (n numLeaves) parent(x nodeIndex) (nodeIndex, bool) {
	if x == n.root() {
		return 0, false
	}
	lvl := nodeIndex(x.level())
	b := (x >> (lvl + 1)) & 1
	p := (x | (1 << lvl)) ^ (b << (lvl + 1))
	return p, true
}

// sibling returns the index of the other child of the node's parent.
func (n numLeaves) sibling(x nodeIndex) (nodeIndex, bool) {
	p, ok := n.parent(x)
	if !ok {
		return 0, false
	}
	if x < p {
		return p.right()
	} else {
		return p.left()
	}
}

// directPath computes the direct path of a node, ordered from leaf to root.
func (n numLeaves) directPath(x nodeIndex) []nodeIndex {
	var path []nodeIndex
	for {
		x, ok := n.parent(x)
		if !ok {
			break
		}
		path = append(path, x)
	}
	return path
}

// copath computes the copath of a node, ordered from leaf to root.
func (n numLeaves) copath(x nodeIndex) []nodeIndex {
	path := n.directPath(x)
	if len(path) == 0 {
		return nil
	}
	path = append([]nodeIndex{x}, path...)
	path = path[:len(path)-1]

	var copath []nodeIndex
	for _, y := range path {
		s, ok := n.sibling(y)
		if !ok {
			panic("unreachable")
		}
		copath = append(copath, s)
	}

	return copath
}

// nodeIndex is the index of a node in a tree.
type nodeIndex uint32

// isLeaf returns true if this is a leaf node, false if this is an intermediate
// node.
func (x nodeIndex) isLeaf() bool {
	return x%2 == 0
}

// leafIndex returns the index of the leaf from a node index.
func (x nodeIndex) leafIndex() (leafIndex, bool) {
	if !x.isLeaf() {
		return 0, false
	}
	return leafIndex(x) >> 1, true
}

// left returns the index of the left child for an intermediate node index.
func (x nodeIndex) left() (nodeIndex, bool) {
	lvl := x.level()
	if lvl == 0 {
		return 0, false
	}
	l := x ^ (1 << (nodeIndex(lvl) - 1))
	return l, true
}

// right returns the index of the right child for an intermediate node index.
func (x nodeIndex) right() (nodeIndex, bool) {
	lvl := x.level()
	if lvl == 0 {
		return 0, false
	}
	r := x ^ (3 << (nodeIndex(lvl) - 1))
	return r, true
}

// children returns the indices of the left and right children for an
// intermediate node index.
func (x nodeIndex) children() (left, right nodeIndex, ok bool) {
	l, ok := x.left()
	if !ok {
		return 0, 0, false
	}
	r, _ := x.right()
	return l, r, true
}

// level returns the level of a node in the tree. Leaves are at level 0, their
// parents are at level 1, etc.
func (x nodeIndex) level() uint32 {
	if x&1 == 0 {
		return 0
	}
	lvl := uint32(0)
	for (x>>lvl)&1 == 1 {
		lvl++
	}
	return lvl
}

type leafIndex uint32

// nodeIndex returns the index of the node from a leaf index.
func (li leafIndex) nodeIndex() nodeIndex {
	return nodeIndex(2 * li)
}

// log2 computes the exponent of the largest power of 2 less than x.
func log2(x uint32) uint32 {
	if x == 0 {
		return 0
	}

	k := uint32(0)
	for x>>k > 0 {
		k++
	}
	return k - 1
}

func isPowerOf2(x uint32) bool {
	return x != 0 && x&(x-1) == 0
}
