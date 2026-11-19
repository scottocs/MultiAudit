package multiaudit

import (
	"bytes"
	"errors"
	"multiaudit/schemes/benchcore"
	"sort"
)

// MultiAudit's tree uses file/position-bound padding. The other protocols keep
// their existing benchcore tree and individual-path semantics unchanged.
type compactTree struct {
	levels [][][]byte
	count  int
	Root   []byte
}

func merkleNode(a, b []byte) []byte { return benchcore.HashBytes("multiaudit:merkle:node", a, b) }
func newCompactTree(id []byte, leaves [][]byte) (*compactTree, error) {
	if len(leaves) == 0 {
		return nil, errors.New("empty tree")
	}
	size := 1
	for size < len(leaves) {
		size *= 2
	}
	level := make([][]byte, size)
	for j := range level {
		if j < len(leaves) {
			level[j] = benchcore.CloneBytes(leaves[j])
		} else {
			level[j] = benchcore.HashBytes("multiaudit:merkle:pad", id, benchcore.IntBytes(len(leaves)), benchcore.IntBytes(j+1))
		}
	}
	t := &compactTree{count: len(leaves), levels: [][][]byte{level}}
	for len(level) > 1 {
		next := make([][]byte, len(level)/2)
		for j := range next {
			next[j] = merkleNode(level[2*j], level[2*j+1])
		}
		t.levels = append(t.levels, next)
		level = next
	}
	t.Root = benchcore.CloneBytes(level[0])
	return t, nil
}
func validIndices(indices []int, n int) bool {
	if n < 1 || len(indices) < 1 {
		return false
	}
	last := -1
	for _, j := range indices {
		if j <= last || j >= n {
			return false
		}
		last = j
	}
	return true
}
func frontierParents(indices []int) []int {
	out := make([]int, 0, len(indices))
	last := -1
	for _, j := range indices {
		parent := j / 2
		if parent != last {
			out = append(out, parent)
			last = parent
		}
	}
	return out
}
func (t *compactTree) proof(indices []int) ([][]byte, error) {
	if t == nil || !validIndices(indices, t.count) {
		return nil, errors.New("invalid multiproof indices")
	}
	aux := make([][]byte, 0)
	positions := append([]int(nil), indices...)
	for level := 0; level < len(t.levels)-1; level++ {
		known := make(map[int]bool, len(positions))
		for _, j := range positions {
			known[j] = true
		}
		parents := frontierParents(positions)
		for _, parent := range parents {
			for _, child := range []int{2 * parent, 2*parent + 1} {
				if !known[child] {
					aux = append(aux, benchcore.CloneBytes(t.levels[level][child]))
				}
			}
		}
		positions = parents
	}
	return aux, nil
}
func verifyCompact(leaves [][]byte, root []byte, indices []int, n int, aux [][]byte) bool {
	if !validIndices(indices, n) || len(leaves) != len(indices) || len(root) != 32 {
		return false
	}
	for _, h := range aux {
		if len(h) != 32 {
			return false
		}
	}
	size := 1
	for size < n {
		size *= 2
	}
	known := make(map[int][]byte, len(indices))
	for i, j := range indices {
		if len(leaves[i]) != 32 {
			return false
		}
		known[j] = leaves[i]
	}
	cursor := 0
	for width := size; width > 1; width /= 2 {
		positions := make([]int, 0, len(known))
		for j := range known {
			positions = append(positions, j)
		}
		sort.Ints(positions)
		next := make(map[int][]byte)
		for _, parent := range frontierParents(positions) {
			children := [2][]byte{}
			for side := 0; side < 2; side++ {
				h, ok := known[2*parent+side]
				if !ok {
					if cursor >= len(aux) {
						return false
					}
					h = aux[cursor]
					cursor++
				}
				children[side] = h
			}
			next[parent] = merkleNode(children[0], children[1])
		}
		known = next
	}
	return cursor == len(aux) && bytes.Equal(known[0], root)
}
