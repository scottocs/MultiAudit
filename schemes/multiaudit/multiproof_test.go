package multiaudit

import (
	"fmt"
	"multiaudit/schemes/benchcore"
	"testing"
)

func TestCompactProofEverySmallSubset(t *testing.T) {
	for n := 1; n <= 9; n++ {
		leaves := make([][]byte, n)
		for j := range leaves {
			leaves[j] = benchcore.HashBytes("leaf", benchcore.IntBytes(j))
		}
		tree, err := newCompactTree([]byte("id"), leaves)
		if err != nil {
			t.Fatal(err)
		}
		for mask := 1; mask < 1<<n; mask++ {
			var indices []int
			var selected [][]byte
			for j := range leaves {
				if mask&(1<<j) != 0 {
					indices = append(indices, j)
					selected = append(selected, leaves[j])
				}
			}
			aux, err := tree.proof(indices)
			if err != nil {
				t.Fatal(err)
			}
			if !verifyCompact(selected, tree.Root, indices, n, aux) {
				t.Fatal(n, mask, "honest proof rejected")
			}
			// Independently count missing frontier siblings at every fixed tree level.
			S := append([]int(nil), indices...)
			want := 0
			for l := 0; l < len(tree.levels)-1; l++ {
				parents := frontierParents(S)
				want += 2*len(parents) - len(S)
				S = parents
			}
			if len(aux) != want {
				t.Fatal("wrong auxiliary count")
			}
			extra := append(append([][]byte(nil), aux...), benchcore.HashBytes("extra"))
			if verifyCompact(selected, tree.Root, indices, n, extra) {
				t.Fatal("extra hash accepted")
			}
			if len(aux) > 0 && verifyCompact(selected, tree.Root, indices, n, aux[:len(aux)-1]) {
				t.Fatal("missing hash accepted")
			}
		}
	}
}
func TestCompactProofRejectsMalformedIndices(t *testing.T) {
	leaves := [][]byte{benchcore.HashBytes("a"), benchcore.HashBytes("b"), benchcore.HashBytes("c")}
	tree, _ := newCompactTree([]byte("id"), leaves)
	for _, indices := range [][]int{nil, {-1}, {3}, {1, 1}, {2, 1}} {
		t.Run(fmt.Sprint(indices), func(t *testing.T) {
			if _, e := tree.proof(indices); e == nil {
				t.Fatal("invalid indices accepted")
			}
		})
	}
	other, _ := newCompactTree([]byte("other"), leaves)
	if string(tree.Root) == string(other.Root) {
		t.Fatal("padding did not bind namespace")
	}
}
