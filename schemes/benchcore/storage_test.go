package benchcore

import (
	"math/big"
	"runtime"
	"testing"
)

func TestStoredScalarsOwnAndBoundTheirMemory(t *testing.T) {
	same := big.NewInt(7)
	input := []*big.Int{nil, Zero(), same, same, new(big.Int).Sub(Order, One()), new(big.Int).Neg(One()), new(big.Int).Add(Order, big.NewInt(11)), new(big.Int).Lsh(One(), 1024)}
	expected := make([]*big.Int, len(input))
	for i, x := range input {
		expected[i] = Normalize(x)
	}
	stored := CloneStoredScalars(input)
	for i, x := range stored {
		if x.Cmp(expected[i]) != 0 {
			t.Fatalf("element %d differs", i)
		}
	}
	same.SetInt64(99)
	if stored[2].Cmp(big.NewInt(7)) != 0 || stored[3].Cmp(big.NewInt(7)) != 0 {
		t.Fatal("input mutation changed stored data")
	}
	// Growing one coefficient must not overwrite a neighbouring coefficient's
	// limbs, even though both started in one contiguous word arena.
	stored[2].Lsh(stored[2], 4096)
	if stored[3].Cmp(big.NewInt(7)) != 0 || input[2].Cmp(big.NewInt(99)) != 0 {
		t.Fatal("coefficient storage aliases another value")
	}
	survivor := stored[4]
	stored = nil
	runtime.GC()
	if survivor.Cmp(expected[4]) != 0 {
		t.Fatal("arena did not survive through coefficient pointer")
	}
}

func TestStoredMatrixRowsAndPolynomialViews(t *testing.T) {
	input := [][]*big.Int{{big.NewInt(3), Zero(), Zero()}, {big.NewInt(9)}, nil}
	stored := CloneStoredMatrix(input)
	if cap(stored[0]) != len(stored[0]) {
		t.Fatal("row capacity extends into next row")
	}
	first := append(stored[0], big.NewInt(42))
	if first[3].Cmp(big.NewInt(42)) != 0 || stored[1][0].Cmp(big.NewInt(9)) != 0 {
		t.Fatal("append overwrote next row")
	}
	p := StoredPolynomialView(stored[0])
	if len(p.Coeffs) != 1 || len(stored[0]) != 3 || p.Coeffs[0] != stored[0][0] {
		t.Fatal("constant polynomial lost its full sector row or shared view")
	}
	if cap(p.Coeffs) != len(p.Coeffs) {
		t.Fatal("polynomial append could overwrite trailing sectors")
	}
	if p.Eval(big.NewInt(11)).Cmp(big.NewInt(3)) != 0 {
		t.Fatal("incorrect polynomial view")
	}
	input[0][0].SetInt64(777)
	if p.Coeffs[0].Cmp(big.NewInt(3)) != 0 {
		t.Fatal("polynomial shares caller input")
	}
	assertPolynomialEqual(t, StoredPolynomialView(nil), NewPoly(nil))
}
