package benchcore

import (
	"math/big"
	"math/bits"
)

// StorageID identifies the owned scalar representation.
const StorageID = "owned-scalar-arena/v1"

// An arena owns scalar headers and disjoint, capacity-bounded limb slices.
type scalarArena struct {
	values   []big.Int
	words    []big.Word
	pointers []*big.Int
	stride   int
}

func newScalarArena(count int) *scalarArena {
	stride := (Order.BitLen() + bits.UintSize - 1) / bits.UintSize
	return &scalarArena{values: make([]big.Int, count), words: make([]big.Word, count*stride), pointers: make([]*big.Int, count), stride: stride}
}

func (a *scalarArena) set(i int, x *big.Int) {
	var reduced big.Int
	if x == nil {
		x = &reduced
	} else if x.Sign() < 0 || x.Cmp(Order) >= 0 {
		x = reduced.Mod(x, Order)
	}
	start, end := i*a.stride, (i+1)*a.stride
	// Capacity must stop at this element: future growth of an Int allocates a
	// new limb buffer rather than overwriting its neighbour's storage.
	words := a.words[start:end:end]
	copy(words, x.Bits())
	a.pointers[i] = a.values[i].SetBits(words)
}

// NewStoredScalars returns independently mutable zeros in owned storage.
func NewStoredScalars(count int) []*big.Int {
	a := newScalarArena(count)
	for i := range a.values {
		a.set(i, nil)
	}
	return a.pointers
}

func CloneStoredScalars(values []*big.Int) []*big.Int {
	a := newScalarArena(len(values))
	for i, x := range values {
		a.set(i, x)
	}
	return a.pointers
}

// CloneStoredMatrix isolates a file and bounds every row's capacity.
func CloneStoredMatrix(rows [][]*big.Int) [][]*big.Int {
	count := 0
	for _, row := range rows {
		count += len(row)
	}
	a := newScalarArena(count)
	out := make([][]*big.Int, len(rows))
	offset := 0
	for j, row := range rows {
		for k, x := range row {
			a.set(offset+k, x)
		}
		end := offset + len(row)
		out[j] = a.pointers[offset:end:end]
		offset = end
	}
	return out
}

// StoredPolynomialView shares a canonical owned row; both views are read-only.
func StoredPolynomialView(coeffs []*big.Int) Poly {
	if len(coeffs) == 0 {
		return NewPoly(nil)
	}
	p := Poly{Coeffs: coeffs}
	p.Trim()
	p.Coeffs = p.Coeffs[:len(p.Coeffs):len(p.Coeffs)]
	return p
}
