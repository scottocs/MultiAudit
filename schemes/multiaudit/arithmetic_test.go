package multiaudit

import (
	"math/big"
	"testing"

	"multiaudit/schemes/benchcore"
)

func assertPolynomialEqual(t *testing.T, got, want benchcore.Poly) {
	t.Helper()
	if len(got.Coeffs) != len(want.Coeffs) {
		t.Fatalf("coefficient counts %d != %d", len(got.Coeffs), len(want.Coeffs))
	}
	for k := range got.Coeffs {
		if got.Coeffs[k].Cmp(want.Coeffs[k]) != 0 {
			t.Fatalf("coefficient %d differs", k)
		}
	}
}

func TestOptimizedAggregationMatchesReference(t *testing.T) {
	p := &Protocol{Config: Config{SectorsPerChunk: 20}}
	file := StoredFile{Polynomials: make([]benchcore.Poly, 690)}
	chal := &Challenge{Coefficients: [][]*big.Int{make([]*big.Int, 690)}}
	reference := benchcore.NewPoly(nil)
	for j := range file.Polynomials {
		values := make([]*big.Int, 20)
		for k := range values {
			values[k] = benchcore.Scalar("aggregate-differential", j*20+k)
		}
		file.Polynomials[j] = benchcore.NewPoly(values)
		chal.Indices = append(chal.Indices, j)
		chal.Coefficients[0][j] = benchcore.Scalar("aggregate-weight", j)
		reference = reference.Add(file.Polynomials[j].Scale(chal.Coefficients[0][j]))
	}
	got, err := p.aggregatePolynomial(file, chal, 0)
	if err != nil {
		t.Fatal(err)
	}
	assertPolynomialEqual(t, got, reference)
	chal.Indices[0] = -1
	if _, err = p.aggregatePolynomial(file, chal, 0); err == nil {
		t.Fatal("accepted negative index")
	}
	chal.Indices[0] = 0
	file.Polynomials[0] = benchcore.NewPoly([]*big.Int{nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, big.NewInt(1)})
	if _, err = p.aggregatePolynomial(file, chal, 0); err == nil {
		t.Fatal("accepted oversized polynomial")
	}
}
