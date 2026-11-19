package benchcore

import (
	"math/big"
	"testing"
)

func assertPolynomialEqual(t *testing.T, got, want Poly) {
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

func TestDelayedReductionMatchesFieldSum(t *testing.T) {
	// Near-modulus values force exact accumulators beyond 512 bits; also cover
	// zero weights, varying degrees, and coefficients normalized by the reference.
	for _, count := range []int{1, 4, 690} {
		polys := make([]Poly, count)
		weights := make([]*big.Int, count)
		reference := NewPoly(nil)
		for i := range polys {
			values := make([]*big.Int, 1+i%20)
			for k := range values {
				values[k] = new(big.Int).Sub(Order, big.NewInt(int64(1+i+k)))
			}
			polys[i] = NewPoly(values)
			weights[i] = new(big.Int).Sub(Order, big.NewInt(int64(1+i)))
			if i%7 == 0 {
				weights[i] = new(big.Int)
			}
			reference = reference.Add(polys[i].Scale(weights[i]))
		}
		got := LinearCombination(polys, weights)
		assertPolynomialEqual(t, got, reference)
		// Every output owns its storage rather than aliasing any input.
		if count > 1 {
			before := new(big.Int).Set(polys[1].Coeffs[0])
			got.Coeffs[0].SetInt64(42)
			if polys[1].Coeffs[0].Cmp(before) != 0 {
				t.Fatal("mutated input")
			}
		}
	}
	polys := []Poly{{Coeffs: []*big.Int{nil, big.NewInt(-3), new(big.Int).Add(Order, big.NewInt(7))}}}
	weights := []*big.Int{big.NewInt(-11)}
	assertPolynomialEqual(t, LinearCombination(polys, weights), NewPoly(polys[0].Coeffs).Scale(weights[0]))
	assertPolynomialEqual(t, LinearCombination(nil, nil), NewPoly(nil))
}

func TestEvaluationQuotientIdentity(t *testing.T) {
	for _, degree := range []int{0, 1, 2, 19, 39, 99} {
		values := make([]*big.Int, degree+1)
		for k := range values {
			values[k] = Scalar("quotient-differential", degree*100+k)
		}
		f := NewPoly(values)
		for _, root := range []*big.Int{new(big.Int), big.NewInt(1), new(big.Int).Sub(Order, big.NewInt(1)), Scalar("quotient-root", degree)} {
			q, y := f.DivLinear(root)
			wantY := f.Eval(root)
			wantQ, rem := f.SubConstant(wantY).DivLinear(root)
			if y.Cmp(wantY) != 0 || rem.Sign() != 0 {
				t.Fatal("incorrect evaluation")
			}
			assertPolynomialEqual(t, q, wantQ)
			x := Scalar("quotient-identity", degree)
			recovered := Add(Mul(q.Eval(x), Sub(x, root)), y)
			if recovered.Cmp(f.Eval(x)) != 0 {
				t.Fatal("f(X) = q(X)(X-r) + y failed")
			}
			if f.Coeffs[0].Cmp(values[0]) != 0 {
				t.Fatal("input coefficient mutated")
			}
		}
	}
}

func TestFieldPrimitivesMatchIntegerModulus(t *testing.T) {
	huge := new(big.Int).Lsh(big.NewInt(1), 1025)
	values := []*big.Int{nil, new(big.Int), big.NewInt(1), big.NewInt(-1), new(big.Int).Set(Order), new(big.Int).Sub(Order, big.NewInt(1)), new(big.Int).Add(Order, big.NewInt(5)), huge, new(big.Int).Neg(huge)}
	asInt := func(x *big.Int) *big.Int {
		if x == nil {
			return new(big.Int)
		}
		return new(big.Int).Set(x)
	}
	for _, a := range values {
		for _, b := range values {
			for name, op := range map[string]struct {
				actual  func(*big.Int, *big.Int) *big.Int
				integer func(*big.Int, *big.Int) *big.Int
			}{
				"add": {Add, func(x, y *big.Int) *big.Int { return new(big.Int).Add(x, y) }},
				"sub": {Sub, func(x, y *big.Int) *big.Int { return new(big.Int).Sub(x, y) }},
				"mul": {Mul, func(x, y *big.Int) *big.Int { return new(big.Int).Mul(x, y) }},
			} {
				aa, bb := asInt(a), asInt(b)
				want := op.integer(aa, bb)
				want.Mod(want, Order)
				got := op.actual(a, b)
				if got.Cmp(want) != 0 {
					t.Fatalf("%s differs from integer modular arithmetic", name)
				}
				if asInt(a).Cmp(aa) != 0 || asInt(b).Cmp(bb) != 0 {
					t.Fatalf("%s mutated input", name)
				}
			}
		}
	}
	var sum ScalarAccumulator
	reference := new(big.Int)
	for i := 0; i < 690; i++ {
		a := new(big.Int).Sub(Order, big.NewInt(int64(i+1)))
		sum.AddProduct(a, a)
		reference.Add(reference, new(big.Int).Mul(a, a))
	}
	sum.Add(big.NewInt(-7))
	reference.Sub(reference, big.NewInt(7))
	reference.Mod(reference, Order)
	if sum.Value().Cmp(reference) != 0 {
		t.Fatal("scalar delayed reduction differs")
	}
}
