package benchcore

import "math/big"

// ArithmeticID identifies the shared finite-field backend.
const ArithmeticID = "shared-delayed-reduction/v1"

// ScalarAccumulator delays reduction of a sum of field values/products. Exact
// big.Int accumulation prevents machine-word overflow; for c canonical products
// its size is at most 2*Order.BitLen()+ceil(log2(c)) bits. Inputs are never mutated.
type ScalarAccumulator struct{ sum, product big.Int }

func (a *ScalarAccumulator) Add(x *big.Int) {
	if x != nil {
		a.sum.Add(&a.sum, x)
	}
}
func (a *ScalarAccumulator) AddProduct(x, y *big.Int) {
	if x == nil || y == nil {
		return
	}
	a.product.Mul(x, y)
	a.sum.Add(&a.sum, &a.product)
}
func (a *ScalarAccumulator) Value() *big.Int { return new(big.Int).Mod(&a.sum, Order) }

// PolynomialAccumulator applies the same delayed-reduction policy to each
// coefficient, sharing a multiplication scratch buffer across all coefficients.
type PolynomialAccumulator struct {
	sums    []*big.Int
	product big.Int
}

func NewPolynomialAccumulator(size int) *PolynomialAccumulator {
	a := &PolynomialAccumulator{}
	a.grow(max(1, size))
	return a
}
func (a *PolynomialAccumulator) grow(size int) {
	for len(a.sums) < size {
		a.sums = append(a.sums, new(big.Int))
	}
}
func (a *PolynomialAccumulator) AddScaled(p Poly, weight *big.Int) {
	if weight == nil || weight.Sign() == 0 {
		return
	}
	a.grow(len(p.Coeffs))
	for k, coefficient := range p.Coeffs {
		if coefficient == nil || coefficient.Sign() == 0 {
			continue
		}
		a.product.Mul(coefficient, weight)
		a.sums[k].Add(a.sums[k], &a.product)
	}
}
func (a *PolynomialAccumulator) Polynomial() Poly { return NewPoly(a.sums) }

func LinearCombination(polys []Poly, weights []*big.Int) Poly {
	if len(polys) != len(weights) {
		panic("polynomial/weight dimension mismatch")
	}
	a := NewPolynomialAccumulator(1)
	for i, p := range polys {
		a.AddScaled(p, weights[i])
	}
	return a.Polynomial()
}
