package benchcore

import (
	"bytes"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"math/big"
	"testing"
)

func TestG1MultiExpMatchesScalarLoop(t *testing.T) {
	pool := make([]*bn256.G1, 64)
	for i := range pool {
		pool[i] = G1Base(Scalar("msm/point", i))
	}
	pool[0] = G1Zero()
	// Cover both execution paths, every window size, and scalar windows crossing byte boundaries.
	for _, n := range []int{0, 1, 7, 31, 32, 65, 129, 257, 513, 1025, 4097, 8193} {
		t.Run(big.NewInt(int64(n)).String(), func(t *testing.T) {
			points := make([]*bn256.G1, n)
			scalars := make([]*big.Int, n)
			want := G1Zero()
			for i := range points {
				points[i] = pool[i%len(pool)]
				scalars[i] = Scalar("msm/scalar", i)
				switch i % 13 {
				case 0:
					scalars[i] = Zero()
				case 1:
					scalars[i] = One()
				case 2:
					scalars[i] = new(big.Int).Neg(scalars[i])
				case 3:
					scalars[i] = new(big.Int).Add(scalars[i], Order)
				case 4:
					scalars[i] = new(big.Int).Set(Order)
				}
				want = G1Add(want, G1Mul(points[i], scalars[i]))
			}
			beforePoints := make([][]byte, n)
			beforeScalars := make([]*big.Int, n)
			for i := range points {
				beforePoints[i] = append([]byte(nil), points[i].Marshal()...)
				beforeScalars[i] = new(big.Int).Set(scalars[i])
			}
			got := G1MultiExp(points, scalars)
			if !G1Eq(got, want) {
				t.Fatal("MSM differs from independent scalar multiplication")
			}
			for i := range points {
				if !bytes.Equal(beforePoints[i], points[i].Marshal()) || scalars[i].Cmp(beforeScalars[i]) != 0 {
					t.Fatalf("input %d mutated", i)
				}
			}
		})
	}
}
func TestG1MultiExpRejectsDimensions(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	G1MultiExp([]*bn256.G1{G1Base(One())}, nil)
}
