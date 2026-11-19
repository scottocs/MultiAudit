package benchcore

import (
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

// G1MultiExp returns sum_i scalars[i]*points[i] in additive notation.
// It uses a common unsigned-window Pippenger implementation for every protocol.
// The buckets are variable-time: this helper is intended for the benchmark's
// public audit coefficients and local protocol execution, not a constant-time
// cryptographic API. No tables or results are cached between calls.
func G1MultiExp(points []*bn256.G1, scalars []*big.Int) *bn256.G1 {
	if len(points) != len(scalars) {
		panic("MSM point/scalar dimension mismatch")
	}
	for _, point := range points {
		if point == nil {
			panic("nil MSM point")
		}
	}
	if len(points) < 32 {
		out := G1Zero()
		for i, point := range points {
			scalar := Normalize(scalars[i])
			if scalar.Sign() == 0 {
				continue
			}
			if scalar.Cmp(big.NewInt(1)) == 0 {
				out.Add(out, point)
			} else {
				out.Add(out, new(bn256.G1).ScalarMult(point, scalar))
			}
		}
		return out
	}
	width := msmWindow(len(points))
	encoded := make([][]byte, len(scalars))
	for i, scalar := range scalars {
		encoded[i] = ScalarBytes(scalar)
	}
	buckets := make([]bn256.G1, 1<<width)
	used := make([]bool, len(buckets))
	out, running, zero := G1Zero(), G1Zero(), G1Zero()
	mask := uint32((1 << width) - 1)
	windows := (256 + int(width) - 1) / int(width)
	for window := windows - 1; window >= 0; window-- {
		if window != windows-1 {
			for k := uint(0); k < width; k++ {
				out.Add(out, out)
			}
		}
		clear(used)
		shift := window * int(width)
		index, offset := 31-shift/8, uint(shift%8)
		for i, point := range points {
			word := uint32(encoded[i][index])
			if index > 0 {
				word |= uint32(encoded[i][index-1]) << 8
			}
			if index > 1 {
				word |= uint32(encoded[i][index-2]) << 16
			}
			digit := int((word >> offset) & mask)
			if digit == 0 {
				continue
			}
			if used[digit] {
				buckets[digit].Add(&buckets[digit], point)
			} else {
				buckets[digit].Set(point)
				used[digit] = true
			}
		}
		running.Set(zero)
		for digit := len(buckets) - 1; digit > 0; digit-- {
			if used[digit] {
				running.Add(running, &buckets[digit])
			}
			out.Add(out, running)
		}
	}
	return out
}

func msmWindow(n int) uint {
	switch {
	case n <= 64:
		return 3
	case n <= 128:
		return 4
	case n <= 256:
		return 5
	case n <= 512:
		return 6
	case n <= 1024:
		return 7
	case n <= 4096:
		return 8
	case n <= 8192:
		return 9
	default:
		return 10
	}
}
