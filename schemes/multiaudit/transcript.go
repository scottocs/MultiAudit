package multiaudit

import (
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"math/big"
	"multiaudit/schemes/benchcore"
)

// Zero-based Go indices encode one-based paper positions. Every component is
// length framed; dimensions, the SRS, registry order, and versions are bound.
func (p *Protocol) baseTranscript(stored *StoredBatch, chal *Challenge, fps []FileProof) []byte {
	parts := [][]byte{[]byte(ProtocolID), p.srsIdentifier()}
	for _, n := range []int{p.Config.NumFiles, p.Config.ChunksPerFile, p.Config.SectorsPerChunk, p.Config.ChallengedChunks} {
		parts = append(parts, benchcore.IntBytes(n))
	}
	for i, f := range stored.Files {
		version := new(big.Int).SetUint64(f.Version).FillBytes(make([]byte, 8))
		parts = append(parts, f.FileID, version, stored.Roots[i])
	}
	parts = append(parts, chal.Nonce)
	for _, j := range chal.Indices {
		parts = append(parts, benchcore.IntBytes(j+1))
	}
	for i, fp := range fps {
		for _, v := range chal.Coefficients[i] {
			parts = append(parts, benchcore.ScalarBytes(v))
		}
		parts = append(parts, benchcore.ScalarBytes(chal.EvaluationPoints[i]))
		for _, tag := range fp.Tags {
			parts = append(parts, g1Bytes(tag))
		}
		parts = append(parts, benchcore.ScalarBytes(fp.YTilde), g1Bytes(fp.R))
	}
	return benchcore.HashBytes("MultiAudit", parts...)
}

func (p *Protocol) srsIdentifier() []byte {
	parts := [][]byte{p.PP.G2.Marshal(), p.PP.TauG2.Marshal()}
	for _, g := range p.PP.SRSG1 {
		parts = append(parts, g.Marshal())
	}
	return benchcore.HashBytes("multiaudit:srs", parts...)
}

// Rejection of integers >= p (rather than modular reduction) is unbiased.
// Each counter is framed into the domain-separated random-oracle input.
func hashToField(domain string, accept func(*big.Int) bool, parts ...[]byte) *big.Int {
	for counter := 0; ; counter++ {
		input := append(append([][]byte(nil), parts...), benchcore.IntBytes(counter))
		digest := benchcore.HashBytes(domain, input...)
		excess := len(digest)*8 - benchcore.Order.BitLen()
		if excess > 0 {
			digest[0] &= byte(255 >> excess)
		}
		x := new(big.Int).SetBytes(digest)
		if x.Cmp(benchcore.Order) < 0 && (accept == nil || accept(x)) {
			return x
		}
	}
}
func openingWeights(T []byte, CQ *bn256.G1, rs []*big.Int) (*big.Int, []*big.Int) {
	gamma := hashToField("multiaudit:gamma", func(x *big.Int) bool { return x.Sign() != 0 }, T)
	z := hashToField("multiaudit:z", func(x *big.Int) bool {
		for _, r := range rs {
			if x.Cmp(r) == 0 {
				return false
			}
		}
		return true
	}, T, g1Bytes(CQ))
	betas := make([]*big.Int, len(rs))
	power := benchcore.One()
	for i, r := range rs {
		inverse, err := benchcore.Inv(benchcore.Sub(z, r))
		if err != nil {
			panic("excluded evaluation point")
		}
		betas[i] = benchcore.Mul(power, inverse)
		power = benchcore.Mul(power, gamma)
	}
	return z, betas
}
func maskChallenge(T []byte, proof *AuditProof, i int, R, A *bn256.G1) *big.Int {
	return hashToField("multiaudit:mask", nil, T, g1Bytes(proof.CQ), g1Bytes(proof.CW), benchcore.IntBytes(i+1), g1Bytes(R), g1Bytes(A))
}
