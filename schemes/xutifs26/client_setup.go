package xutifs26

import (
	"crypto/rand"
	bn "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"multiaudit/schemes/benchcore"
)

// NewOwnerProtocol samples the owner's setup secret for a live client session.
// The native Store, Prove and Verify equations are unchanged.
func NewOwnerProtocol(m, n, s int) (*Protocol, error) {
	alpha, err := benchcore.RandomScalar(rand.Reader, true)
	if err != nil {
		return nil, err
	}
	srs := make([]*bn.G1, s)
	power := benchcore.One()
	for i := range srs {
		srs[i] = benchcore.G1Base(power)
		power = benchcore.Mul(power, alpha)
	}
	return &Protocol{M: m, N: n, S: s, alpha: alpha, SRSG1: srs, G2: benchcore.G2Base(benchcore.One()), AlphaG2: benchcore.G2Base(alpha)}, nil
}
