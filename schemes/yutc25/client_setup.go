package yutc25

import (
	"crypto/rand"
	bn "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"multiaudit/schemes/benchcore"
)

// NewOwnerProtocol uses fresh setup randomness for an owner on a live device.
func NewOwnerProtocol(n, s int) (*Protocol, error) {
	psi, err := benchcore.RandomScalar(rand.Reader, true)
	if err != nil {
		return nil, err
	}
	srs := make([]*bn.G1, s+1)
	power := benchcore.One()
	for i := range srs {
		srs[i] = benchcore.G1Base(power)
		power = benchcore.Mul(power, psi)
	}
	return &Protocol{N: n, S: s, psi: psi, SRS: srs, rand: rand.Reader}, nil
}
