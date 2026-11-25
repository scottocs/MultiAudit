package multiaudit

import (
	"bytes"
	"encoding/binary"
	"errors"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"io"
	"math/big"
	"multiaudit/schemes/benchcore"
)

// MarshalProof uses the backend's actual 64-byte G1 encoding, not the paper's
// illustrative 48-byte estimate. Indices and trusted metadata belong to the
// challenge/registry and are not repeated in the response.
func (p *Protocol) MarshalProof(proof *AuditProof) ([]byte, error) {
	if err := p.Config.Validate(); err != nil {
		return nil, err
	}
	if proof == nil || len(proof.FileProofs) != p.Config.NumFiles {
		return nil, errors.New("invalid proof dimensions")
	}
	var b bytes.Buffer
	b.WriteString("MA02")
	binary.Write(&b, binary.BigEndian, uint32(p.Config.NumFiles))
	binary.Write(&b, binary.BigEndian, uint32(p.Config.ChallengedChunks))
	putPoint := func(x *bn256.G1) error {
		if !validG1(x) {
			return errors.New("invalid group element")
		}
		b.Write(x.Marshal())
		return nil
	}
	if err := putPoint(proof.CQ); err != nil {
		return nil, err
	}
	if err := putPoint(proof.CW); err != nil {
		return nil, err
	}
	for _, fp := range proof.FileProofs {
		if len(fp.Tags) != p.Config.ChallengedChunks || !canonicalScalar(fp.Value) {
			return nil, errors.New("invalid proof fields")
		}
		for _, tag := range fp.Tags {
			if err := putPoint(tag); err != nil {
				return nil, err
			}
		}
		if len(fp.Auxiliary) > maxAuxiliary(p.Config) {
			return nil, errors.New("too many auxiliary hashes")
		}
		binary.Write(&b, binary.BigEndian, uint32(len(fp.Auxiliary)))
		for _, h := range fp.Auxiliary {
			if len(h) != 32 {
				return nil, errors.New("invalid digest")
			}
			b.Write(h)
		}
		b.Write(benchcore.ScalarBytes(fp.Value))

	}
	return b.Bytes(), nil
}
func maxAuxiliary(c Config) int {
	L := 0
	for n := c.ChunksPerFile - 1; n > 0; n >>= 1 {
		L++
	}
	return c.ChallengedChunks * L
}

// UnmarshalProof bounds all allocations by the trusted configuration and input
// length, rejects noncanonical scalars/points and refuses trailing bytes.
func (p *Protocol) UnmarshalProof(data []byte) (*AuditProof, error) {
	if err := p.Config.Validate(); err != nil {
		return nil, err
	}
	fail := errors.New("invalid proof encoding")
	r := bytes.NewReader(data)
	magic := make([]byte, 4)
	if _, err := io.ReadFull(r, magic); err != nil || string(magic) != "MA02" {
		return nil, fail
	}
	var m, c uint32
	if binary.Read(r, binary.BigEndian, &m) != nil || binary.Read(r, binary.BigEndian, &c) != nil || uint64(m) != uint64(p.Config.NumFiles) || uint64(c) != uint64(p.Config.ChallengedChunks) {
		return nil, fail
	}
	// Check the product using division before allocating or multiplying counts.
	perFile := uint64(c)*64 + 32 + 4
	if r.Len() < 128 || uint64(m) > uint64(r.Len()-128)/perFile {
		return nil, fail
	}
	point := func() (*bn256.G1, error) {
		raw := make([]byte, 64)
		if _, e := io.ReadFull(r, raw); e != nil {
			return nil, fail
		}
		g := new(bn256.G1)
		rest, e := g.Unmarshal(raw)
		if e != nil || len(rest) != 0 || !bytes.Equal(g.Marshal(), raw) {
			return nil, fail
		}
		return g, nil
	}
	scalar := func() (*big.Int, error) {
		raw := make([]byte, 32)
		if _, e := io.ReadFull(r, raw); e != nil {
			return nil, fail
		}
		x := new(big.Int).SetBytes(raw)
		if !canonicalScalar(x) {
			return nil, fail
		}
		return x, nil
	}
	out := &AuditProof{FileProofs: make([]FileProof, int(m))}
	var err error
	if out.CQ, err = point(); err != nil {
		return nil, err
	}
	if out.CW, err = point(); err != nil {
		return nil, err
	}
	for i := range out.FileProofs {
		fp := &out.FileProofs[i]
		fp.Tags = make([]*bn256.G1, int(c))
		for j := range fp.Tags {
			if fp.Tags[j], err = point(); err != nil {
				return nil, err
			}
		}
		var n uint32
		if binary.Read(r, binary.BigEndian, &n) != nil || uint64(n) > uint64(maxAuxiliary(p.Config)) || uint64(n)*32 > uint64(r.Len()) {
			return nil, fail
		}
		fp.Auxiliary = make([][]byte, int(n))
		for j := range fp.Auxiliary {
			fp.Auxiliary[j] = make([]byte, 32)
			if _, err = io.ReadFull(r, fp.Auxiliary[j]); err != nil {
				return nil, fail
			}
		}
		if fp.Value, err = scalar(); err != nil {
			return nil, err
		}

	}
	if r.Len() != 0 {
		return nil, fail
	}
	return out, nil
}
