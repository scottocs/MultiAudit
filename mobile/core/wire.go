package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"sort"

	"multiaudit/schemes/benchcore"
	"multiaudit/schemes/multiaudit"
	"multiaudit/schemes/xutifs26"
	"multiaudit/schemes/yutc25"
)

func putScalar(b *bytes.Buffer, x *big.Int) { b.Write(benchcore.ScalarBytes(x)) }
func scalar(r *bytes.Reader) (*big.Int, error) {
	b := make([]byte, 32)
	if _, e := io.ReadFull(r, b); e != nil {
		return nil, e
	}
	x := new(big.Int).SetBytes(b)
	if x.Cmp(benchcore.Order) >= 0 {
		return nil, errors.New("noncanonical scalar")
	}
	return x, nil
}
func readN(r *bytes.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func (v *Client) encodeChallenge() ([]byte, error) {
	var b bytes.Buffer
	c := v.Manifest.Config
	switch c.Scheme {
	case "Xu":
		b.Write(v.xc.Seed)
	case "Yu":
		for _, ch := range v.yc.FileChallenges {
			b.Write(ch.K1)
			b.Write(ch.K2)
		}
	case "MultiAudit":
		b.Write(v.fc.Nonce)
		for _, j := range v.fc.Indices {
			binary.Write(&b, binary.BigEndian, uint32(j))
		}
		for i := 0; i < c.M; i++ {
			putScalar(&b, v.fc.EvaluationPoints[i])
			for _, x := range v.fc.Coefficients[i] {
				putScalar(&b, x)
			}
		}
	}
	return b.Bytes(), nil
}

func (v *Client) decodeChallenge(wire []byte) error {
	c := v.Manifest.Config
	r := bytes.NewReader(wire)
	expected := 32
	if c.Scheme == "Yu" {
		expected = c.M * 64
	}
	if c.Scheme == "MultiAudit" {
		expected = 32 + 4*c.C + 32*c.M*(c.C+1)
	}
	if len(wire) != expected {
		return errors.New("invalid challenge length")
	}
	switch c.Scheme {
	case "Xu":
		v.xc = v.x.ChallengeFromSeed(wire, c.C)
	case "Yu":
		v.yc.FileChallenges = make([]yutc25.Challenge, c.M)
		for i := range v.yc.FileChallenges {
			v.yc.FileChallenges[i] = v.y.ChallengeFromKeys(wire[i*64:i*64+32], wire[i*64+32:(i+1)*64], c.C)
		}
	case "MultiAudit":
		nonce, _ := readN(r, 32)
		ch := &multiaudit.Challenge{Nonce: nonce, Indices: make([]int, c.C), EvaluationPoints: make([]*big.Int, c.M), Coefficients: make([][]*big.Int, c.M)}
		for i := range ch.Indices {
			var j uint32
			binary.Read(r, binary.BigEndian, &j)
			ch.Indices[i] = int(j)
			if int(j) >= c.N || (i > 0 && ch.Indices[i-1] >= int(j)) {
				return errors.New("invalid challenge indices")
			}
		}
		if !sort.IntsAreSorted(ch.Indices) {
			return errors.New("unordered indices")
		}
		seen := map[string]bool{}
		for i := 0; i < c.M; i++ {
			x, err := scalar(r)
			if err != nil {
				return err
			}
			if seen[x.String()] {
				return errors.New("repeated evaluation point")
			}
			seen[x.String()] = true
			ch.EvaluationPoints[i] = x
			ch.Coefficients[i] = make([]*big.Int, c.C)
			for j := 0; j < c.C; j++ {
				x, err = scalar(r)
				if err != nil {
					return err
				}
				ch.Coefficients[i][j] = x
			}
		}
		v.fc = ch
	}
	v.pending = true
	return nil
}

func (v *Client) decodeProof(wire []byte) (func() bool, error) {
	c := v.Manifest.Config
	if c.Scheme == "MultiAudit" {
		p, e := v.f.UnmarshalProof(wire)
		if e != nil {
			return nil, e
		}
		return func() bool { return v.f.Verify(v.fs, v.fc, p) }, nil
	}
	L := height(c.N)
	size := c.M * (96 + c.C*(64+32*L))
	if c.Scheme == "Yu" {
		size += 32 * c.M * (c.S - 1)
	}
	if len(wire) != size {
		return nil, errors.New("invalid proof length")
	}
	r := bytes.NewReader(wire)
	if c.Scheme == "Xu" {
		p := &xutifs26.Proof{Files: make([]xutifs26.FileProof, c.M)}
		for i := range p.Files {
			y, e := scalar(r)
			if e != nil {
				return nil, e
			}
			b, _ := readN(r, 64)
			w, e := point(b)
			if e != nil {
				return nil, e
			}
			fp := xutifs26.FileProof{Value: y, W: w, Tags: make([]xutifs26.TagOpening, c.C)}
			for j, index := range v.xc.Indices {
				b, _ = readN(r, 64)
				t, e := point(b)
				if e != nil {
					return nil, e
				}
				path := benchcore.MerkleProof{Index: index, Siblings: make([][]byte, L)}
				for k := range path.Siblings {
					path.Siblings[k], _ = readN(r, 32)
				}
				fp.Tags[j] = xutifs26.TagOpening{Index: index, Tag: t, Path: path}
			}
			p.Files[i] = fp
		}
		return func() bool { return v.x.Verify(v.xs, v.xc, p) }, nil
	}
	p := &yutc25.BatchProof{Proofs: make([]*yutc25.Proof, c.M)}
	for i := range p.Proofs {
		y, e := scalar(r)
		if e != nil {
			return nil, e
		}
		b, _ := readN(r, 64)
		B, e := point(b)
		if e != nil {
			return nil, e
		}
		q := make([]*big.Int, c.S-1)
		for k := range q {
			q[k], e = scalar(r)
			if e != nil {
				return nil, e
			}
		}
		fp := &yutc25.Proof{Value: y, B: B, Quotient: benchcore.NewPoly(q), Openings: make([]yutc25.TagOpening, c.C)}
		for j, index := range v.yc.FileChallenges[i].Indices {
			b, _ = readN(r, 64)
			t, e := point(b)
			if e != nil {
				return nil, e
			}
			path := benchcore.MerkleProof{Index: index, Siblings: make([][]byte, L)}
			for k := range path.Siblings {
				path.Siblings[k], _ = readN(r, 32)
			}
			fp.Openings[j] = yutc25.TagOpening{Index: index, Tag: t, Path: path}
		}
		p.Proofs[i] = fp
	}
	return func() bool { return v.y.VerifyBatch(v.ys, v.yc, p) }, nil
}
