package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"math/big"

	"multiaudit/schemes/benchcore"
	"multiaudit/schemes/multiaudit"
	"multiaudit/schemes/xutifs26"
	"multiaudit/schemes/yutc25"
)

// Fixture performs trusted owner preprocessing on synthetic files. The phone
// receives only signed public metadata; no data sectors or setup secret.
type Fixture struct {
	Manifest Manifest
	f        *multiaudit.Protocol
	fs       *multiaudit.StoredBatch
	x        *xutifs26.Protocol
	xs       *xutifs26.StoredBatch
	y        *yutc25.Protocol
	ys       *yutc25.StoredBatch
}

func NewFixture(c Config) (*Fixture, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	f := &Fixture{Manifest: Manifest{Config: c, Roots: make([][]byte, c.M), IDs: make([][]byte, c.M), Versions: make([]uint64, c.M)}}
	data := make([][][]*big.Int, c.M)
	for i := range data {
		data[i] = make([][]*big.Int, c.N)
		flat := benchcore.NewStoredScalars(c.N * c.S)
		for j := 0; j < c.N; j++ {
			data[i][j] = flat[j*c.S : (j+1)*c.S : (j+1)*c.S]
			for k := 0; k < c.S; k++ {
				flat[j*c.S+k].Set(benchcore.Scalar("mobile/equal-byte-file", i*c.N*c.S+j*c.S+k))
			}
		}
		f.Manifest.IDs[i] = []byte(fmt.Sprintf("file-%d", i))
		f.Manifest.Versions[i] = 1
	}
	switch c.Scheme {
	case "MultiAudit":
		p, e := multiaudit.Setup(multiaudit.Config{NumFiles: c.M, ChunksPerFile: c.N, SectorsPerChunk: c.S, ChallengedChunks: c.C}, rand.Reader)
		if e != nil {
			return nil, e
		}
		st, e := p.Store(data)
		if e != nil {
			return nil, e
		}
		f.f = p
		f.fs = st
		f.Manifest.Roots = st.Roots
		f.Manifest.SRSID = st.SRSID
		f.Manifest.G2 = p.PP.G2.Marshal()
		f.Manifest.TauG2 = p.PP.TauG2.Marshal()
		for _, x := range p.PP.SRSG1 {
			f.Manifest.SRS = append(f.Manifest.SRS, x.Marshal())
		}
		for i, x := range st.Files {
			f.Manifest.IDs[i] = x.FileID
			f.Manifest.Versions[i] = x.Version
		}
	case "Xu":
		p := xutifs26.NewProtocol(c.M, c.N, c.S)
		st, e := p.Store(data)
		if e != nil {
			return nil, e
		}
		f.x = p
		f.xs = st
		f.Manifest.Roots = st.Roots
		f.Manifest.G2 = p.G2.Marshal()
		f.Manifest.TauG2 = p.AlphaG2.Marshal()
		for _, x := range p.SRSG1 {
			f.Manifest.SRS = append(f.Manifest.SRS, x.Marshal())
		}
	case "Yu":
		p := yutc25.NewProtocol(c.N, c.S)
		st, e := p.StoreBatch(data)
		if e != nil {
			return nil, e
		}
		f.y = p
		f.ys = st
		f.Manifest.Roots = st.Roots
		for _, x := range p.SRS {
			f.Manifest.SRS = append(f.Manifest.SRS, x.Marshal())
		}
	}
	return f, nil
}

func (f *Fixture) Signed(key ed25519.PrivateKey) ([]byte, error) {
	return SignManifest(f.Manifest, key)
}

func (f *Fixture) Prove(challenge []byte) ([]byte, error) {
	// Construct a public-only verifier context, then decode the client's exact
	// issued challenge. Neither peer changes transcript domains or equations.
	v := &Client{Manifest: f.Manifest, f: f.f, fs: f.fs, x: f.x, xs: f.xs, y: f.y, ys: f.ys}
	if e := v.decodeChallenge(challenge); e != nil {
		return nil, e
	}
	var b bytes.Buffer
	c := f.Manifest.Config
	switch c.Scheme {
	case "MultiAudit":
		p, e := f.f.ProofGen(f.fs, v.fc)
		if e != nil {
			return nil, e
		}
		return f.f.MarshalProof(p)
	case "Xu":
		p, e := f.x.Prove(f.xs, v.xc)
		if e != nil {
			return nil, e
		}
		for _, fp := range p.Files {
			putScalar(&b, fp.Value)
			b.Write(fp.W.Marshal())
			for _, o := range fp.Tags {
				b.Write(o.Tag.Marshal())
				for _, h := range o.Path.Siblings {
					b.Write(h)
				}
			}
		}
	case "Yu":
		p, e := f.y.ProveBatch(f.ys, v.yc)
		if e != nil {
			return nil, e
		}
		for _, fp := range p.Proofs {
			putScalar(&b, fp.Value)
			b.Write(fp.B.Marshal())
			for k := 0; k < c.S-1; k++ {
				x := new(big.Int)
				if k < len(fp.Quotient.Coeffs) {
					x = fp.Quotient.Coeffs[k]
				}
				putScalar(&b, x)
			}
			for _, o := range fp.Openings {
				b.Write(o.Tag.Marshal())
				for _, h := range o.Path.Siblings {
					b.Write(h)
				}
			}
		}
	}
	return b.Bytes(), nil
}
