// Package core adapts the unchanged paper implementations to an iOS client.
package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	bn "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"multiaudit/schemes/benchcore"
	"multiaudit/schemes/multiaudit"
	"multiaudit/schemes/xutifs26"
	"multiaudit/schemes/yutc25"
)

const MaxWire = 64 << 20

type Config struct {
	Scheme string `json:"scheme"`
	M      int    `json:"m"`
	N      int    `json:"n"`
	S      int    `json:"s"`
	C      int    `json:"c"`
}

func (c Config) Validate() error {
	if c.M < 1 || c.M > 40 || c.N < 1 || c.N > 100000 || c.S < 2 || c.S > 1000 || c.C < 1 || c.C > c.N || c.C > 10000 {
		return errors.New("configuration outside client limits")
	}
	if c.Scheme != "MultiAudit" && c.Scheme != "Xu" && c.Scheme != "Yu" {
		return errors.New("unknown scheme")
	}
	if c.M*c.C*(64+32*height(c.N)) > MaxWire {
		return errors.New("proof exceeds client limits")
	}
	return nil
}

// Tree height is independent of machine word width in the wire format.
func height(n int) int {
	l := 0
	for n--; n > 0; n >>= 1 {
		l++
	}
	return l
}

type Manifest struct {
	Config   Config   `json:"config"`
	Roots    [][]byte `json:"roots"`
	IDs      [][]byte `json:"ids"`
	Versions []uint64 `json:"versions"`
	SRS      [][]byte `json:"srs"`
	G2       []byte   `json:"g2,omitempty"`
	TauG2    []byte   `json:"tau_g2,omitempty"`
	SRSID    []byte   `json:"srs_id,omitempty"`
}

type Envelope struct {
	Body      json.RawMessage `json:"body"`
	Signature []byte          `json:"signature"`
}

func SignManifest(m Manifest, key ed25519.PrivateKey) ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Envelope{Body: b, Signature: ed25519.Sign(key, b)})
}

type Client struct {
	Manifest Manifest
	Digest   string
	f        *multiaudit.Protocol
	fs       *multiaudit.StoredBatch
	x        *xutifs26.Protocol
	xs       *xutifs26.StoredBatch
	y        *yutc25.Protocol
	ys       *yutc25.StoredBatch
	fc       *multiaudit.Challenge
	xc       xutifs26.Challenge
	yc       yutc25.BatchChallenge
	pending  bool
}

func NewClient(signed []byte, pinnedKey string) (*Client, error) {
	key, err := hex.DecodeString(pinnedKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("invalid pinned owner key")
	}
	var env Envelope
	if len(signed) > 1<<20 || json.Unmarshal(signed, &env) != nil || !ed25519.Verify(key, env.Body, env.Signature) {
		return nil, errors.New("owner signature rejected")
	}
	var m Manifest
	if err = json.Unmarshal(env.Body, &m); err != nil {
		return nil, err
	}
	if err = m.Config.Validate(); err != nil {
		return nil, err
	}
	c := m.Config
	if len(m.Roots) != c.M || len(m.IDs) != c.M || len(m.Versions) != c.M {
		return nil, errors.New("invalid registry dimensions")
	}
	for i := range m.Roots {
		if len(m.Roots[i]) != 32 || len(m.IDs[i]) == 0 || m.Versions[i] == 0 {
			return nil, errors.New("invalid registry entry")
		}
	}
	count := c.S
	if c.Scheme == "Yu" {
		count++
	}
	if len(m.SRS) != count {
		return nil, errors.New("invalid SRS length")
	}
	srs := make([]*bn.G1, count)
	for i, b := range m.SRS {
		srs[i], err = point(b)
		if err != nil {
			return nil, err
		}
	}
	h := sha256.Sum256(env.Body)
	v := &Client{Manifest: m, Digest: hex.EncodeToString(h[:])}
	switch c.Scheme {
	case "MultiAudit":
		g2, err := point2(m.G2)
		if err != nil {
			return nil, err
		}
		t, err := point2(m.TauG2)
		if err != nil {
			return nil, err
		}
		v.f = &multiaudit.Protocol{Config: multiaudit.Config{NumFiles: c.M, ChunksPerFile: c.N, SectorsPerChunk: c.S, ChallengedChunks: c.C}, PP: multiaudit.PublicParams{SRSG1: srs, G2: g2, TauG2: t}}
		// Challenge uses private randomness in Protocol; a public-only constructor
		// below samples the same uniform distributions without storing a trapdoor.
		v.fs = &multiaudit.StoredBatch{SRSID: m.SRSID, Roots: m.Roots, Files: make([]multiaudit.StoredFile, c.M)}
		for i := range v.fs.Files {
			v.fs.Files[i] = multiaudit.StoredFile{FileID: m.IDs[i], Version: m.Versions[i], Root: m.Roots[i]}
		}
	case "Xu":
		g2, err := point2(m.G2)
		if err != nil {
			return nil, err
		}
		t, err := point2(m.TauG2)
		if err != nil {
			return nil, err
		}
		v.x = &xutifs26.Protocol{M: c.M, N: c.N, S: c.S, SRSG1: srs, G2: g2, AlphaG2: t}
		v.xs = &xutifs26.StoredBatch{Roots: m.Roots, Files: make([]xutifs26.StoredFile, c.M)}
	case "Yu":
		v.y = &yutc25.Protocol{N: c.N, S: c.S, SRS: srs}
		v.ys = &yutc25.StoredBatch{Roots: m.Roots, Files: make([]*yutc25.StoredData, c.M)}
	}
	return v, nil
}

func point(b []byte) (*bn.G1, error) {
	if len(b) != 64 {
		return nil, errors.New("invalid G1 encoding")
	}
	p := new(bn.G1)
	rest, err := p.Unmarshal(b)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("invalid G1 point")
	}
	return p, nil
}
func point2(b []byte) (*bn.G2, error) {
	if len(b) != 128 {
		return nil, errors.New("invalid G2 encoding")
	}
	p := new(bn.G2)
	rest, err := p.Unmarshal(b)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("invalid G2 point")
	}
	return p, nil
}

func (v *Client) Challenge() ([]byte, error) {
	v.pending = false
	c := v.Manifest.Config
	switch c.Scheme {
	case "MultiAudit":
		// Sampling is exactly the native Challenge distribution: ordered indices
		// without replacement, independent scalars, distinct points, fresh nonce.
		indices, err := benchcore.RandomUniqueIndices(rand.Reader, c.C, c.N)
		if err != nil {
			return nil, err
		}
		v.fc = &multiaudit.Challenge{Indices: indices, Coefficients: make([][]*big.Int, c.M), EvaluationPoints: make([]*big.Int, c.M), Nonce: make([]byte, 32)}
		for i := 0; i < c.M; i++ {
			v.fc.Coefficients[i] = make([]*big.Int, c.C)
			for j := 0; j < c.C; j++ {
				v.fc.Coefficients[i][j], err = benchcore.RandomScalar(rand.Reader, false)
				if err != nil {
					return nil, err
				}
			}
		}
		seen := map[string]bool{}
		for i := 0; i < c.M; i++ {
			for {
				x, e := benchcore.RandomScalar(rand.Reader, false)
				if e != nil {
					return nil, e
				}
				if !seen[x.String()] {
					seen[x.String()] = true
					v.fc.EvaluationPoints[i] = x
					break
				}
			}
		}
		if _, err = rand.Read(v.fc.Nonce); err != nil {
			return nil, err
		}
	case "Xu":
		v.xc = v.x.Challenge(c.C)
	case "Yu":
		v.yc = v.y.BatchChallenge(c.M, c.C)
	}
	wire, err := v.encodeChallenge()
	if err == nil {
		v.pending = true
	}
	return wire, err
}

type Verification struct {
	Accepted   bool    `json:"accepted"`
	DecodeMS   float64 `json:"decode_ms"`
	VerifyMS   float64 `json:"verify_ms"`
	ProofBytes int     `json:"proof_bytes"`
}

func (v *Client) Verify(wire []byte) (Verification, error) {
	out := Verification{ProofBytes: len(wire)}
	if !v.pending {
		return out, errors.New("no pending challenge")
	}
	v.pending = false
	if len(wire) > MaxWire {
		return out, errors.New("response too large")
	}
	start := time.Now()
	verify, err := v.decodeProof(wire)
	out.DecodeMS = float64(time.Since(start).Nanoseconds()) / 1e6
	if err != nil {
		return out, err
	}
	start = time.Now()
	out.Accepted = verify()
	out.VerifyMS = float64(time.Since(start).Nanoseconds()) / 1e6
	return out, nil
}

func (v *Client) Describe() string {
	return fmt.Sprintf("%s: %d files, %d sectors, %d challenges", v.Manifest.Config.Scheme, v.Manifest.Config.M, v.Manifest.Config.S, v.Manifest.Config.C)
}
