// Generate fresh single-file audits from the native implementations.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"math/rand"
	"os"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"multiaudit/schemes/benchcore"
	"multiaudit/schemes/multiaudit"
	"multiaudit/schemes/xutifs26"
	"multiaudit/schemes/yutc25"
)

const n, s, c = 3907, 80, 690

type audit struct {
	Challenge string `json:"challenge"`
	Proof     string `json:"proof"`
}
type fixture struct {
	Scheme string   `json:"scheme"`
	Root   string   `json:"root"`
	Prefix string   `json:"prefix"`
	G2     string   `json:"g2"`
	TauG2  string   `json:"tau_g2"`
	SRS    []string `json:"srs"`
	Audits []audit  `json:"audits"`
}

func hx(b []byte) string       { return "0x" + hex.EncodeToString(b) }
func word(n int) []byte        { return new(big.Int).SetInt64(int64(n)).FillBytes(make([]byte, 32)) }
func scalar(b *big.Int) []byte { return benchcore.ScalarBytes(b) }
func challenge(id []byte, r *big.Int, indices []int, coefficients []*big.Int) []byte {
	out := append(append([]byte{}, id...), scalar(r)...)
	for k, index := range indices {
		out = append(out, word(index)...)
		out = append(out, scalar(coefficients[k])...)
	}
	return out
}
func opening(out []byte, tag *bn256.G1, siblings [][]byte) []byte {
	out = append(out, tag.Marshal()...)
	for _, h := range siblings {
		out = append(out, h...)
	}
	return out
}
func main() {
	path := flag.String("out", "/private/tmp/multiaudit-onchain-fixtures.json", "fixture JSON")
	repeats := flag.Int("repeats", 10, "fresh audits per scheme")
	flag.Parse()
	data := make([][][]*big.Int, 1)
	data[0] = make([][]*big.Int, n)
	flat := benchcore.NewStoredScalars(n * s)
	for j := 0; j < n; j++ {
		data[0][j] = flat[j*s : (j+1)*s : (j+1)*s]
		for k := 0; k < s; k++ {
			data[0][j][k].Set(benchcore.Scalar("onchain/equal-byte-file", j*s+k))
		}
	}
	var all []fixture
	x := xutifs26.NewProtocol(1, n, s)
	xstore, err := x.Store(data)
	must(err)
	xf := fixture{Scheme: "XuTIFS26", Root: hx(xstore.Roots[0]), G2: hx(x.G2.Marshal()), TauG2: hx(x.AlphaG2.Marshal())}
	for run := 0; run < *repeats; run++ {
		ch := x.ChallengeFromSeed(scalar(benchcore.Scalar("onchain/xu/audit", run)), c)
		pr, err := x.Prove(xstore, ch)
		must(err)
		if !x.Verify(xstore, ch, pr) {
			panic("native Xu verification failed")
		}
		fp := pr.Files[0]
		out := append(scalar(fp.Value), fp.W.Marshal()...)
		for _, o := range fp.Tags {
			out = opening(out, o.Tag, o.Path.Siblings)
		}
		xf.Audits = append(xf.Audits, audit{hx(challenge(ch.Seed, ch.R, ch.Indices, ch.Coeffs)), hx(out)})
	}
	all = append(all, xf)
	y := yutc25.NewProtocolWithReader(n, s, rand.New(rand.NewSource(2026111901)))
	ystore, err := y.Store(data[0])
	must(err)
	yf := fixture{Scheme: "YuTC25", Root: hx(ystore.Root)}
	for _, p := range y.SRS {
		yf.SRS = append(yf.SRS, hx(p.Marshal()))
	}
	for run := 0; run < *repeats; run++ {
		k1, k2 := scalar(benchcore.Scalar("onchain/yu/k1", run)), scalar(benchcore.Scalar("onchain/yu/k2", run))
		ch := y.ChallengeFromKeys(k1, k2, c)
		pr, err := y.Prove(ystore, ch)
		must(err)
		if !y.Verify(ystore.Root, ch, pr) {
			panic("native Yu verification failed")
		}
		out := append(scalar(pr.Value), pr.B.Marshal()...)
		for k := 0; k < s-1; k++ {
			v := new(big.Int)
			if k < len(pr.Quotient.Coeffs) {
				v = pr.Quotient.Coeffs[k]
			}
			out = append(out, scalar(v)...)
		}
		for _, o := range pr.Openings {
			out = opening(out, o.Tag, o.Path.Siblings)
		}
		id := benchcore.HashBytes("onchain/audit-id", k1, k2)
		yf.Audits = append(yf.Audits, audit{hx(challenge(id, ch.Z, ch.Indices, ch.Coeffs)), hx(out)})
	}
	all = append(all, yf)
	f, err := multiaudit.Setup(multiaudit.Config{NumFiles: 1, ChunksPerFile: n, SectorsPerChunk: s, ChallengedChunks: c}, rand.New(rand.NewSource(2026111902)))
	must(err)
	fstore, err := f.Store(data)
	must(err)
	parts := [][]byte{f.PP.G2.Marshal(), f.PP.TauG2.Marshal()}
	for _, p := range f.PP.SRSG1 {
		parts = append(parts, p.Marshal())
	}
	srsID := benchcore.HashBytes("multiaudit:srs", parts...)
	parts = [][]byte{[]byte("MultiAudit"), []byte(multiaudit.ProtocolID), srsID, benchcore.IntBytes(1), benchcore.IntBytes(n), benchcore.IntBytes(s), benchcore.IntBytes(c), fstore.Files[0].FileID, benchcore.IntBytes(1), fstore.Roots[0]}
	var prefix []byte
	for _, p := range parts {
		prefix = append(prefix, benchcore.IntBytes(len(p))...)
		prefix = append(prefix, p...)
	}
	ff := fixture{Scheme: "MultiAudit", Root: hx(fstore.Roots[0]), Prefix: hx(prefix), G2: hx(f.PP.G2.Marshal()), TauG2: hx(f.PP.TauG2.Marshal())}
	for run := 0; run < *repeats; run++ {
		ch, err := f.Challenge()
		must(err)
		pr, err := f.ProofGen(fstore, ch)
		must(err)
		if !f.Verify(fstore.Registry(), ch, pr) {
			panic("native MultiAudit verification failed")
		}
		fp := pr.FileProofs[0]
		out := append(pr.CQ.Marshal(), pr.CW.Marshal()...)
		out = append(out, scalar(fp.YTilde)...)
		out = append(out, fp.R.Marshal()...)
		out = append(out, pr.PiR[0].A.Marshal()...)
		out = append(out, scalar(pr.PiR[0].Z)...)
		out = append(out, word(len(fp.Auxiliary))...)
		for _, tag := range fp.Tags {
			out = append(out, tag.Marshal()...)
		}
		for _, h := range fp.Auxiliary {
			out = append(out, h...)
		}
		ff.Audits = append(ff.Audits, audit{hx(challenge(ch.Nonce, ch.EvaluationPoints[0], ch.Indices, ch.Coefficients[0])), hx(out)})
	}
	all = append(all, ff)
	b, err := json.Marshal(all)
	must(err)
	must(os.WriteFile(*path, b, 0644))
	fmt.Printf("Generated %d native-verified audits per scheme at (m,n,s,c)=(1,%d,%d,%d)\n", *repeats, n, s, c)
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
