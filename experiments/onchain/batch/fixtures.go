// Generate complete native batch fixtures; no gas extrapolation or proof stubs.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	bn "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"math/big"
	"math/rand"
	"multiaudit/schemes/benchcore"
	"multiaudit/schemes/multiaudit"
	"multiaudit/schemes/xutifs26"
	"multiaudit/schemes/yutc25"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type audit struct {
	Challenge string `json:"challenge"`
	Proof     string `json:"proof"`
}
type fixture struct {
	Scheme         string   `json:"scheme"`
	M              int      `json:"m"`
	N              int      `json:"n"`
	S              int      `json:"s"`
	C              int      `json:"c"`
	Roots          []string `json:"roots"`
	IDs            []string `json:"ids"`
	Prefix         string   `json:"prefix"`
	G2             string   `json:"g2"`
	TauG2          string   `json:"tau_g2"`
	SRS            []string `json:"srs"`
	NativeVerified bool     `json:"native_verified"`
	Audits         []audit  `json:"audits"`
}

func hx(b []byte) string       { return "0x" + hex.EncodeToString(b) }
func scalar(x *big.Int) []byte { return benchcore.ScalarBytes(x) }
func word(x int) []byte        { return new(big.Int).SetInt64(int64(x)).FillBytes(make([]byte, 32)) }
func challenge(id []byte, r *big.Int, indices []int, coeffs []*big.Int) []byte {
	out := append(append([]byte(nil), id...), scalar(r)...)
	for j, index := range indices {
		out = append(out, word(index)...)
		out = append(out, scalar(coeffs[j])...)
	}
	return out
}
func opening(out []byte, tag *bn.G1, siblings [][]byte) []byte {
	out = append(out, tag.Marshal()...)
	for _, h := range siblings {
		out = append(out, h...)
	}
	return out
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
func base(name string, data [][][]*big.Int, c int) fixture {
	f := fixture{Scheme: name, M: len(data), N: len(data[0]), S: len(data[0][0]), C: c, Prefix: "0x", G2: "0x", TauG2: "0x", NativeVerified: true}
	for i := range data {
		f.IDs = append(f.IDs, hx([]byte(fmt.Sprintf("file-%d", i))))
	}
	return f
}
func xu(data [][][]*big.Int, c, repeats int) fixture {
	f := base("XuTIFS26", data, c)
	p := xutifs26.NewProtocol(f.M, f.N, f.S)
	st, err := p.Store(data)
	must(err)
	for _, root := range st.Roots {
		f.Roots = append(f.Roots, hx(root))
	}
	f.G2 = hx(p.G2.Marshal())
	f.TauG2 = hx(p.AlphaG2.Marshal())
	for run := 0; run < repeats; run++ {
		ch := p.ChallengeFromSeed(scalar(benchcore.Scalar("onchain-batch/xu/challenge", run)), c)
		pr, err := p.Prove(st, ch)
		must(err)
		if !p.Verify(st, ch, pr) {
			panic("native Xu batch rejected")
		}
		var out []byte
		for _, fp := range pr.Files {
			out = append(out, scalar(fp.Value)...)
			out = append(out, fp.W.Marshal()...)
			for _, o := range fp.Tags {
				out = opening(out, o.Tag, o.Path.Siblings)
			}
		}
		f.Audits = append(f.Audits, audit{hx(challenge(ch.Seed, ch.R, ch.Indices, ch.Coeffs)), hx(out)})
	}
	return f
}
func yu(data [][][]*big.Int, c, repeats int) fixture {
	f := base("YuTC25", data, c)
	p := yutc25.NewProtocolWithReader(f.N, f.S, rand.New(rand.NewSource(2026112401)))
	st, err := p.StoreBatch(data)
	must(err)
	for _, root := range st.Roots {
		f.Roots = append(f.Roots, hx(root))
	}
	for _, v := range p.SRS {
		f.SRS = append(f.SRS, hx(v.Marshal()))
	}
	for run := 0; run < repeats; run++ {
		ch := yutc25.BatchChallenge{FileChallenges: make([]yutc25.Challenge, f.M)}
		var encoded []byte
		for i := range ch.FileChallenges {
			k1 := scalar(benchcore.Scalar("onchain-batch/yu/k1", run*f.M+i))
			k2 := scalar(benchcore.Scalar("onchain-batch/yu/k2", run*f.M+i))
			fc := p.ChallengeFromKeys(k1, k2, c)
			ch.FileChallenges[i] = fc
			encoded = append(encoded, challenge(benchcore.HashBytes("onchain-batch/audit-id", k1, k2), fc.Z, fc.Indices, fc.Coeffs)...)
		}
		pr, err := p.ProveBatch(st, ch)
		must(err)
		if !p.VerifyBatch(st, ch, pr) {
			panic("native Yu batch rejected")
		}
		var out []byte
		for _, fp := range pr.Proofs {
			out = append(out, scalar(fp.Value)...)
			out = append(out, fp.B.Marshal()...)
			for k := 0; k < f.S-1; k++ {
				v := new(big.Int)
				if k < len(fp.Quotient.Coeffs) {
					v = fp.Quotient.Coeffs[k]
				}
				out = append(out, scalar(v)...)
			}
			for _, o := range fp.Openings {
				out = opening(out, o.Tag, o.Path.Siblings)
			}
		}
		f.Audits = append(f.Audits, audit{hx(encoded), hx(out)})
	}
	return f
}
func multi(data [][][]*big.Int, c, repeats int) fixture {
	f := base("MultiAudit", data, c)
	p, err := multiaudit.Setup(multiaudit.Config{NumFiles: f.M, ChunksPerFile: f.N, SectorsPerChunk: f.S, ChallengedChunks: c}, rand.New(rand.NewSource(2026112402)))
	must(err)
	st, err := p.Store(data)
	must(err)
	for _, root := range st.Roots {
		f.Roots = append(f.Roots, hx(root))
	}
	f.G2 = hx(p.PP.G2.Marshal())
	f.TauG2 = hx(p.PP.TauG2.Marshal())
	parts := [][]byte{[]byte("MultiAudit"), []byte(multiaudit.ProtocolID), st.SRSID, benchcore.IntBytes(f.M), benchcore.IntBytes(f.N), benchcore.IntBytes(f.S), benchcore.IntBytes(c)}
	for _, file := range st.Files {
		parts = append(parts, file.FileID, benchcore.IntBytes(int(file.Version)), file.Root)
	}
	var prefix []byte
	for _, part := range parts {
		prefix = append(prefix, benchcore.IntBytes(len(part))...)
		prefix = append(prefix, part...)
	}
	f.Prefix = hx(prefix)
	for run := 0; run < repeats; run++ {
		ch, err := p.Challenge()
		must(err)
		pr, err := p.ProofGen(st, ch)
		must(err)
		if !p.Verify(st.Registry(), ch, pr) {
			panic("native MultiAudit batch rejected")
		}
		encoded := append([]byte(nil), ch.Nonce...)
		for _, j := range ch.Indices {
			encoded = append(encoded, word(j)...)
		}
		for i := range ch.EvaluationPoints {
			encoded = append(encoded, scalar(ch.EvaluationPoints[i])...)
			for _, v := range ch.Coefficients[i] {
				encoded = append(encoded, scalar(v)...)
			}
		}
		out := append(pr.CQ.Marshal(), pr.CW.Marshal()...)
		for _, fp := range pr.FileProofs {
			out = append(out, scalar(fp.Value)...)
			out = append(out, word(len(fp.Auxiliary))...)
			for _, tag := range fp.Tags {
				out = append(out, tag.Marshal()...)
			}
			for _, h := range fp.Auxiliary {
				out = append(out, h...)
			}
		}
		f.Audits = append(f.Audits, audit{hx(encoded), hx(out)})
	}
	return f
}
func main() {
	out := flag.String("out-dir", "/private/tmp/multiaudit-onchain-batch-fixtures", "fixture directory")
	scan := flag.String("m", "10,20,30,40", "file counts")
	names := flag.String("schemes", "XuTIFS26,YuTC25,MultiAudit", "schemes")
	n := flag.Int("n", 3907, "chunks per file")
	s := flag.Int("s", 80, "sectors per chunk")
	c := flag.Int("c", 690, "challenged chunks")
	repeats := flag.Int("repeats", 5, "fresh audits per scheme and file count")
	flag.Parse()
	if *repeats < 1 || *n < 1 || *s < 2 || *c < 1 || *c > *n {
		panic("invalid dimensions")
	}
	must(os.MkdirAll(*out, 0755))
	var index []string
	for _, entry := range strings.Split(*scan, ",") {
		m, err := strconv.Atoi(entry)
		must(err)
		if m < 1 {
			panic("invalid m")
		}
		fmt.Printf("Preparing %d complete files n=%d s=%d\n", m, *n, *s)
		data := make([][][]*big.Int, m)
		for i := range data {
			flat := benchcore.NewStoredScalars(*n * *s)
			data[i] = make([][]*big.Int, *n)
			for j := 0; j < *n; j++ {
				data[i][j] = flat[j**s : (j+1)**s : (j+1)**s]
				for k := 0; k < *s; k++ {
					flat[j**s+k].Set(benchcore.Scalar("onchain-batch/equal-byte-file", i**n**s+j**s+k))
				}
			}
		}
		for _, name := range strings.Split(*names, ",") {
			fmt.Printf("Generating %s m=%d repeats=%d\n", name, m, *repeats)
			var f fixture
			switch name {
			case "XuTIFS26":
				f = xu(data, *c, *repeats)
			case "YuTC25":
				f = yu(data, *c, *repeats)
			case "MultiAudit":
				f = multi(data, *c, *repeats)
			default:
				panic(name)
			}
			b, err := json.Marshal(f)
			must(err)
			name := fmt.Sprintf("%s-m%d.json", name, m)
			must(os.WriteFile(filepath.Join(*out, name), b, 0644))
			index = append(index, name)
			runtime.GC()
		}
	}
	b, err := json.MarshalIndent(index, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(*out, "index.json"), b, 0644))
}
