package multiaudit

import (
	"bytes"
	"io"
	"math/big"
	"testing"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"multiaudit/schemes/benchcore"
)

type deterministicReader struct {
	state uint64
}

func newDeterministicReader(seed uint64) io.Reader {
	return &deterministicReader{state: seed}
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	for i := range p {
		r.state = r.state*6364136223846793005 + 1442695040888963407
		p[i] = byte(r.state >> 56)
	}
	return len(p), nil
}

func testProtocol(t *testing.T, seed uint64) *Protocol {
	t.Helper()
	cfg := DefaultConfig()
	cfg.NumFiles = 3
	cfg.ChunksPerFile = 64
	cfg.SectorsPerChunk = 40
	cfg.ChallengedChunks = 40

	protocol, err := Setup(cfg, newDeterministicReader(seed))
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	return protocol
}

func TestHonestMultiAuditRoundAccepts(t *testing.T) {
	protocol := testProtocol(t, 11)
	data, err := protocol.RandomDataset()
	if err != nil {
		t.Fatalf("RandomDataset failed: %v", err)
	}
	stored, err := protocol.Store(data)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	chal, err := protocol.Challenge()
	if err != nil {
		t.Fatalf("Challenge failed: %v", err)
	}
	proof, err := protocol.ProofGen(stored, chal)
	if err != nil {
		t.Fatalf("ProofGen failed: %v", err)
	}
	if !protocol.Verify(stored, chal, proof) {
		t.Fatal("Verify rejected honest proof")
	}
}

func TestProofGenDoesNotUseTrapdoor(t *testing.T) {
	protocol := testProtocol(t, 14)
	data, err := protocol.RandomDataset()
	if err != nil {
		t.Fatalf("RandomDataset failed: %v", err)
	}
	stored, err := protocol.Store(data)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	chal, err := protocol.Challenge()
	if err != nil {
		t.Fatalf("Challenge failed: %v", err)
	}

	protocol.tau = nil

	proof, err := protocol.ProofGen(stored, chal)
	if err != nil {
		t.Fatalf("ProofGen failed without trapdoor: %v", err)
	}
	if !protocol.Verify(stored, chal, proof) {
		t.Fatal("Verify rejected proof generated without trapdoor")
	}
}

func TestTamperedProofFieldsAreRejected(t *testing.T) {
	protocol := testProtocol(t, 12)
	data, _ := protocol.RandomDataset()
	stored, err := protocol.Store(data)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	chal, err := protocol.Challenge()
	if err != nil {
		t.Fatalf("Challenge failed: %v", err)
	}
	proof, err := protocol.ProofGen(stored, chal)
	if err != nil {
		t.Fatalf("ProofGen failed: %v", err)
	}
	if !protocol.Verify(stored, chal, proof) {
		t.Fatal("Verify rejected honest proof")
	}

	tamperedY := cloneProof(proof)
	tamperedY.FileProofs[0].YTilde = benchcore.Add(tamperedY.FileProofs[0].YTilde, benchcore.One())
	if protocol.Verify(stored, chal, tamperedY) {
		t.Fatal("Verify accepted tampered masked evaluation")
	}

	tamperedCQ := cloneProof(proof)
	tamperedCQ.CQ = benchcore.G1Add(tamperedCQ.CQ, benchcore.G1Base(benchcore.One()))
	if protocol.Verify(stored, chal, tamperedCQ) {
		t.Fatal("Verify accepted tampered quotient commitment")
	}
}

func TestTamperedChallengedDataWithOldTagsIsRejected(t *testing.T) {
	protocol := testProtocol(t, 13)
	data, _ := protocol.RandomDataset()
	stored, err := protocol.Store(data)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	chal, err := protocol.Challenge()
	if err != nil {
		t.Fatalf("Challenge failed: %v", err)
	}

	chunk := chal.Indices[0]
	stored.Files[0].Sectors[chunk][0] = benchcore.Add(stored.Files[0].Sectors[chunk][0], benchcore.One())
	stored.Files[0].Polynomials[chunk] = benchcore.NewPoly(stored.Files[0].Sectors[chunk])

	proof, err := protocol.ProofGen(stored, chal)
	if err != nil {
		t.Fatalf("ProofGen failed: %v", err)
	}
	if protocol.Verify(stored, chal, proof) {
		t.Fatal("Verify accepted proof generated from data inconsistent with authenticated tags")
	}
}

func TestMerkleLeafBindsFileAndPosition(t *testing.T) {
	tag := benchcore.G1Base(benchcore.One())
	leafA := merkleLeaf([]byte("file-a"), 0, tag)
	leafB := merkleLeaf([]byte("file-b"), 0, tag)
	leafC := merkleLeaf([]byte("file-a"), 1, tag)
	if bytes.Equal(leafA, leafB) || bytes.Equal(leafA, leafC) {
		t.Fatal("merkle leaf does not bind file id and chunk index")
	}
}

func cloneProof(proof *AuditProof) *AuditProof {
	out := &AuditProof{FileProofs: make([]FileProof, len(proof.FileProofs)), PiR: make([]SchnorrProof, len(proof.PiR)), CQ: cloneG1(proof.CQ), CW: cloneG1(proof.CW)}
	for i, fp := range proof.FileProofs {
		tags := make([]*bn256.G1, len(fp.Tags))
		for j, tag := range fp.Tags {
			tags[j] = cloneG1(tag)
		}
		aux := make([][]byte, len(fp.Auxiliary))
		for j, h := range fp.Auxiliary {
			aux[j] = benchcore.CloneBytes(h)
		}
		out.FileProofs[i] = FileProof{Tags: tags, Auxiliary: aux, YTilde: benchcore.Normalize(fp.YTilde), R: cloneG1(fp.R)}
	}
	for i, pi := range proof.PiR {
		out.PiR[i] = SchnorrProof{A: cloneG1(pi.A), Z: benchcore.Normalize(pi.Z)}
	}
	return out
}

// Exercise the final pairing with authenticated tags and freshly signed mask
// proofs. Rebuild both witnesses after each statement change, so rejection
// cannot be attributed merely to stale Fiat-Shamir mask challenges.
func TestSHPLONKRejectsFalseEvaluationWithValidMaskProofs(t *testing.T) {
	p := testProtocol(t, 701)
	data, _ := p.RandomDataset()
	stored, err := p.Store(data)
	if err != nil {
		t.Fatal(err)
	}
	chal, _ := p.Challenge()
	proof, err := p.ProofGen(stored, chal)
	if err != nil {
		t.Fatal(err)
	}
	masks := make([]*big.Int, p.Config.NumFiles)
	qs := make([]benchcore.Poly, len(masks))
	for i := range masks {
		masks[i] = benchcore.Scalar("test/mask", i)
		f, _ := p.aggregatePolynomial(stored.Files[i], chal, i)
		y := f.Eval(chal.EvaluationPoints[i])
		qs[i], _ = f.SubConstant(y).DivLinear(chal.EvaluationPoints[i])
		proof.FileProofs[i].R = benchcore.G1Base(masks[i])
		proof.FileProofs[i].YTilde = benchcore.Add(y, masks[i])
	}
	rebuild := func() {
		T := p.baseTranscript(stored, chal, proof.FileProofs)
		p.commitQuotients(T, chal, proof, qs)
		proof.PiR, err = p.schnorrMaskProofs(T, proof, masks)
		if err != nil {
			t.Fatal(err)
		}
		if !p.verifySchnorrMaskProofs(T, proof) {
			t.Fatal("invalid test mask proofs")
		}
	}
	rebuild()
	if !p.Verify(stored, chal, proof) {
		t.Fatal("honest rebuilt proof rejected")
	}
	proof.FileProofs[0].YTilde = benchcore.Add(proof.FileProofs[0].YTilde, benchcore.One())
	// Opposite errors must not cancel across distinct file evaluation points.
	proof.FileProofs[1].YTilde = benchcore.Sub(proof.FileProofs[1].YTilde, benchcore.One())
	rebuild()
	if p.Verify(stored, chal, proof) {
		t.Fatal("false claims accepted with valid mask proofs")
	}
}

func TestProtocolBoundaryAndEncoding(t *testing.T) {
	for _, shape := range [][3]int{{1, 1, 2}, {3, 3, 2}, {17, 8, 5}, {17, 17, 2}} {
		cfg := Config{NumFiles: 2, ChunksPerFile: shape[0], ChallengedChunks: shape[1], SectorsPerChunk: shape[2]}
		p, err := Setup(cfg, newDeterministicReader(uint64(900+shape[0]+shape[1])))
		if err != nil {
			t.Fatal(err)
		}
		data, _ := p.RandomDataset()
		stored, err := p.Store(data)
		if err != nil {
			t.Fatal(err)
		}
		chal, _ := p.Challenge()
		// Zero coefficients and a zero evaluation point are allowed by the paper.
		chal.EvaluationPoints[0] = benchcore.Zero()
		chal.EvaluationPoints[1] = benchcore.One()
		chal.Coefficients[0][0] = benchcore.Zero()
		proof, err := p.ProofGen(stored, chal)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := p.MarshalProof(proof)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := p.UnmarshalProof(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !p.Verify(stored, chal, decoded) {
			t.Fatal("round-trip proof rejected")
		}
		aux := 0
		for _, fp := range proof.FileProofs {
			aux += len(fp.Auxiliary)
		}
		want := 12 + 4*cfg.NumFiles + (cfg.NumFiles*cfg.ChallengedChunks+2*cfg.NumFiles+2)*64 + 2*cfg.NumFiles*32 + aux*32
		if len(raw) != want {
			t.Fatalf("response has %d bytes, want %d", len(raw), want)
		}
		for _, bad := range [][]byte{raw[:len(raw)-1], append(append([]byte(nil), raw...), 0), {}} {
			if _, err := p.UnmarshalProof(bad); err == nil {
				t.Fatal("malformed encoding accepted")
			}
		}
		// A verifier only requires authenticated metadata, not retained server data.
		registry := stored.Registry()
		if !p.Verify(registry, chal, proof) {
			t.Fatal("metadata-only verification failed")
		}
	}
}
func TestTranscriptAndMalformedProofRejection(t *testing.T) {
	p := testProtocol(t, 914)
	data, _ := p.RandomDataset()
	stored, _ := p.Store(data)
	chal, _ := p.Challenge()
	proof, err := p.ProofGen(stored, chal)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*AuditProof){
		"CW":          func(q *AuditProof) { q.CW = benchcore.G1Add(q.CW, benchcore.G1Base(benchcore.One())) },
		"nilCQ":       func(q *AuditProof) { q.CQ = nil },
		"nilR":        func(q *AuditProof) { q.FileProofs[0].R = nil },
		"nilY":        func(q *AuditProof) { q.FileProofs[0].YTilde = nil },
		"scalarAlias": func(q *AuditProof) { q.PiR[0].Z.Add(q.PiR[0].Z, benchcore.Order) },
		"tag":         func(q *AuditProof) { q.FileProofs[0].Tags[0] = q.FileProofs[1].Tags[0] },
		"aux":         func(q *AuditProof) { q.FileProofs[0].Auxiliary = append(q.FileProofs[0].Auxiliary, make([]byte, 32)) },
		"A":           func(q *AuditProof) { q.PiR[0].A = benchcore.G1Base(benchcore.One()) },
	} {
		t.Run(name, func(t *testing.T) {
			q := cloneProof(proof)
			mutate(q)
			if p.Verify(stored, chal, q) {
				t.Fatal("tampered proof accepted")
			}
		})
	}
	old := chal.Nonce[0]
	chal.Nonce[0] ^= 1
	if p.Verify(stored, chal, proof) {
		t.Fatal("nonce replay accepted")
	}
	chal.Nonce[0] = old
	stored.Files[0].Version++
	if p.Verify(stored, chal, proof) {
		t.Fatal("version replay accepted")
	}
	stored.Files[0].Version--
	stored.Files[0].FileID[0] ^= 1
	if p.Verify(stored, chal, proof) {
		t.Fatal("file identity substitution accepted")
	}
	stored.Files[0].FileID[0] ^= 1
	r := chal.EvaluationPoints[1]
	chal.EvaluationPoints[1] = chal.EvaluationPoints[0]
	if p.Verify(stored, chal, proof) {
		t.Fatal("duplicate point accepted")
	}
	if _, e := p.ProofGen(stored, chal); e == nil {
		t.Fatal("prover accepts duplicate point")
	}
	chal.EvaluationPoints[1] = r
	T := p.baseTranscript(stored, chal, proof.FileProofs)
	z, _ := openingWeights(T, proof.CQ, chal.EvaluationPoints)
	for _, r := range chal.EvaluationPoints {
		if z.Cmp(r) == 0 {
			t.Fatal("forbidden z")
		}
	}
}

func TestIndependentFileManagement(t *testing.T) {
	cfg := Config{NumFiles: 1, ChunksPerFile: 3, SectorsPerChunk: 2, ChallengedChunks: 2}
	p, _ := Setup(cfg, newDeterministicReader(51))
	data, _ := p.RandomDataset()
	stored, _ := p.Store(data)
	root := benchcore.CloneBytes(stored.Roots[0])
	tag := g1Bytes(stored.Files[0].Tags[0])
	added, err := p.AddFile(stored, []byte("new-file"), 2, data[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(root, added.Roots[0]) || !bytes.Equal(tag, g1Bytes(added.Files[0].Tags[0])) {
		t.Fatal("surviving authentication state changed")
	}
	chal, _ := p.Challenge()
	proof, err := p.ProofGen(added, chal)
	if err != nil || !p.Verify(added, chal, proof) {
		t.Fatal("audit after addition failed", err)
	}
	removed, err := p.RemoveFile(added, []byte("new-file"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(root, removed.Roots[0]) {
		t.Fatal("root changed on removal")
	}
	chal, _ = p.Challenge()
	proof, err = p.ProofGen(removed, chal)
	if err != nil || !p.Verify(removed, chal, proof) {
		t.Fatal("audit after removal failed", err)
	}
	empty, err := p.RemoveFile(removed, removed.Files[0].FileID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Challenge(); err == nil {
		t.Fatal("empty audit allowed")
	}
	again, err := p.AddFile(empty, []byte("replacement"), 3, data[0])
	if err != nil {
		t.Fatal(err)
	}
	chal, _ = p.Challenge()
	proof, err = p.ProofGen(again, chal)
	if err != nil || !p.Verify(again, chal, proof) {
		t.Fatal("audit after readdition failed", err)
	}
}

func TestDifferentSRSRegistryRejected(t *testing.T) {
	p := testProtocol(t, 144)
	data, _ := p.RandomDataset()
	stored, _ := p.Store(data)
	other, err := Setup(p.Config, newDeterministicReader(145))
	if err != nil {
		t.Fatal(err)
	}
	chal, _ := other.Challenge()
	if _, err = other.ProofGen(stored, chal); err == nil {
		t.Fatal("mixed-SRS batch accepted")
	}
	if _, err = other.AddFile(stored, []byte("wrong-key"), 1, data[0]); err == nil {
		t.Fatal("mixed-SRS addition accepted")
	}
}
