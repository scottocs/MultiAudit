package miaoscis2026

import (
	"bytes"
	"math/big"
	"testing"

	"multiaudit/schemes/benchcore"
)

func TestChallengeWithTrapdoorUsesFreshRandomKeys(t *testing.T) {
	n, c := 32, 8
	p := NewProtocol(n)
	files := []struct {
		FID      string
		Keywords []string
		Blocks   []*big.Int
	}{
		{FID: "f0", Keywords: []string{"audit", "cloud"}, Blocks: testScalars(n, "miao/random/f0")},
		{FID: "f1", Keywords: []string{"audit", "chain"}, Blocks: testScalars(n, "miao/random/f1")},
		{FID: "f2", Keywords: []string{"cloud"}, Blocks: testScalars(n, "miao/random/f2")},
	}
	stored, err := p.Store(files)
	if err != nil {
		t.Fatal(err)
	}
	trap, err := p.Trapdoor(stored, []string{"audit"})
	if err != nil {
		t.Fatal(err)
	}

	chalA := p.ChallengeWithTrapdoor(trap, c, len(files))
	chalB := p.ChallengeWithTrapdoor(trap, c, len(files))
	if bytes.Equal(chalA.K1, chalB.K1) || bytes.Equal(chalA.K2, chalB.K2) {
		t.Fatal("ChallengeWithTrapdoor reused random keys")
	}
	assertUniqueInRange(t, chalA.Indices, c, n)
	assertUniqueInRange(t, chalB.Indices, c, n)
}

func TestTrapdoorMatchingUsesKeywordUnion(t *testing.T) {
	n, c := 8, 3
	p := NewProtocol(n)
	files := []struct {
		FID      string
		Keywords []string
		Blocks   []*big.Int
	}{
		{FID: "f0", Keywords: []string{"audit", "cloud"}, Blocks: testScalars(n, "miao/union/f0")},
		{FID: "f1", Keywords: []string{"audit", "chain"}, Blocks: testScalars(n, "miao/union/f1")},
		{FID: "f2", Keywords: []string{"cloud"}, Blocks: testScalars(n, "miao/union/f2")},
	}
	stored, err := p.Store(files)
	if err != nil {
		t.Fatal(err)
	}
	trap, err := p.Trapdoor(stored, []string{"audit", "cloud"})
	if err != nil {
		t.Fatal(err)
	}

	chal := p.ChallengeWithTrapdoor(trap, c, len(files))
	matched := matchedByChallenge(stored, chal)
	if len(matched) != 3 || matched[0] != 0 || matched[1] != 1 || matched[2] != 2 {
		t.Fatalf("expected union-matched files [0 1 2], got %v", matched)
	}
}

func TestProveDoesNotUseSecretExponent(t *testing.T) {
	n, c := 8, 3
	p := NewProtocol(n)
	files := []struct {
		FID      string
		Keywords []string
		Blocks   []*big.Int
	}{
		{FID: "f0", Keywords: []string{"audit", "cloud"}, Blocks: testScalars(n, "miao/no-secret/f0")},
		{FID: "f1", Keywords: []string{"audit", "chain"}, Blocks: testScalars(n, "miao/no-secret/f1")},
	}
	stored, err := p.Store(files)
	if err != nil {
		t.Fatal(err)
	}
	trap, err := p.Trapdoor(stored, []string{"audit"})
	if err != nil {
		t.Fatal(err)
	}
	chal := p.ChallengeWithTrapdoor(trap, c, len(files))

	p.x = nil

	proof, err := p.Prove(stored, chal)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Verify(stored, chal, proof) {
		t.Fatal("honest proof generated without secret exponent was rejected")
	}
}

func testScalars(n int, label string) []*big.Int {
	out := make([]*big.Int, n)
	for i := range out {
		out[i] = benchcore.Scalar(label, i)
	}
	return out
}

func assertUniqueInRange(t *testing.T, indices []int, want, n int) {
	t.Helper()
	if len(indices) != want {
		t.Fatalf("expected %d indices, got %d", want, len(indices))
	}
	seen := make(map[int]struct{}, len(indices))
	for _, index := range indices {
		if index < 0 || index >= n {
			t.Fatalf("challenge index %d out of range", index)
		}
		if _, ok := seen[index]; ok {
			t.Fatalf("duplicate challenge index %d", index)
		}
		seen[index] = struct{}{}
	}
}

// A repeated public challenge still needs an independently sampled mask.
func TestProveUsesFreshMask(t *testing.T) {
	p := NewProtocol(40)
	files := []struct {
		FID      string
		Keywords []string
		Blocks   []*big.Int
	}{{"f0", []string{"audit"}, testScalars(40, "miao/fresh-mask")}}
	stored, err := p.Store(files)
	if err != nil {
		t.Fatal(err)
	}
	chal := p.Challenge([]string{"audit"}, 40, 1)
	a, err := p.Prove(stored, chal)
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Prove(stored, chal)
	if err != nil {
		t.Fatal(err)
	}
	if benchcore.G1Eq(a.R, b.R) {
		t.Fatal("proofs reuse the evaluation mask")
	}
	if !p.Verify(stored, chal, a) || !p.Verify(stored, chal, b) {
		t.Fatal("fresh masked proof rejected")
	}
}

func TestParallelFixturePreparationMatchesStore(t *testing.T) {
	p := NewProtocol(64)
	files := []InputFile{{"f0", []string{"audit", "a"}, testScalars(64, "parallel/a")}, {"f1", []string{"audit", "b"}, testScalars(64, "parallel/b")}, {"f2", []string{"audit"}, testScalars(64, "parallel/c")}}
	a, e := p.Store(files)
	if e != nil {
		t.Fatal(e)
	}
	b, e := p.StoreWithWorkers(files, 4)
	if e != nil {
		t.Fatal(e)
	}
	for i := range a.Files {
		for j := range a.Files[i].Sigmas {
			if a.Files[i].Aux[j] != b.Files[i].Aux[j] || !benchcore.G1Eq(a.Files[i].Sigmas[j], b.Files[i].Sigmas[j]) {
				t.Fatal("parallel preparation changes authenticators")
			}
		}
	}
	trap, e := p.Trapdoor(b, []string{"audit"})
	if e != nil {
		t.Fatal(e)
	}
	chal := p.ChallengeWithTrapdoor(trap, 40, len(files))
	proof, e := p.Prove(b, chal)
	if e != nil || !p.Verify(b, chal, proof) {
		t.Fatal("prepared fixture rejected")
	}
}
