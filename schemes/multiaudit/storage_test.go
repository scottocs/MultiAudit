package multiaudit

import (
	"bytes"
	"math/big"
	"testing"

	"multiaudit/schemes/benchcore"
)

func TestStoreOwnsInputAndSharesInternalReadOnlyViews(t *testing.T) {
	p := testProtocol(t, 9041)
	data, _ := p.RandomDataset()
	stored, err := p.Store(data)
	if err != nil {
		t.Fatal(err)
	}
	f := &stored.Files[0]
	original := new(big.Int).Set(f.Sectors[0][0])
	if f.Sectors[0][0] != f.Polynomials[0].Coeffs[0] {
		t.Fatal("duplicate stored sector and coefficient objects")
	}
	data[0][0][0].SetInt64(0)
	if f.Sectors[0][0].Cmp(original) != 0 {
		t.Fatal("Store retained caller-owned scalar")
	}
	data[0][0][0] = big.NewInt(1)
	if f.Sectors[0][0].Cmp(original) != 0 {
		t.Fatal("Store retained caller-owned pointer row")
	}
	chal, _ := p.Challenge()
	p.tau = nil
	p.rand = newDeterministicReader(19041)
	before, err := p.ProofGen(stored, chal)
	if err != nil {
		t.Fatal(err)
	}
	wire1, err := p.MarshalProof(before)
	if err != nil {
		t.Fatal(err)
	}
	p.rand = newDeterministicReader(19041)
	after, err := p.ProofGen(stored, chal)
	if err != nil {
		t.Fatal(err)
	}
	wire2, err := p.MarshalProof(after)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire1, wire2) {
		t.Fatal("ProofGen mutated stored coefficients")
	}
	registry := stored.Registry()
	if !p.Verify(registry, chal, after) {
		t.Fatal("metadata-only verifier rejected proof")
	}
	// Mutation through either owned view changes the data but never updates its
	// authenticators; a malicious server cannot turn it into an accepted opening.
	index := chal.Indices[0]
	f.Sectors[index][0].Add(f.Sectors[index][0], benchcore.One()).Mod(f.Sectors[index][0], benchcore.Order)
	bad, err := p.ProofGen(stored, chal)
	if err != nil {
		t.Fatal(err)
	}
	if p.Verify(registry, chal, bad) {
		t.Fatal("changed data accepted with old tags")
	}
}
