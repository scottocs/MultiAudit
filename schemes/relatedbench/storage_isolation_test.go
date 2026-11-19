package relatedbench

import (
	"math/big"
	"testing"

	"multiaudit/schemes/benchcore"
	"multiaudit/schemes/miaoscis2026"
	"multiaudit/schemes/xutifs26"
	"multiaudit/schemes/yutc25"
	"multiaudit/schemes/zhangtpds23"
)

// Store must own all uploaded values even when the caller later reuses its
// input buffers. Cover the common storage helper at every comparison call site.
func TestComparisonStoresIsolateCallerBuffers(t *testing.T) {
	t.Run("Xu", func(t *testing.T) {
		data := dataset(2, 8, 4, "isolation/xu")
		p := xutifs26.NewProtocol(2, 8, 4)
		stored, e := p.Store(data)
		if e != nil {
			t.Fatal(e)
		}
		data[0][0][0].SetInt64(0)
		data[1][0][1] = new(big.Int)
		if !p.TagVerify(stored) {
			t.Fatal("caller mutation changed tags' committed data")
		}
		c := p.ChallengeFromSeed([]byte("isolation/xu"), 4)
		proof, e := p.Prove(stored, c)
		if e != nil || !p.Verify(stored, c, proof) {
			t.Fatal("audit failed after caller reused buffers", e)
		}
	})
	t.Run("Zhang", func(t *testing.T) {
		data := dataset(2, 8, 4, "isolation/zhang")
		p := zhangtpds23.NewProtocol(2, 8, 4)
		stored, e := p.Store(data)
		if e != nil {
			t.Fatal(e)
		}
		data[0][0][0].SetInt64(0)
		data[1][0][1] = new(big.Int)
		if !p.TagVerify(stored) {
			t.Fatal("caller mutation changed tags' committed data")
		}
		c := p.ChallengeFromSeed([]byte("isolation/zhang"), 4)
		proof, e := p.Prove(stored, c)
		if e != nil || !p.Verify(stored, c, proof) {
			t.Fatal("audit failed after caller reused buffers", e)
		}
	})
	t.Run("Yu", func(t *testing.T) {
		data := dataset(2, 8, 4, "isolation/yu")
		p := yutc25.NewProtocol(8, 4)
		stored, e := p.StoreBatch(data)
		if e != nil {
			t.Fatal(e)
		}
		data[0][0][0].SetInt64(0)
		data[1][0][1] = new(big.Int)
		c := p.BatchChallenge(2, 4)
		proof, e := p.ProveBatch(stored, c)
		if e != nil || !p.VerifyBatch(stored, c, proof) {
			t.Fatal("audit failed after caller reused buffers", e)
		}
	})
	t.Run("Miao", func(t *testing.T) {
		p := miaoscis2026.NewProtocol(8)
		data := []miaoscis2026.InputFile{{FID: "a", Keywords: []string{"audit"}, Blocks: scalars(8, "isolation/miao")}}
		stored, e := p.Store(data)
		if e != nil {
			t.Fatal(e)
		}
		before := benchcore.Normalize(stored.Files[0].Blocks[0])
		data[0].Blocks[0].SetInt64(0)
		data[0].Blocks[1] = new(big.Int)
		if stored.Files[0].Blocks[0].Cmp(before) != 0 {
			t.Fatal("caller mutation changed stored data")
		}
		trap, e := p.Trapdoor(stored, []string{"audit"})
		if e != nil {
			t.Fatal(e)
		}
		c := p.ChallengeWithTrapdoor(trap, 4, 1)
		proof, e := p.Prove(stored, c)
		if e != nil || !p.Verify(stored, c, proof) {
			t.Fatal("audit failed after caller reused buffers", e)
		}
	})
}
