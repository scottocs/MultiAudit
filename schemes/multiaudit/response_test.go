package multiaudit

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math/big"
	"multiaudit/schemes/benchcore"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// This opt-in test measures complete encoded responses for the paper configuration.
func TestResponseMeasurement(t *testing.T) {
	path := os.Getenv("MULTIAUDIT_RESPONSE_CSV")
	if path == "" {
		t.Skip("opt-in response measurement")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	runtime.GOMAXPROCS(1)
	cfg := Config{NumFiles: 40, ChunksPerFile: 3907, SectorsPerChunk: 80, ChallengedChunks: 690}
	p, err := Setup(cfg, newDeterministicReader(20261118))
	if err != nil {
		t.Fatal(err)
	}
	data := make([][][]*big.Int, cfg.NumFiles)
	for i := range data {
		data[i] = make([][]*big.Int, cfg.ChunksPerFile)
		flat := benchcore.NewStoredScalars(cfg.ChunksPerFile * cfg.SectorsPerChunk)
		for j := range data[i] {
			a, b := j*cfg.SectorsPerChunk, (j+1)*cfg.SectorsPerChunk
			data[i][j] = flat[a:b:b]
			for k := range data[i][j] {
				data[i][j][k].Set(benchcore.Scalar("equal-byte-file", i*cfg.ChunksPerFile*cfg.SectorsPerChunk+j*cfg.SectorsPerChunk+k))
			}
		}
	}
	stored, err := p.Store(data)
	if err != nil {
		t.Fatal(err)
	}
	registry := stored.Registry()
	p.tau = nil // Proof generation uses only the public SRS.
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	w := csv.NewWriter(file)
	if err := w.Write([]string{"c", "repeat", "proofgen_ms", "verify_ms", "wire_bytes", "auxiliary_hashes", "ok", "proof_sha256"}); err != nil {
		t.Fatal(err)
	}
	run := func(repeat int) {
		if repeat > 0 {
			p.rand = newDeterministicReader(uint64(20261118 + 690*1000 + repeat))
		}
		runtime.GOMAXPROCS(4)
		runtime.GC()
		runtime.GOMAXPROCS(1)
		challenge, err := p.Challenge()
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		proof, err := p.ProofGen(stored, challenge)
		pg := float64(time.Since(start).Nanoseconds()) / 1e6
		if err != nil {
			t.Fatal(err)
		}
		start = time.Now()
		ok := p.Verify(registry, challenge, proof)
		vr := float64(time.Since(start).Nanoseconds()) / 1e6
		if !ok {
			t.Fatal("audit rejected")
		}
		wire, err := p.MarshalProof(proof)
		if err != nil {
			t.Fatal(err)
		}
		auxiliary := 0
		for _, f := range proof.FileProofs {
			auxiliary += len(f.Auxiliary)
		}
		if repeat > 0 {
			err = w.Write([]string{"690", strconv.Itoa(repeat), fmt.Sprintf("%.9f", pg), fmt.Sprintf("%.9f", vr), strconv.Itoa(len(wire)), strconv.Itoa(auxiliary), "true", fmt.Sprintf("%x", sha256.Sum256(wire))})
			if err != nil {
				t.Fatal(err)
			}
			w.Flush()
			if err := w.Error(); err != nil {
				t.Fatal(err)
			}
		}
	}
	until := time.Now().Add(5 * time.Second)
	for i := 0; i < 3 || time.Now().Before(until); i++ {
		run(0)
	}
	for i := 1; i <= 30; i++ {
		run(i)
	}
	meta := map[string]any{"complete": true, "protocol": ProtocolID, "storage_backend": benchcore.StorageID, "arithmetic_backend": benchcore.ArithmeticID, "goarch": runtime.GOARCH, "goos": runtime.GOOS, "go_version": runtime.Version(), "m": 40, "n": 3907, "s": 80, "c": 690, "repeats": 30, "g1_bytes": 64, "scalar_bytes": 32, "digest_bytes": 32}
	bytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".meta.json", append(bytes, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}
