// protocolbench measures complete native multi-file protocol calls in ms.
package main

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"multiaudit/schemes/benchcore"
	"multiaudit/schemes/miaoscis2026"
	"multiaudit/schemes/multiaudit"
	"multiaudit/schemes/xutifs26"
	"multiaudit/schemes/yutc25"
	"multiaudit/schemes/zhangtpds23"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"time"
)

const (
	challengeSize = 690
	baseBMB       = 10
	baseS         = 80
)

type params struct{ M, BMB, S, C int }

func (p params) N() int     { return max(p.C, (p.BMB*1_000_000+32*p.S-1)/(32*p.S)) }
func (p params) Bytes() int { return p.N() * p.S * 32 }
func (p params) native(scheme string) (int, int) {
	if scheme == "MiaoSCIS2026" {
		return p.N() * p.S, 1
	}
	return p.N(), p.S
}

type fixture struct {
	name                     string
	challenge, prove, verify func() bool
	prepMS                   float64
}
type scheme struct {
	name    string
	prepare func(params) fixture
}

var preparationWorkers = 4

var schemes = []scheme{{"ZhangTPDS23", prepareZhang}, {"MiaoSCIS2026", prepareMiao}, {"XuTIFS26", prepareXu}, {"MultiAudit", prepareMultiAudit}, {"YuTC25", prepareYu}}

type samples map[string][]float64

func paperGrid() []params {
	points := make([]params, 0, 4)
	for _, m := range []int{10, 20, 30, 40} {
		points = append(points, params{m, baseBMB, baseS, challengeSize})
	}
	return points
}

func main() {
	out := flag.String("out", "experiments/results/paper/runtime.csv", "measurements CSV")
	repeats := flag.Int("repeats", 30, "fresh audits per fixture")
	warmups := flag.Int("warmups", 3, "minimum warmup audits")
	flag.Parse()
	if *repeats < 1 || *warmups < 0 {
		fatal(fmt.Errorf("invalid repetitions"))
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	f, w := createCSV(*out)
	defer f.Close()
	must(w.Write([]string{"scenario", "variable", "value", "scheme", "phase", "m", "B_MB", "s", "c", "n", "milliseconds", "milliseconds_stddev", "p25_ms", "p75_ms", "repeats", "ok", "native_blocks", "native_sectors", "encoded_bytes_per_file", "challenged_bytes_per_file", "measurement_source"}))
	w.Flush()
	rf, rw := createCSV(*out + ".samples.csv")
	defer rf.Close()
	must(rw.Write([]string{"m", "B_MB", "s", "c", "scheme", "phase", "repeat", "order_position", "milliseconds", "ok", "measurement_source", "gc_cycles_during_phase"}))
	rw.Flush()
	names := make([]string, len(schemes))
	for i, candidate := range schemes {
		names[i] = candidate.name
	}
	meta := map[string]any{
		"profile": "file-count", "B_MB": baseBMB, "s": baseS, "c": challengeSize,
		"n": paperGrid()[0].N(), "m_scan": []int{10, 20, 30, 40}, "schemes": names,
		"binary_sha256": binaryFingerprint(), "multiaudit_protocol": multiaudit.ProtocolID,
		"storage_backend": benchcore.StorageID, "arithmetic_backend": benchcore.ArithmeticID,
		"go_version": runtime.Version(), "goarch": runtime.GOARCH,
		"goos": runtime.GOOS, "online_repeats": *repeats, "warmup_rounds": *warmups,
		"minimum_warmup_seconds": 5, "online_gomaxprocs": 1, "locked_os_thread": true,
		"fixture_preparation_gomaxprocs": 4, "miao_preparation_workers": preparationWorkers,
		"order_seed": 42, "time_unit": "ms", "workload_heap_bytes": map[string]uint64{},
		"gc_policy": "four workers outside timers; one worker in online calls",
	}
	saveJSON(*out+".meta.json", meta)
	rng := rand.New(rand.NewSource(42))
	for _, point := range paperGrid() {
		values := map[string]samples{}
		for pos, index := range rng.Perm(len(schemes)) {
			candidate := schemes[index]
			values[candidate.name] = measureScheme(point, candidate, pos, *repeats, *warmups, rw, meta)
			saveJSON(*out+".meta.json", meta)
		}
		for _, candidate := range schemes {
			for _, phase := range []string{"Store", "ProofGen", "Verify"} {
				writeSummary(w, point, candidate.name, phase, values[candidate.name][phase])
			}
		}
		w.Flush()
		must(w.Error())
	}
	meta["complete"] = true
	saveJSON(*out+".meta.json", meta)
	fmt.Println("wrote", *out)
}

func measureScheme(p params, s scheme, pos, repeats, warmups int, rw *csv.Writer, meta map[string]any) samples {
	runtime.GOMAXPROCS(4)
	debug.FreeOSMemory()
	fmt.Fprintf(os.Stderr, "%s preparing %s m=%d B_MB=%d s=%d bytes/file=%d\n", time.Now().Format(time.RFC3339), s.name, p.M, p.BMB, p.S, p.Bytes())
	fx := s.prepare(p)
	r := samples{}
	r["Store"] = []float64{fx.prepMS}
	writeRaw(rw, p, s.name, "Store", 1, pos, fx.prepMS, "measured", 0)
	debug.FreeOSMemory()
	runtime.GOMAXPROCS(1)
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	meta["workload_heap_bytes"].(map[string]uint64)[storeKey(p, s.name)] = mem.HeapAlloc
	fmt.Fprintf(os.Stderr, "%s measuring %s m=%d B_MB=%d s=%d heap_MB=%.1f\n", time.Now().Format(time.RFC3339), s.name, p.M, p.BMB, p.S, float64(mem.HeapAlloc)/1e6)
	once := func(repeat int) {
		runtime.GOMAXPROCS(4)
		runtime.GC()
		runtime.GOMAXPROCS(1)
		if !fx.challenge() {
			fatal(fmt.Errorf("%s challenge failed", s.name))
		}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		ok := fx.prove()
		pg := float64(time.Since(start).Nanoseconds()) / 1e6
		if !ok {
			fatal(fmt.Errorf("%s proof failed", s.name))
		}
		runtime.ReadMemStats(&after)
		pgGC := after.NumGC - before.NumGC
		before = after
		start = time.Now()
		ok = fx.verify()
		vr := float64(time.Since(start).Nanoseconds()) / 1e6
		if !ok {
			fatal(fmt.Errorf("%s verification failed", s.name))
		}
		runtime.ReadMemStats(&after)
		vrGC := after.NumGC - before.NumGC
		if repeat > 0 {
			r["ProofGen"] = append(r["ProofGen"], pg)
			r["Verify"] = append(r["Verify"], vr)
			writeRaw(rw, p, s.name, "ProofGen", repeat, pos, pg, "measured", pgGC)
			writeRaw(rw, p, s.name, "Verify", repeat, pos, vr, "measured", vrGC)
		}
	}
	warmUntil := time.Now().Add(5 * time.Second)
	for i := 0; i < warmups || time.Now().Before(warmUntil); i++ {
		once(0)
	}
	for i := 1; i <= repeats; i++ {
		once(i)
	}
	rw.Flush()
	must(rw.Error())
	return r
}

func storeKey(p params, name string) string {
	return fmt.Sprintf("%d/%d/%d/%d/%s", p.M, p.BMB, p.S, p.C, name)
}
func writeRaw(w *csv.Writer, p params, name, phase string, repeat, pos int, ms float64, source string, gcCycles uint32) {
	must(w.Write([]string{strconv.Itoa(p.M), strconv.Itoa(p.BMB), strconv.Itoa(p.S), strconv.Itoa(p.C), name, phase, strconv.Itoa(repeat), strconv.Itoa(pos), fmt.Sprintf("%.6f", ms), "true", source, strconv.FormatUint(uint64(gcCycles), 10)}))
}
func writeSummary(w *csv.Writer, p params, name, phase string, v []float64) {
	median, sd := medianStdDev(v)
	dev, q1, q3 := "", "", ""
	if len(v) > 1 {
		dev = fmt.Sprintf("%.6f", sd)
		q1 = fmt.Sprintf("%.6f", quantile(v, .25))
		q3 = fmt.Sprintf("%.6f", quantile(v, .75))
	}
	n, s := p.native(name)
	must(w.Write([]string{"vary_m", "m", strconv.Itoa(p.M), name, phase, strconv.Itoa(p.M), strconv.Itoa(p.BMB), strconv.Itoa(p.S), strconv.Itoa(p.C), strconv.Itoa(p.N()), fmt.Sprintf("%.6f", median), dev, q1, q3, strconv.Itoa(len(v)), "true", strconv.Itoa(n), strconv.Itoa(s), strconv.Itoa(p.Bytes()), strconv.Itoa(p.C * s * 32), "measured"}))
}
func quantile(v []float64, p float64) float64 {
	x := append([]float64(nil), v...)
	sort.Float64s(x)
	at := p * float64(len(x)-1)
	lo := int(at)
	hi := min(lo+1, len(x)-1)
	return x[lo] + (at-float64(lo))*(x[hi]-x[lo])
}
func prepTime(fn func() bool) float64 {
	runtime.GC()
	t := time.Now()
	if !fn() {
		fatal(fmt.Errorf("fixture storage failed"))
	}
	return float64(time.Since(t).Nanoseconds()) / 1e6
}
func prepareXu(p params) fixture {
	protocol := xutifs26.NewProtocol(p.M, p.N(), p.S)
	data := dataset(p.M, p.N(), p.S)
	var stored *xutifs26.StoredBatch
	var chal xutifs26.Challenge
	var proof *xutifs26.Proof
	ms := prepTime(func() bool { var e error; stored, e = protocol.Store(data); return e == nil })
	return fixture{"XuTIFS26", func() bool { chal = protocol.Challenge(p.C); return true }, func() bool { var e error; proof, e = protocol.Prove(stored, chal); return e == nil }, func() bool { return protocol.Verify(stored, chal, proof) }, ms}
}
func prepareZhang(p params) fixture {
	protocol := zhangtpds23.NewProtocol(p.M, p.N(), p.S)
	data := dataset(p.M, p.N(), p.S)
	var stored *zhangtpds23.StoredBatch
	var chal zhangtpds23.Challenge
	var proof *zhangtpds23.Proof
	ms := prepTime(func() bool { var e error; stored, e = protocol.Store(data); return e == nil })
	return fixture{"ZhangTPDS23", func() bool { chal = protocol.Challenge(p.C); return true }, func() bool { var e error; proof, e = protocol.Prove(stored, chal); return e == nil }, func() bool { return protocol.Verify(stored, chal, proof) }, ms}
}
func prepareMiao(p params) fixture {
	n, _ := p.native("MiaoSCIS2026")
	protocol := miaoscis2026.NewProtocol(n)
	data := miaoFiles(p.M, n)
	var stored *miaoscis2026.StoredData
	var chal miaoscis2026.Challenge
	var proof *miaoscis2026.Proof
	ms := prepTime(func() bool {
		var e error
		stored, e = protocol.StoreWithWorkers(data, preparationWorkers)
		return e == nil
	})
	return fixture{"MiaoSCIS2026", func() bool {
		trap, e := protocol.Trapdoor(stored, []string{"audit"})
		if e != nil {
			return false
		}
		chal = protocol.ChallengeWithTrapdoor(trap, p.C, p.M)
		return true
	}, func() bool { var e error; proof, e = protocol.Prove(stored, chal); return e == nil }, func() bool { return protocol.Verify(stored, chal, proof) }, ms}
}
func prepareYu(p params) fixture {
	protocol := yutc25.NewProtocol(p.N(), p.S)
	data := dataset(p.M, p.N(), p.S)
	var stored *yutc25.StoredBatch
	var chal yutc25.BatchChallenge
	var proof *yutc25.BatchProof
	ms := prepTime(func() bool { var e error; stored, e = protocol.StoreBatch(data); return e == nil })
	return fixture{"YuTC25", func() bool { chal = protocol.BatchChallenge(p.M, p.C); return true }, func() bool { var e error; proof, e = protocol.ProveBatch(stored, chal); return e == nil }, func() bool { return protocol.VerifyBatch(stored, chal, proof) }, ms}
}
func prepareMultiAudit(p params) fixture {
	cfg := multiaudit.DefaultConfig()
	cfg.NumFiles = p.M
	cfg.ChunksPerFile = p.N()
	cfg.SectorsPerChunk = p.S
	cfg.ChallengedChunks = p.C
	protocol, e := multiaudit.Setup(cfg, newDeterministicReader(42))
	must(e)
	data := dataset(p.M, p.N(), p.S)
	var stored *multiaudit.StoredBatch
	var chal *multiaudit.Challenge
	var proof *multiaudit.AuditProof
	ms := prepTime(func() bool { var e error; stored, e = protocol.Store(data); return e == nil })
	return fixture{"MultiAudit", func() bool { var e error; chal, e = protocol.Challenge(); return e == nil }, func() bool { var e error; proof, e = protocol.ProofGen(stored, chal); return e == nil }, func() bool { return protocol.Verify(stored, chal, proof) }, ms}
}
func dataset(m, n, s int) [][][]*big.Int {
	out := make([][][]*big.Int, m)
	for i := range out {
		out[i] = make([][]*big.Int, n)
		flat := benchcore.NewStoredScalars(n * s)
		for j := range out[i] {
			out[i][j] = flat[j*s : (j+1)*s : (j+1)*s]
			for k := range out[i][j] {
				out[i][j][k].Set(benchcore.Scalar("equal-byte-file", i*n*s+j*s+k))
			}
		}
	}
	return out
}
func miaoFiles(m, n int) []struct {
	FID      string
	Keywords []string
	Blocks   []*big.Int
} {
	out := make([]struct {
		FID      string
		Keywords []string
		Blocks   []*big.Int
	}, m)
	for i := range out {
		out[i].FID = fmt.Sprintf("file-%d", i)
		out[i].Keywords = []string{"audit", fmt.Sprintf("kw-%d", i%3)}
		out[i].Blocks = benchcore.NewStoredScalars(n)
		for j := range out[i].Blocks {
			out[i].Blocks[j].Set(benchcore.Scalar("equal-byte-file", i*n+j))
		}
	}
	return out
}
func createCSV(path string) (*os.File, *csv.Writer) {
	must(os.MkdirAll(filepath.Dir(path), 0755))
	f, err := os.Create(path)
	must(err)
	return f, csv.NewWriter(f)
}
func medianStdDev(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	med := sorted[mid]
	if len(sorted)%2 == 0 {
		med = (sorted[mid-1] + sorted[mid]) / 2
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))
	if len(values) == 1 {
		return med, 0
	}
	sq := 0.0
	for _, v := range values {
		sq += (v - mean) * (v - mean)
	}
	return med, math.Sqrt(sq / float64(len(values)-1))
}
func saveJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	must(err)
	must(os.WriteFile(path, append(b, '\n'), 0644))
}
func must(err error) {
	if err != nil {
		fatal(err)
	}
}
func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }

type deterministicReader struct{ state uint64 }

func newDeterministicReader(seed uint64) *deterministicReader { return &deterministicReader{seed} }
func (r *deterministicReader) Read(p []byte) (int, error) {
	for i := range p {
		r.state = r.state*6364136223846793005 + 1442695040888963407
		p[i] = byte(r.state >> 56)
	}
	return len(p), nil
}

func binaryFingerprint() string {
	path, e := os.Executable()
	must(e)
	b, e := os.ReadFile(path)
	must(e)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
