// Package multiaudit implements the protocol described in paper/MultiAudit.tex.
// The code follows the paper notation closely: files are split into chunks,
// each chunk is encoded as a low-degree polynomial. Compact per-file Merkle
// multiproofs authenticate tags; SHPLONK batches openings into two witnesses.
package multiaudit

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"

	"multiaudit/schemes/benchcore"
)

// ProtocolID identifies incompatible protocol and measurement formats.
const ProtocolID = "multiaudit/compact-merkle-shplonk/v1"

type Config struct {
	NumFiles         int
	ChunksPerFile    int
	SectorsPerChunk  int
	ChallengedChunks int
}

func DefaultConfig() Config {
	return Config{
		NumFiles:         4,
		ChunksPerFile:    64,
		SectorsPerChunk:  8,
		ChallengedChunks: 8,
	}
}

func (c Config) Validate() error {
	if c.NumFiles <= 0 {
		return errors.New("num files must be positive")
	}
	if c.ChunksPerFile <= 0 {
		return errors.New("chunks per file must be positive")
	}
	if c.SectorsPerChunk < 2 {
		return errors.New("sectors per chunk must be at least two")
	}
	if c.ChallengedChunks <= 0 || c.ChallengedChunks > c.ChunksPerFile {
		return errors.New("challenged chunks must be in [1, chunks per file]")
	}
	return nil
}

type PublicParams struct {
	SRSG1 []*bn256.G1
	G2    *bn256.G2
	TauG2 *bn256.G2
}

type Protocol struct {
	Config Config
	PP     PublicParams

	tau  *big.Int
	rand io.Reader
}

func Setup(config Config, reader io.Reader) (*Protocol, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if reader == nil {
		reader = rand.Reader
	}

	tau, err := benchcore.RandomScalar(reader, true)
	if err != nil {
		return nil, err
	}

	srs := make([]*bn256.G1, config.SectorsPerChunk)
	power := benchcore.One()
	for i := range srs {
		// Public KZG SRS element g^{tau^i}; tau itself is kept only to model the data owner.
		srs[i] = benchcore.G1Base(power)
		power = benchcore.Mul(power, tau)
	}

	return &Protocol{
		Config: config,
		PP: PublicParams{
			SRSG1: srs,
			G2:    benchcore.G2Base(benchcore.One()),
			TauG2: benchcore.G2Base(tau),
		},
		tau:  benchcore.Normalize(tau),
		rand: reader,
	}, nil
}

type StoredFile struct {
	FileID []byte
	// Sectors and Polynomials are read-only views of the same owned values.
	Sectors     [][]*big.Int
	Polynomials []benchcore.Poly
	Tags        []*bn256.G1
	Tree        *compactTree
	Version     uint64
	Root        []byte
}

type StoredBatch struct {
	SRSID []byte
	Files []StoredFile
	Roots [][]byte
}

type Challenge struct {
	Indices          []int
	Coefficients     [][]*big.Int
	EvaluationPoints []*big.Int
	Nonce            []byte
}

type SchnorrProof struct {
	A *bn256.G1
	Z *big.Int
}

// Tags follow Challenge.Indices; auxiliary positions are reconstructed, never sent.
type FileProof struct {
	Tags      []*bn256.G1
	Auxiliary [][]byte
	YTilde    *big.Int
	R         *bn256.G1
}
type AuditProof struct {
	FileProofs []FileProof
	PiR        []SchnorrProof
	CQ, CW     *bn256.G1
}

func (p *Protocol) RandomDataset() ([][][]*big.Int, error) {
	data := make([][][]*big.Int, p.Config.NumFiles)
	for i := range data {
		data[i] = make([][]*big.Int, p.Config.ChunksPerFile)
		for j := range data[i] {
			data[i][j] = make([]*big.Int, p.Config.SectorsPerChunk)
			for k := range data[i][j] {
				x, err := benchcore.RandomScalar(p.rand, false)
				if err != nil {
					return nil, err
				}
				data[i][j][k] = x
			}
		}
	}
	return data, nil
}

func (p *Protocol) Store(dataset [][][]*big.Int) (*StoredBatch, error) {
	if len(dataset) != p.Config.NumFiles {
		return nil, fmt.Errorf("expected %d files, got %d", p.Config.NumFiles, len(dataset))
	}

	files := make([]StoredFile, len(dataset))
	roots := make([][]byte, len(dataset))
	for i, chunks := range dataset {
		if len(chunks) != p.Config.ChunksPerFile {
			return nil, fmt.Errorf("file %d: expected %d chunks, got %d", i, p.Config.ChunksPerFile, len(chunks))
		}

		for j, chunk := range chunks {
			if len(chunk) != p.Config.SectorsPerChunk {
				return nil, fmt.Errorf("file %d chunk %d: expected %d sectors", i, j, p.Config.SectorsPerChunk)
			}
			for _, value := range chunk {
				if !canonicalScalar(value) {
					return nil, errors.New("noncanonical stored sector")
				}
			}
		}
		fileID := []byte(fmt.Sprintf("file-%d", i))
		sectors := benchcore.CloneStoredMatrix(chunks)
		polys := make([]benchcore.Poly, len(chunks))
		tags := make([]*bn256.G1, len(chunks))
		leaves := make([][]byte, len(chunks))
		for j := range chunks {
			polys[j] = benchcore.StoredPolynomialView(sectors[j])
			// Store computes the chunk tag sigma_{i,j}=g^{f_{i,j}(tau)}.
			tags[j] = p.ownerCommitPolynomial(polys[j])
			// The leaf binds file identity, chunk position, and tag to prevent tag reuse.
			leaves[j] = merkleLeaf(fileID, j, tags[j])
		}

		tree, err := newCompactTree(fileID, leaves)
		if err != nil {
			return nil, err
		}
		files[i] = StoredFile{
			FileID:      benchcore.CloneBytes(fileID),
			Version:     1,
			Sectors:     sectors,
			Polynomials: polys,
			Tags:        tags,
			Tree:        tree,
			Root:        benchcore.CloneBytes(tree.Root),
		}
		roots[i] = benchcore.CloneBytes(tree.Root)
	}

	return &StoredBatch{Files: files, Roots: roots, SRSID: p.srsIdentifier()}, nil
}

func (p *Protocol) Challenge() (*Challenge, error) {
	if err := p.Config.Validate(); err != nil {
		return nil, err
	}
	indices, err := p.sampleIndices()
	if err != nil {
		return nil, err
	}

	coefficients := make([][]*big.Int, p.Config.NumFiles)
	for i := range coefficients {
		coefficients[i] = make([]*big.Int, len(indices))
		for j := range indices {
			// Coefficients are sampled independently per file to avoid coupled aggregates.
			coefficients[i][j], err = benchcore.RandomScalar(p.rand, false)
			if err != nil {
				return nil, err
			}
		}
	}

	points := make([]*big.Int, p.Config.NumFiles)
	seen := make(map[string]bool)
	for i := range points {
		for {
			points[i], err = benchcore.RandomScalar(p.rand, false)
			if err != nil {
				return nil, err
			}
			key := string(benchcore.ScalarBytes(points[i]))
			if !seen[key] {
				seen[key] = true
				break
			}
		}
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(p.rand, nonce); err != nil {
		return nil, err
	}

	return &Challenge{
		Indices:          indices,
		Coefficients:     coefficients,
		EvaluationPoints: points,
		Nonce:            nonce,
	}, nil
}

func (p *Protocol) ProofGen(stored *StoredBatch, chal *Challenge) (*AuditProof, error) {
	if err := p.validateStoredBatch(stored); err != nil {
		return nil, err
	}
	if err := p.validateChallenge(chal); err != nil {
		return nil, err
	}
	proof := &AuditProof{FileProofs: make([]FileProof, p.Config.NumFiles)}
	masks := make([]*big.Int, p.Config.NumFiles)
	quotients := make([]benchcore.Poly, p.Config.NumFiles)
	for i, file := range stored.Files {
		f, err := p.aggregatePolynomial(file, chal, i)
		if err != nil {
			return nil, err
		}
		q, y := f.DivLinear(chal.EvaluationPoints[i])
		mu, err := benchcore.RandomScalar(p.rand, false)
		if err != nil {
			return nil, err
		}
		masks[i] = mu
		quotients[i] = q
		aux, err := file.Tree.proof(chal.Indices)
		if err != nil {
			return nil, err
		}
		tags := make([]*bn256.G1, len(chal.Indices))
		for j, index := range chal.Indices {
			tags[j] = cloneG1(file.Tags[index])
		}
		proof.FileProofs[i] = FileProof{Tags: tags, Auxiliary: aux, YTilde: benchcore.Add(y, mu), R: benchcore.G1Base(mu)}
	}
	T := p.baseTranscript(stored, chal, proof.FileProofs)
	p.commitQuotients(T, chal, proof, quotients)
	var err error
	proof.PiR, err = p.schnorrMaskProofs(T, proof, masks)
	return proof, err
}

// Aggregate coefficients before the only two public-SRS commitments.
func (p *Protocol) commitQuotients(T []byte, chal *Challenge, proof *AuditProof, qs []benchcore.Poly) {
	gamma := hashToField("multiaudit:gamma", func(x *big.Int) bool { return x.Sign() != 0 }, T)
	weights := make([]*big.Int, len(qs))
	power := benchcore.One()
	for i := range qs {
		weights[i] = power
		power = benchcore.Mul(power, gamma)
	}
	Q := benchcore.LinearCombination(qs, weights)
	proof.CQ = p.CommitPolynomial(Q)
	_, betas := openingWeights(T, proof.CQ, chal.EvaluationPoints)
	W := benchcore.LinearCombination(qs, betas)
	proof.CW = p.CommitPolynomial(W)
}

func (p *Protocol) Verify(stored *StoredBatch, chal *Challenge, proof *AuditProof) bool {
	if p.validateRegistry(stored) != nil || p.validateChallenge(chal) != nil || proof == nil {
		return false
	}
	if len(proof.FileProofs) != p.Config.NumFiles || len(proof.PiR) != p.Config.NumFiles || !validG1(proof.CQ) || !validG1(proof.CW) {
		return false
	}
	for i, fp := range proof.FileProofs {
		if !canonicalScalar(fp.YTilde) || !validG1(fp.R) || len(fp.Tags) != len(chal.Indices) {
			return false
		}
		leaves := make([][]byte, len(fp.Tags))
		for j, tag := range fp.Tags {
			if !validG1(tag) {
				return false
			}
			leaves[j] = merkleLeaf(stored.Files[i].FileID, chal.Indices[j], tag)
		}
		if !verifyCompact(leaves, stored.Roots[i], chal.Indices, p.Config.ChunksPerFile, fp.Auxiliary) {
			return false
		}
	}
	T := p.baseTranscript(stored, chal, proof.FileProofs)
	if !p.verifySchnorrMaskProofs(T, proof) {
		return false
	}
	z, betas := openingWeights(T, proof.CQ, chal.EvaluationPoints)
	points := make([]*bn256.G1, 0, p.Config.NumFiles*(p.Config.ChallengedChunks+1)+2)
	scalars := make([]*big.Int, 0, cap(points))
	value := benchcore.Zero()
	for i, fp := range proof.FileProofs {
		for j, tag := range fp.Tags {
			points = append(points, tag)
			scalars = append(scalars, benchcore.Mul(betas[i], chal.Coefficients[i][j]))
		}
		points = append(points, fp.R)
		scalars = append(scalars, betas[i])
		value = benchcore.Add(value, benchcore.Mul(betas[i], fp.YTilde))
	}
	points = append(points, p.PP.SRSG1[0], proof.CW)
	scalars = append(scalars, benchcore.Neg(value), z)
	left := benchcore.G1Add(benchcore.G1MultiExp(points, scalars), benchcore.G1Neg(proof.CQ))
	return benchcore.PairingEqual(left, p.PP.G2, proof.CW, p.PP.TauG2)
}

func (p *Protocol) CommitPolynomial(poly benchcore.Poly) *bn256.G1 {
	return benchcore.CommitG1(p.PP.SRSG1, poly)
}

func (p *Protocol) ownerCommitPolynomial(poly benchcore.Poly) *bn256.G1 {
	if p.tau == nil {
		panic("multiaudit: missing data-owner trapdoor for Store")
	}
	return benchcore.G1Base(poly.Eval(p.tau))
}

func (p *Protocol) sampleIndices() ([]int, error) {
	return benchcore.RandomUniqueIndices(p.rand, p.Config.ChallengedChunks, p.Config.ChunksPerFile)
}

func (p *Protocol) aggregatePolynomial(file StoredFile, chal *Challenge, fileIndex int) (benchcore.Poly, error) {
	sum := benchcore.NewPolynomialAccumulator(p.Config.SectorsPerChunk)
	for pos, chunkIndex := range chal.Indices {
		if chunkIndex < 0 || chunkIndex >= len(file.Polynomials) {
			return benchcore.Poly{}, fmt.Errorf("challenge index %d out of range", chunkIndex)
		}
		poly := file.Polynomials[chunkIndex]
		if len(poly.Coeffs) > p.Config.SectorsPerChunk {
			return benchcore.Poly{}, errors.New("chunk polynomial exceeds configured degree")
		}
		sum.AddScaled(poly, chal.Coefficients[fileIndex][pos])
	}
	return sum.Polynomial(), nil
}

func (p *Protocol) schnorrMaskProofs(T []byte, proof *AuditProof, masks []*big.Int) ([]SchnorrProof, error) {
	proofs := make([]SchnorrProof, len(proof.FileProofs))
	for i, fp := range proof.FileProofs {
		t, err := benchcore.RandomScalar(p.rand, false)
		if err != nil {
			return nil, err
		}
		A := benchcore.G1Base(t)
		chi := maskChallenge(T, proof, i, fp.R, A)
		proofs[i] = SchnorrProof{A: A, Z: benchcore.Add(t, benchcore.Mul(chi, masks[i]))}
	}
	return proofs, nil
}
func (p *Protocol) verifySchnorrMaskProofs(T []byte, proof *AuditProof) bool {
	for i, pi := range proof.PiR {
		if !validG1(pi.A) || !canonicalScalar(pi.Z) {
			return false
		}
		chi := maskChallenge(T, proof, i, proof.FileProofs[i].R, pi.A)
		if !benchcore.G1Eq(benchcore.G1Base(pi.Z), benchcore.G1Add(pi.A, benchcore.G1Mul(proof.FileProofs[i].R, chi))) {
			return false
		}
	}
	return true
}
func canonicalScalar(x *big.Int) bool { return x != nil && x.Sign() >= 0 && x.Cmp(benchcore.Order) < 0 }
func validG1(x *bn256.G1) bool {
	if x == nil {
		return false
	}
	raw := x.Marshal()
	rest, err := new(bn256.G1).Unmarshal(raw)
	return err == nil && len(rest) == 0
}

// Verification needs only the trusted registry, not server data, tags, or trees.
func (p *Protocol) validateRegistry(stored *StoredBatch) error {
	if stored == nil || !bytes.Equal(stored.SRSID, p.srsIdentifier()) || len(stored.Files) != p.Config.NumFiles || len(stored.Roots) != p.Config.NumFiles {
		return errors.New("registry dimension mismatch")
	}
	seen := make(map[string]bool)
	for i, f := range stored.Files {
		if len(f.FileID) == 0 || seen[string(f.FileID)] || f.Version == 0 || len(stored.Roots[i]) != 32 || !bytes.Equal(f.Root, stored.Roots[i]) {
			return errors.New("invalid file registry")
		}
		seen[string(f.FileID)] = true
	}
	return nil
}

func (p *Protocol) validateStoredBatch(stored *StoredBatch) error {
	if err := p.validateRegistry(stored); err != nil {
		return err
	}
	for i, file := range stored.Files {
		if len(file.Polynomials) != p.Config.ChunksPerFile || len(file.Tags) != p.Config.ChunksPerFile {
			return fmt.Errorf("file %d chunk metadata mismatch", i)
		}
		if file.Tree == nil {
			return fmt.Errorf("file %d merkle tree is nil", i)
		}
	}
	return nil
}

func (p *Protocol) validateChallenge(chal *Challenge) error {
	if err := p.Config.Validate(); err != nil {
		return err
	}
	if chal == nil {
		return errors.New("challenge is nil")
	}
	if len(chal.Indices) != p.Config.ChallengedChunks {
		return errors.New("challenge index count mismatch")
	}
	if len(chal.Coefficients) != p.Config.NumFiles || len(chal.EvaluationPoints) != p.Config.NumFiles {
		return errors.New("challenge file dimension mismatch")
	}
	last := -1
	for _, index := range chal.Indices {
		if index <= last || index < 0 || index >= p.Config.ChunksPerFile {
			return fmt.Errorf("invalid challenge index %d", index)
		}
		last = index
	}
	if len(chal.Nonce) != 32 {
		return errors.New("invalid nonce length")
	}
	seen := make(map[string]bool)
	for _, r := range chal.EvaluationPoints {
		if !canonicalScalar(r) {
			return errors.New("invalid evaluation point")
		}
		key := string(benchcore.ScalarBytes(r))
		if seen[key] {
			return errors.New("repeated evaluation point")
		}
		seen[key] = true
	}
	for i := range chal.Coefficients {
		for _, v := range chal.Coefficients[i] {
			if !canonicalScalar(v) {
				return errors.New("invalid coefficient")
			}
		}
		if len(chal.Coefficients[i]) != len(chal.Indices) {
			return fmt.Errorf("challenge coefficient count mismatch for file %d", i)
		}
	}
	return nil
}

func merkleLeaf(fileID []byte, index int, tag *bn256.G1) []byte {
	return benchcore.HashBytes("multiaudit:merkle:leaf", fileID, benchcore.IntBytes(index+1), g1Bytes(tag))
}

func cloneG1(point *bn256.G1) *bn256.G1 {
	if point == nil {
		return nil
	}
	return new(bn256.G1).Set(point)
}

func g1Bytes(point *bn256.G1) []byte {
	if point == nil {
		return nil
	}
	return point.Marshal()
}
