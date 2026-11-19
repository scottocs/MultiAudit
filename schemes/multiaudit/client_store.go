package multiaudit

import (
	"errors"
	"math/big"

	bn "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"multiaudit/schemes/benchcore"
)

// StoreFile executes the native Store steps for one independently named file.
// It lets an owner upload files sequentially without retaining a whole batch.
func (p *Protocol) StoreFile(id []byte, chunks [][]*big.Int) (StoredFile, error) {
	if p.tau == nil || len(id) == 0 || len(chunks) != p.Config.ChunksPerFile {
		return StoredFile{}, errors.New("invalid owner Store input")
	}
	for _, row := range chunks {
		if len(row) != p.Config.SectorsPerChunk {
			return StoredFile{}, errors.New("invalid sector count")
		}
		for _, x := range row {
			if !canonicalScalar(x) {
				return StoredFile{}, errors.New("invalid sector")
			}
		}
	}
	values := benchcore.CloneStoredMatrix(chunks)
	polys := make([]benchcore.Poly, len(values))
	tags := make([]*bn.G1, len(values))
	for j := range values {
		polys[j] = benchcore.StoredPolynomialView(values[j])
		tags[j] = p.ownerCommitPolynomial(polys[j])
	}
	return p.fileFromOwnedValues(id, values, polys, tags)
}

// ImportFile reconstructs the cloud-side data/tree representation from the
// owner's uploaded sectors and tags. It does not compute replacement tags.
func (p *Protocol) ImportFile(id []byte, chunks [][]*big.Int, tags []*bn.G1) (StoredFile, error) {
	if len(id) == 0 || len(chunks) != p.Config.ChunksPerFile || len(tags) != len(chunks) {
		return StoredFile{}, errors.New("invalid uploaded file")
	}
	for _, row := range chunks {
		if len(row) != p.Config.SectorsPerChunk {
			return StoredFile{}, errors.New("invalid sector count")
		}
		for _, x := range row {
			if !canonicalScalar(x) {
				return StoredFile{}, errors.New("invalid sector")
			}
		}
	}
	for _, tag := range tags {
		if !validG1(tag) {
			return StoredFile{}, errors.New("invalid tag")
		}
	}
	values := benchcore.CloneStoredMatrix(chunks)
	polys := make([]benchcore.Poly, len(values))
	ownedTags := make([]*bn.G1, len(tags))
	for j := range values {
		polys[j] = benchcore.StoredPolynomialView(values[j])
		ownedTags[j] = cloneG1(tags[j])
	}
	return p.fileFromOwnedValues(id, values, polys, ownedTags)
}

func (p *Protocol) fileFromOwnedValues(id []byte, values [][]*big.Int, polys []benchcore.Poly, tags []*bn.G1) (StoredFile, error) {
	leaves := make([][]byte, len(tags))
	for j, tag := range tags {
		leaves[j] = merkleLeaf(id, j, tag)
	}
	tree, err := newCompactTree(id, leaves)
	if err != nil {
		return StoredFile{}, err
	}
	return StoredFile{FileID: benchcore.CloneBytes(id), Version: 1, Sectors: values, Polynomials: polys, Tags: tags, Tree: tree, Root: benchcore.CloneBytes(tree.Root)}, nil
}
