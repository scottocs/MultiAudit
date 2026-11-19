package multiaudit

import (
	"bytes"
	"errors"
	"math/big"
	"multiaudit/schemes/benchcore"
)

// AddFile is an owner-side registry operation. Existing files' tags and roots
// are reused unchanged. Callers authenticate the returned registry before audit.
// Like Store/Challenge, registry mutation is not safe for concurrent use.
func (p *Protocol) AddFile(stored *StoredBatch, id []byte, version uint64, chunks [][]*big.Int) (*StoredBatch, error) {
	if err := p.validateRegistry(stored); err != nil {
		return nil, err
	}
	if len(id) == 0 || version == 0 || p.tau == nil {
		return nil, errors.New("invalid owner/file metadata")
	}
	for _, f := range stored.Files {
		if bytes.Equal(f.FileID, id) {
			return nil, errors.New("file already registered")
		}
	}
	owner := *p
	owner.Config.NumFiles = 1
	one, err := owner.Store([][][]*big.Int{chunks})
	if err != nil {
		return nil, err
	}
	f := one.Files[0]
	f.FileID = benchcore.CloneBytes(id)
	f.Version = version
	leaves := make([][]byte, len(f.Tags))
	for j, tag := range f.Tags {
		leaves[j] = merkleLeaf(id, j, tag)
	}
	f.Tree, err = newCompactTree(id, leaves)
	if err != nil {
		return nil, err
	}
	f.Root = benchcore.CloneBytes(f.Tree.Root)
	out := &StoredBatch{SRSID: benchcore.CloneBytes(stored.SRSID), Files: append(append([]StoredFile(nil), stored.Files...), f), Roots: append(append([][]byte(nil), stored.Roots...), benchcore.CloneBytes(f.Root))}
	p.Config.NumFiles++
	return out, nil
}

// RemoveFile changes the active audit set; it does not attest physical erasure.
// An empty registry is allowed, but auditing requires at least one active file.
func (p *Protocol) RemoveFile(stored *StoredBatch, id []byte) (*StoredBatch, error) {
	if err := p.validateRegistry(stored); err != nil {
		return nil, err
	}
	index := -1
	for i, f := range stored.Files {
		if bytes.Equal(f.FileID, id) {
			index = i
			break
		}
	}
	if index < 0 {
		return nil, errors.New("unknown file")
	}
	out := &StoredBatch{SRSID: benchcore.CloneBytes(stored.SRSID), Files: make([]StoredFile, 0, len(stored.Files)-1), Roots: make([][]byte, 0, len(stored.Roots)-1)}
	for i, f := range stored.Files {
		if i != index {
			out.Files = append(out.Files, f)
			out.Roots = append(out.Roots, stored.Roots[i])
		}
	}
	p.Config.NumFiles--
	return out, nil
}

// Registry returns an independent metadata-only snapshot for the verifier.
// The owner must transmit/authenticate it through its trusted metadata channel.
func (stored *StoredBatch) Registry() *StoredBatch {
	if stored == nil {
		return nil
	}
	out := &StoredBatch{SRSID: benchcore.CloneBytes(stored.SRSID), Files: make([]StoredFile, len(stored.Files)), Roots: make([][]byte, len(stored.Roots))}
	for i, f := range stored.Files {
		out.Files[i] = StoredFile{FileID: benchcore.CloneBytes(f.FileID), Version: f.Version, Root: benchcore.CloneBytes(f.Root)}
	}
	for i, r := range stored.Roots {
		out.Roots[i] = benchcore.CloneBytes(r)
	}
	return out
}
