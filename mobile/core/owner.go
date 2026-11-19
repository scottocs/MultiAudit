package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	bn "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"multiaudit/schemes/benchcore"
	"multiaudit/schemes/multiaudit"
	"multiaudit/schemes/xutifs26"
	"multiaudit/schemes/yutc25"
)

type Owner struct {
	Manifest Manifest
	key      ed25519.PrivateKey
	ready    []bool
	f        *multiaudit.Protocol
	x        *xutifs26.Protocol
	y        *yutc25.Protocol
}

func NewOwner(c Config) (*Owner, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	o := &Owner{Manifest: Manifest{Config: c, Roots: make([][]byte, c.M), IDs: make([][]byte, c.M), Versions: make([]uint64, c.M)}, key: key, ready: make([]bool, c.M)}
	for i := 0; i < c.M; i++ {
		o.Manifest.Roots[i] = make([]byte, 32)
		o.Manifest.IDs[i] = []byte(fmt.Sprintf("file-%d", i))
		o.Manifest.Versions[i] = 1
	}
	switch c.Scheme {
	case "MultiAudit":
		o.f, err = multiaudit.Setup(multiaudit.Config{NumFiles: c.M, ChunksPerFile: c.N, SectorsPerChunk: c.S, ChallengedChunks: c.C}, rand.Reader)
		if err != nil {
			return nil, err
		}
		o.Manifest.G2 = o.f.PP.G2.Marshal()
		o.Manifest.TauG2 = o.f.PP.TauG2.Marshal()
		parts := [][]byte{o.Manifest.G2, o.Manifest.TauG2}
		for _, p := range o.f.PP.SRSG1 {
			b := p.Marshal()
			o.Manifest.SRS = append(o.Manifest.SRS, b)
			parts = append(parts, b)
		}
		o.Manifest.SRSID = benchcore.HashBytes("multiaudit:srs", parts...)
	case "Xu":
		o.x, err = xutifs26.NewOwnerProtocol(c.M, c.N, c.S)
		if err != nil {
			return nil, err
		}
		o.Manifest.G2 = o.x.G2.Marshal()
		o.Manifest.TauG2 = o.x.AlphaG2.Marshal()
		for _, p := range o.x.SRSG1 {
			o.Manifest.SRS = append(o.Manifest.SRS, p.Marshal())
		}
	case "Yu":
		o.y, err = yutc25.NewOwnerProtocol(c.N, c.S)
		if err != nil {
			return nil, err
		}
		for _, p := range o.y.SRS {
			o.Manifest.SRS = append(o.Manifest.SRS, p.Marshal())
		}
	}
	return o, nil
}

func (o *Owner) PublicKey() string       { return hex.EncodeToString(o.key.Public().(ed25519.PublicKey)) }
func (o *Owner) Signed() ([]byte, error) { return SignManifest(o.Manifest, o.key) }
func (o *Owner) Complete() bool {
	for _, ok := range o.ready {
		if !ok {
			return false
		}
	}
	return true
}

type StoreMeasurement struct {
	DataMS           float64 `json:"data_ms"`
	StoreMS          float64 `json:"store_ms"`
	EncodeMS         float64 `json:"encode_ms"`
	EncodedDataBytes int     `json:"encoded_data_bytes"`
	UploadBytes      int     `json:"upload_bytes"`
	Root             string  `json:"root"`
}

// A nil payload generates the same canonical synthetic sector values for every
// scheme. Real file bytes use reversible 31-byte sectors, with zero padding.
func (o *Owner) StoreFile(index int, payload []byte) ([]byte, StoreMeasurement, error) {
	c := o.Manifest.Config
	var result StoreMeasurement
	if index < 0 || index >= c.M || o.ready[index] {
		return nil, result, errors.New("invalid or already stored file index")
	}
	if len(payload) > c.N*c.S*31 {
		return nil, result, errors.New("file exceeds configured capacity")
	}
	start := time.Now()
	flat := benchcore.NewStoredScalars(c.N * c.S)
	rows := make([][]*big.Int, c.N)
	for j := 0; j < c.N; j++ {
		rows[j] = flat[j*c.S : (j+1)*c.S : (j+1)*c.S]
		for k := 0; k < c.S; k++ {
			pos := j*c.S + k
			if payload == nil {
				flat[pos].Set(benchcore.Scalar("mobile/equal-byte-file", index*c.N*c.S+pos))
			} else {
				a := pos * 31
				if a < len(payload) {
					b := a + 31
					if b > len(payload) {
						b = len(payload)
					}
					flat[pos].SetBytes(payload[a:b])
				}
			}
		}
	}
	result.DataMS = float64(time.Since(start).Nanoseconds()) / 1e6
	start = time.Now()
	var tags []*bn.G1
	var root []byte
	switch c.Scheme {
	case "MultiAudit":
		file, e := o.f.StoreFile(o.Manifest.IDs[index], rows)
		if e != nil {
			return nil, result, e
		}
		tags = file.Tags
		root = file.Root
	case "Xu":
		single := *o.x
		single.M = 1
		st, e := single.Store([][][]*big.Int{rows})
		if e != nil {
			return nil, result, e
		}
		tags = st.Files[0].Tags
		root = st.Roots[0]
	case "Yu":
		st, e := o.y.Store(rows)
		if e != nil {
			return nil, result, e
		}
		tags = st.Tags
		root = st.Root
	}
	result.StoreMS = float64(time.Since(start).Nanoseconds()) / 1e6
	start = time.Now()
	var b bytes.Buffer
	b.Grow(4 + c.N*c.S*32 + c.N*64 + 32)
	binary.Write(&b, binary.BigEndian, uint32(index))
	for _, x := range flat {
		putScalar(&b, x)
	}
	for _, tag := range tags {
		b.Write(tag.Marshal())
	}
	b.Write(root)
	o.Manifest.Roots[index] = root
	o.ready[index] = true
	result.EncodeMS = float64(time.Since(start).Nanoseconds()) / 1e6
	result.EncodedDataBytes = c.N * c.S * 32
	result.UploadBytes = b.Len()
	result.Root = hex.EncodeToString(root)
	return b.Bytes(), result, nil
}

func NewUploadFixture(envelope []byte, ownerKey string) (*Fixture, error) {
	v, err := NewClient(envelope, ownerKey)
	if err != nil {
		return nil, err
	}
	f := &Fixture{Manifest: v.Manifest, f: v.f, fs: v.fs, x: v.x, xs: v.xs, y: v.y, ys: v.ys}
	return f, nil
}

func (f *Fixture) ImportFile(wire []byte) error {
	c := f.Manifest.Config
	if len(wire) != 4+c.N*c.S*32+c.N*64+32 {
		return errors.New("invalid upload length")
	}
	r := bytes.NewReader(wire)
	var index uint32
	binary.Read(r, binary.BigEndian, &index)
	i := int(index)
	if i >= c.M {
		return errors.New("invalid upload index")
	}
	flat := benchcore.NewStoredScalars(c.N * c.S)
	rows := make([][]*big.Int, c.N)
	for j := 0; j < c.N; j++ {
		rows[j] = flat[j*c.S : (j+1)*c.S : (j+1)*c.S]
		for k := 0; k < c.S; k++ {
			x, e := scalar(r)
			if e != nil {
				return e
			}
			rows[j][k].Set(x)
		}
	}
	tags := make([]*bn.G1, c.N)
	for j := range tags {
		b, _ := readN(r, 64)
		p, e := point(b)
		if e != nil {
			return e
		}
		tags[j] = p
	}
	claimed, _ := readN(r, 32)
	var root []byte
	switch c.Scheme {
	case "MultiAudit":
		file, e := f.f.ImportFile(f.Manifest.IDs[i], rows, tags)
		if e != nil {
			return e
		}
		f.fs.Files[i] = file
		f.fs.Roots[i] = file.Root
		root = file.Root
	case "Xu":
		leaves := make([][]byte, c.N)
		polys := make([]benchcore.Poly, c.N)
		for j, tag := range tags {
			leaves[j] = benchcore.HashBytes("xutifs26:leaf", tag.Marshal())
			polys[j] = benchcore.StoredPolynomialView(rows[j])
		}
		tree, e := benchcore.NewMerkleTree(leaves)
		if e != nil {
			return e
		}
		f.xs.Files[i] = xutifs26.StoredFile{FileID: f.Manifest.IDs[i], Blocks: polys, Tags: tags, Tree: tree, Root: tree.Root}
		f.xs.Roots[i] = tree.Root
		root = tree.Root
	case "Yu":
		leaves := make([][]byte, c.N)
		polys := make([]benchcore.Poly, c.N)
		for j, tag := range tags {
			leaves[j] = benchcore.HashBytes("yutc25:tag-imht", tag.Marshal())
			polys[j] = benchcore.StoredPolynomialView(rows[j])
		}
		tree, e := benchcore.NewMerkleTree(leaves)
		if e != nil {
			return e
		}
		f.ys.Files[i] = &yutc25.StoredData{Blocks: polys, Tags: tags, Tree: tree, Root: tree.Root}
		f.ys.Roots[i] = tree.Root
		root = tree.Root
	}
	if !bytes.Equal(root, claimed) {
		return errors.New("uploaded root mismatch")
	}
	f.Manifest.Roots[i] = root
	return nil
}

func (f *Fixture) Finalize(envelope []byte, key string) error {
	v, err := NewClient(envelope, key)
	if err != nil {
		return err
	}
	a, _ := json.Marshal(f.Manifest)
	b, _ := json.Marshal(v.Manifest)
	if !bytes.Equal(a, b) {
		return errors.New("final signed registry does not match uploaded files")
	}
	return nil
}
