package multiaudit

import (
	"bytes"
	"fmt"
	"testing"
)

func TestSequentialOwnerStoreMatchesBatch(t *testing.T) {
	p, e := Setup(Config{NumFiles: 2, ChunksPerFile: 16, SectorsPerChunk: 5, ChallengedChunks: 7}, nil)
	if e != nil {
		t.Fatal(e)
	}
	data, e := p.RandomDataset()
	if e != nil {
		t.Fatal(e)
	}
	batch, e := p.Store(data)
	if e != nil {
		t.Fatal(e)
	}
	for i := range data {
		f, e := p.StoreFile([]byte(fmt.Sprintf("file-%d", i)), data[i])
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(f.Root, batch.Roots[i]) {
			t.Fatal("sequential Store changed the native root")
		}
		imported, e := p.ImportFile(f.FileID, f.Sectors, f.Tags)
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(imported.Root, f.Root) {
			t.Fatal("uploaded file did not reconstruct native tree")
		}
	}
}
