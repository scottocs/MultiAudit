package main

import "testing"

func TestEqualByteLayouts(t *testing.T) {
	for _, p := range paperGrid() {
		for _, s := range schemes {
			n, sectors := p.native(s.name)
			if n*sectors*32 != p.Bytes() {
				t.Fatalf("%s byte count differs", s.name)
			}
			if n < p.C {
				t.Fatal("challenge exceeds native block count")
			}
		}
	}
	p := params{2, 0, 3, 2}
	d := dataset(p.M, p.N(), p.S)
	m := miaoFiles(p.M, p.N()*p.S)
	for i := range d {
		for j := range d[i] {
			for k := range d[i][j] {
				if d[i][j][k].Cmp(m[i].Blocks[j*p.S+k]) != 0 {
					t.Fatal("reshaping changes file contents")
				}
			}
		}
	}
}
func TestMedianStdDev(t *testing.T) {
	m, s := medianStdDev([]float64{3, 1, 2})
	if m != 2 || s != 1 {
		t.Fatalf("got %g %g", m, s)
	}
}

func TestPaperGrid(t *testing.T) {
	points := paperGrid()
	if len(points) != 4 || len(schemes) != 5 {
		t.Fatal("incomplete experiment")
	}
	for i, p := range points {
		if p.M != (i+1)*10 || p.BMB != 10 || p.S != 80 || p.C != 690 || p.N() != 3907 {
			t.Fatalf("unexpected experiment point: %+v", p)
		}
	}
}
