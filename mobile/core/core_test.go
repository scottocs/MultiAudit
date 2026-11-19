package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestNativeRoundTripsAndRejections(t *testing.T) {
	for _, scheme := range []string{"MultiAudit", "Xu", "Yu"} {
		t.Run(scheme, func(t *testing.T) {
			pub, key, _ := ed25519.GenerateKey(rand.Reader)
			f, err := NewFixture(Config{Scheme: scheme, M: 2, N: 16, S: 5, C: 7})
			if err != nil {
				t.Fatal(err)
			}
			env, err := f.Signed(key)
			if err != nil {
				t.Fatal(err)
			}
			v, err := NewClient(env, hex.EncodeToString(pub))
			if err != nil {
				t.Fatal(err)
			}
			ch, err := v.Challenge()
			if err != nil {
				t.Fatal(err)
			}
			proof, err := f.Prove(ch)
			if err != nil {
				t.Fatal(err)
			}
			valid := *v
			r, err := valid.Verify(proof)
			if err != nil || !r.Accepted {
				t.Fatalf("valid audit rejected: %v %+v", err, r)
			}
			if _, err = valid.Verify(proof); err == nil {
				t.Fatal("unsolicited duplicate response accepted")
			}
			for _, bad := range [][]byte{proof[:len(proof)-1], append(append([]byte{}, proof...), 0), bytes.Repeat([]byte{255}, len(proof))} {
				copy := *v
				r, e := copy.Verify(bad)
				if e == nil && r.Accepted {
					t.Fatal("malformed proof accepted")
				}
			}
			bad := append([]byte{}, proof...)
			bad[len(bad)-1] ^= 1
			copy := *v
			r, err = copy.Verify(bad)
			if err == nil && r.Accepted {
				t.Fatal("tampering accepted")
			}
			if _, err = v.Challenge(); err != nil {
				t.Fatal(err)
			}
			r, err = v.Verify(proof)
			if err == nil && r.Accepted {
				t.Fatal("stale response accepted for new challenge")
			}
			_, wrong, _ := ed25519.GenerateKey(rand.Reader)
			if _, err = NewClient(env, hex.EncodeToString(wrong.Public().(ed25519.PublicKey))); err == nil {
				t.Fatal("wrong owner key accepted")
			}
			corrupt := append([]byte{}, env...)
			corrupt[len(corrupt)/2] ^= 1
			if _, err = NewClient(corrupt, hex.EncodeToString(pub)); err == nil {
				t.Fatal("modified registry accepted")
			}
			if _, err = f.Prove(ch[:len(ch)-1]); err == nil {
				t.Fatal("truncated challenge accepted")
			}
		})
	}
}

func TestOwnerStoreUploadAndPublicVerify(t *testing.T) {
	for _, scheme := range []string{"MultiAudit", "Xu", "Yu"} {
		t.Run(scheme, func(t *testing.T) {
			o, e := NewOwner(Config{Scheme: scheme, M: 2, N: 16, S: 5, C: 7})
			if e != nil {
				t.Fatal(e)
			}
			begin, e := o.Signed()
			if e != nil {
				t.Fatal(e)
			}
			cloud, e := NewUploadFixture(begin, o.PublicKey())
			if e != nil {
				t.Fatal(e)
			}
			for i := 0; i < 2; i++ {
				wire, measure, e := o.StoreFile(i, nil)
				if e != nil {
					t.Fatal(e)
				}
				if measure.StoreMS <= 0 {
					t.Fatal("Store not measured")
				}
				if e = cloud.ImportFile(wire); e != nil {
					t.Fatal(e)
				}
			}
			end, e := o.Signed()
			if e != nil {
				t.Fatal(e)
			}
			if e = cloud.Finalize(end, o.PublicKey()); e != nil {
				t.Fatal(e)
			}
			phone, e := NewClient(end, o.PublicKey())
			if e != nil {
				t.Fatal(e)
			}
			ch, e := phone.Challenge()
			if e != nil {
				t.Fatal(e)
			}
			proof, e := cloud.Prove(ch)
			if e != nil {
				t.Fatal(e)
			}
			result, e := phone.Verify(proof)
			if e != nil || !result.Accepted {
				t.Fatalf("public-only cloud proof rejected: %v", e)
			}
		})
	}
}
