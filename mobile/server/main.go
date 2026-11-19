// The server stores owner-uploaded data/tags and runs native ProofGen.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"multiaudit/mobile/core"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

func main() {
	addr := flag.String("listen", ":8788", "experiment listener")
	dir := flag.String("out", "/private/tmp/multiaudit-mobile-owner-server", "experiment account token")
	flag.Parse()
	if err := os.MkdirAll(*dir, 0700); err != nil {
		log.Fatal(err)
	}
	token := make([]byte, 32)
	if _, e := rand.Read(token); e != nil {
		log.Fatal(e)
	}
	account := hex.EncodeToString(token)
	if e := os.WriteFile(filepath.Join(*dir, "account-token.txt"), []byte(account), 0600); e != nil {
		log.Fatal(e)
	}
	var mu sync.Mutex
	var fixture *core.Fixture
	var envelope []byte
	var ownerKey string
	var ready []bool
	var finalized bool
	authorized := func(w http.ResponseWriter, r *http.Request) bool {
		if !bytes.Equal([]byte(r.Header.Get("Authorization")), []byte("Bearer "+account)) {
			http.Error(w, "account authorization required", 401)
			return false
		}
		return true
	}
	read := func(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
		return io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/owner/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}
		if !authorized(w, r) {
			return
		}
		body, e := read(w, r, 1<<20)
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		key := r.Header.Get("X-Owner-Key")
		candidate, e := core.NewUploadFixture(body, key)
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		fixture = nil
		runtime.GC()
		fixture = candidate
		envelope = nil
		ownerKey = key
		ready = make([]bool, fixture.Manifest.Config.M)
		finalized = false
		log.Printf("owner session %s m=%d; Store executes on phone", fixture.Manifest.Config.Scheme, fixture.Manifest.Config.M)
		w.WriteHeader(201)
	})
	mux.HandleFunc("/owner/file", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}
		if !authorized(w, r) {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if fixture == nil || finalized {
			http.Error(w, "start owner session first", 409)
			return
		}
		c := fixture.Manifest.Config
		limit := 4 + int64(c.N)*int64(c.S)*32 + int64(c.N)*64 + 32
		if limit > 64<<20 {
			http.Error(w, "file exceeds experiment upload limit", 413)
			return
		}
		body, e := read(w, r, limit)
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		if len(body) < 4 {
			http.Error(w, "missing index", 400)
			return
		}
		i := int(uint32(body[0])<<24 | uint32(body[1])<<16 | uint32(body[2])<<8 | uint32(body[3]))
		if i >= len(ready) || ready[i] {
			http.Error(w, "invalid or duplicate file", 409)
			return
		}
		if e = fixture.ImportFile(body); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		ready[i] = true
		log.Printf("received owner file %d/%d (%s)", i+1, c.M, c.Scheme)
		w.WriteHeader(201)
	})
	mux.HandleFunc("/owner/finish", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}
		if !authorized(w, r) {
			return
		}
		body, e := read(w, r, 1<<20)
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if fixture == nil {
			http.Error(w, "no upload session", 409)
			return
		}
		for _, ok := range ready {
			if !ok {
				http.Error(w, "missing file", 409)
				return
			}
		}
		if e = fixture.Finalize(body, ownerKey); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		envelope = body
		finalized = true
		runtime.GC()
		w.WriteHeader(201)
	})
	mux.HandleFunc("/manifest", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !finalized {
			http.Error(w, "no finalized owner registry", 409)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(envelope)
	})
	mux.HandleFunc("/audit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}
		raw, e := read(w, r, 2<<20)
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if !finalized {
			http.Error(w, "finalize owner upload first", 409)
			return
		}
		start := time.Now()
		proof, e := fixture.Prove(raw)
		work := float64(time.Since(start).Nanoseconds()) / 1e6
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Server-Work-Ms", fmt.Sprintf("%.6f", work))
		w.Write(proof)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"service": "MultiAudit cloud ProofGen", "Store": "owner phone", "Verify": "optional owner phone", "setup_secret_received": false})
	})
	log.Printf("MultiAudit cloud prover %s; account token file %s", *addr, filepath.Join(*dir, "account-token.txt"))
	server := http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 5 * time.Minute, WriteTimeout: 10 * time.Minute}
	log.Fatal(server.ListenAndServe())
}
