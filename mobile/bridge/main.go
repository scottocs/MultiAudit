package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"multiaudit/mobile/core"
)

var mu sync.Mutex
var client *core.Client
var owner *core.Owner

//export MAInvoke
func MAInvoke(operation *C.char, input *C.char) (output *C.char) {
	mu.Lock()
	defer mu.Unlock()
	var result any
	var err error
	defer func() {
		if r := recover(); r != nil {
			client = nil
			output = response(nil, fmt.Errorf("client operation failed: %v", r))
		}
	}()
	var req struct {
		Envelope string      `json:"envelope"`
		OwnerKey string      `json:"owner_key"`
		Proof    string      `json:"proof"`
		Config   core.Config `json:"config"`
		Index    int         `json:"index"`
		File     string      `json:"file"`
		RealFile bool        `json:"real_file"`
	}
	if e := json.Unmarshal([]byte(C.GoString(input)), &req); e != nil {
		return response(nil, e)
	}
	switch C.GoString(operation) {
	case "owner_start":
		client = nil
		owner = nil
		runtime.GC()
		start := time.Now()
		owner, err = core.NewOwner(req.Config)
		if err == nil {
			var b []byte
			b, err = owner.Signed()
			result = map[string]any{"envelope": base64.StdEncoding.EncodeToString(b), "owner_key": owner.PublicKey(), "setup_ms": float64(time.Since(start).Nanoseconds()) / 1e6}
		}
	case "owner_file":
		if owner == nil {
			err = fmt.Errorf("start owner Store first")
			break
		}
		runtime.GC()
		var data []byte
		if req.RealFile {
			data, err = base64.StdEncoding.DecodeString(req.File)
			if data == nil {
				data = []byte{}
			}
		}
		if err == nil {
			var b []byte
			var measurement core.StoreMeasurement
			b, measurement, err = owner.StoreFile(req.Index, data)
			result = map[string]any{"wire": base64.StdEncoding.EncodeToString(b), "measurement": measurement}
		}
	case "owner_finish":
		if owner == nil || !owner.Complete() {
			err = fmt.Errorf("Store every file before finalizing")
			break
		}
		var b []byte
		b, err = owner.Signed()
		if err == nil {
			client, err = core.NewClient(b, owner.PublicKey())
			result = map[string]any{"envelope": base64.StdEncoding.EncodeToString(b), "owner_key": owner.PublicKey(), "registry_digest": client.Digest}
		}
	case "load":
		var b []byte
		b, err = base64.StdEncoding.DecodeString(req.Envelope)
		if err == nil {
			client, err = core.NewClient(b, req.OwnerKey)
		}
		if err == nil {
			result = map[string]any{"description": client.Describe(), "registry_digest": client.Digest, "config": client.Manifest.Config}
		}
	case "challenge":
		if client == nil {
			err = fmt.Errorf("load owner-authenticated metadata first")
			break
		}
		runtime.GC()
		start := time.Now()
		var b []byte
		b, err = client.Challenge()
		result = map[string]any{"wire": base64.StdEncoding.EncodeToString(b), "challenge_ms": float64(time.Since(start).Nanoseconds()) / 1e6, "upload_bytes": len(b)}
	case "verify":
		if client == nil {
			err = fmt.Errorf("load owner-authenticated metadata first")
			break
		}
		var b []byte
		b, err = base64.StdEncoding.DecodeString(req.Proof)
		if err == nil {
			result, err = client.Verify(b)
		}
	case "collect":
		runtime.GC()
		result = map[string]bool{"ok": true}
	default:
		err = fmt.Errorf("unknown operation")
	}
	return response(result, err)
}

func response(result any, err error) *C.char {
	out := map[string]any{"result": result}
	if err != nil {
		out["error"] = err.Error()
	}
	b, e := json.Marshal(out)
	if e != nil {
		b = []byte(`{"error":"encoding error"}`)
	}
	return C.CString(string(b))
}

//export MARelease
func MARelease(p *C.char) { C.free(unsafe.Pointer(p)) }

func main() {}
