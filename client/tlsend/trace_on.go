// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build relaytrace

package tlsend

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

// Trace mode (go test -tags relaytrace, RELAYTRACE=<dir>) writes the steps
// of spec/TLSEnd.tla one direction of a session's end takes to
// <dir>/tlsend-<key>.ndjson (key: the TLS connection's exported keying
// material, the same at both ends), under one process-wide lock;
// spec/TraceTLSEnd.tla checks each file. The direction is the first
// close_notify's: its sender is X, the other Conn Y; the later direction
// is not logged. A file whose X is no tlsend Conn (its Notify never
// logged), or whose Y's transport acknowledges no end (a direct path's:
// Close's exemption), is not TLSEnd's and is removed.
//
//	Notify  X's close_notify written (CloseWrite, CloseWriteSync)
//	Fin     X's transport end next (a CloseWrite or CloseWriteSync below)
//	End     X's CloseWriteSync returned: n 1 nil, 0 an error (a reset)
//	EOF     Y's Read returned the close_notify's io.EOF
//	Close   Y's Close began: n 1 it takes the transport's end first
//	Closed  Y's Close closes the TLS connection whole
var (
	traceMu   sync.Mutex
	traceDirs = map[string]*traceDir{}
	traceN    atomic.Int64
	traceIDs  = map[*rawEnd]int64{}
)

type traceDir struct {
	path string
	x, y int64 // conn ids; 0 none yet, -1 out of scope
	f    *os.File
}

// traceID names c in its trace files (traceMu held).
func (c *Conn) traceID() int64 {
	id := traceIDs[c.raw]
	if id == 0 {
		id = traceN.Add(1)
		traceIDs[c.raw] = id
	}
	return id
}

func (c *Conn) trace(ev string, n int) {
	dir := os.Getenv("RELAYTRACE")
	if dir == "" {
		return
	}
	cs := c.Conn.ConnectionState()
	if !cs.HandshakeComplete {
		return
	}
	k, err := cs.ExportKeyingMaterial("nfltr tlsend trace", nil, 8)
	if err != nil {
		return
	}
	key := hex.EncodeToString(k)
	traceMu.Lock()
	defer traceMu.Unlock()
	id := c.traceID()
	d := traceDirs[key]
	if d == nil {
		d = &traceDir{path: filepath.Join(dir, "tlsend-"+key+".ndjson")}
		traceDirs[key] = d
	}
	switch ev {
	case "Notify", "Fin", "End":
		if d.x == 0 && ev == "Notify" {
			d.x = id
		}
		if d.x != id || d.y == -1 { // d.y -1: the file is dropped (a direct path's Y)
			return
		}
	default:
		if d.x == 0 { // the peer's close_notify was no tlsend Conn's
			d.x = -1
		}
		if d.x == -1 || d.x == id || d.y == -1 {
			return
		}
		if d.y == 0 {
			d.y = id
			if !syncsEnd(c.raw.Conn) { // a direct path's: not TLSEnd's
				d.y = -1
				if d.f != nil {
					_ = d.f.Close()
					d.f = nil
				}
				_ = os.Remove(d.path)
				return
			}
		}
	}
	if d.f == nil {
		if d.f, err = os.OpenFile(d.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err != nil { // #nosec G304 -- the tester's RELAYTRACE
			panic(err)
		}
	}
	b, err := json.Marshal(map[string]any{"ev": ev, "n": n})
	if err != nil {
		panic(err)
	}
	if _, err := d.f.Write(append(b, '\n')); err != nil {
		panic(err)
	}
}
