// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

// Session audit at the issuer (nfltr docs/decisions/service-access-2026-11-25.md
// "SA5: the record, its check, the names"): the issuer appends the lines
// its checker takes to SessionsFile, keeps per machine and log where it
// stands and when it last heard the machine's head (HeadsFile), and
// exports SessionsFile to the sink the operator set (audit.sink of
// ConfigFile), a cursor (SinkCursorFile) moving only after the sink took
// the lines. The relay carries the sealed batches and the answers'
// {log, seq}; it never reads a record.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/nfltr/relay/client/orgaudit"
	"github.com/nfltr/relay/org/internal/audittrace"
	"github.com/nfltr/relay/org/internal/orgfiles"
	"github.com/nfltr/relay/org/orgissuer"
	"github.com/nfltr/relay/org/orgpki"
)

// The issuer directory's audit files.
const (
	SessionsFile   = "sessions.jsonl"      // the machines' lines the issuer took, in the order it took them
	HeadsFile      = "sessions-heads.json" // per machine: where the issuer stands per log, its last head and when heard
	SinkCursorFile = "sessions.sink"       // how much of SessionsFile the sink took
	ConfigFile     = "config.json"         // the issuer's settings: audit.sink
)

// machineHeads is HeadsFile's entry of one machine.
type machineHeads struct {
	Logs  map[string]logHead `json:"logs"`
	Head  []byte             `json:"head,omitempty"` // its last signed head
	Heard time.Time          `json:"heard,omitzero"` // the issuer's time at it
}

type logHead struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path) // #nosec G304 -- a file of the issuer's own directory
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func writeJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return orgfiles.Write(path, b, 0o600)
}

// takeAudit is the issuer's intake of one sealed batch, under the
// directory's lock: the lines the checker takes appended in order, one
// ActAuditRefused for the rest, the head heard.
func takeAudit(dir string, iss *orgpki.Issuer, req orgpki.AuditRequest, now time.Time) (orgpki.AuditAnswer, error) {
	b, err := iss.OpenAudit(req.Sealed)
	if err != nil {
		return orgpki.AuditAnswer{}, err
	}
	heads := map[string]*machineHeads{}
	if err := readJSON(filepath.Join(dir, HeadsFile), &heads); err != nil {
		return orgpki.AuditAnswer{}, err
	}
	c := iss.AuditChecker()
	for m, h := range heads {
		for l, at := range h.Logs {
			c.Seed(m, l, at.Seq, at.Hash)
		}
	}
	var took []byte
	type refusal struct {
		seq  uint64
		what string
		n    int
	}
	refused := map[string]*refusal{}
	var pre, post uint64 // the machine's held seq before and after (MoveAudit.tla Take; traced)
	gap := false
	if len(b.Lines) > 0 {
		if r, err := orgaudit.Parse(b.Lines[0]); err == nil {
			pre, _ = c.Held(r.Machine, r.Log)
			defer func() {
				post, _ = c.Held(r.Machine, r.Log)
				audittrace.Line(map[string]any{"ev": "take", "h": dir, "pre": pre, "n": post, "gap": gap})
			}()
		}
	}
	for _, line := range b.Lines {
		r, ok, fs := c.Add(line)
		for _, f := range fs {
			gap = gap || strings.HasPrefix(f.What, "gap:")
		}
		if ok {
			took = append(append(took, line...), '\n')
			continue
		}
		if f := refused[r.Machine]; f != nil {
			f.n++
		} else if len(fs) > 0 {
			refused[r.Machine] = &refusal{r.Seq, fs[0].What, 1}
		}
	}
	if len(took) > 0 {
		if err := appendFile(filepath.Join(dir, SessionsFile), took); err != nil {
			return orgpki.AuditAnswer{}, err
		}
	}
	for _, m := range slices.Sorted(maps.Keys(refused)) {
		f := refused[m]
		if err := iss.RefuseAudit(m, f.seq, fmt.Sprintf("%s (%d lines refused)", f.what, f.n), now); err != nil {
			return orgpki.AuditAnswer{}, err
		}
	}
	h, hfs := c.CheckHead(b.Head)
	headOK := h.Machine != "" && (len(hfs) == 0 || strings.HasPrefix(hfs[0].What, "withheld"))
	for _, r := range b.Lines {
		if rec, err := orgaudit.Parse(r); err == nil {
			hold(heads, c, rec.Machine)
		}
	}
	if headOK {
		mh := hold(heads, c, h.Machine)
		if !h.At.Before(heardAt(mh)) { // an older head replayed changes nothing
			mh.Head, mh.Heard = b.Head, now
		}
	}
	if err := writeJSON(filepath.Join(dir, HeadsFile), heads); err != nil {
		return orgpki.AuditAnswer{}, err
	}
	if !headOK {
		return orgpki.AuditAnswer{}, errors.New("the batch's head is not its machine's")
	}
	seq, _ := c.Held(h.Machine, h.Log)
	return orgpki.AuditAnswer{Log: h.Log, Seq: seq}, nil
}

// hold is heads' entry of machine with the checker's positions in it.
func hold(heads map[string]*machineHeads, c *orgaudit.Checker, machine string) *machineHeads {
	mh := heads[machine]
	if mh == nil {
		mh = &machineHeads{Logs: map[string]logHead{}}
		heads[machine] = mh
	}
	for _, l := range c.Logs(machine) {
		seq, hash := c.Held(machine, l)
		mh.Logs[l] = logHead{seq, hash}
	}
	return mh
}

// heardAt is the At of mh's last head (zero: none).
func heardAt(mh *machineHeads) time.Time {
	h, err := orgaudit.ParseHead(mh.Head)
	if err != nil {
		return time.Time{}
	}
	return h.At
}

func appendFile(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600) // #nosec G304 -- the issuer's own directory, or the sink its owner set
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// issuerConfig is ConfigFile.
type issuerConfig struct {
	Audit struct {
		Sink string `json:"sink,omitempty"`
	} `json:"audit"`
}

// AuditSink is the sink set in dir ("" none).
func AuditSink(dir string) (string, error) {
	var c issuerConfig
	err := readJSON(filepath.Join(dir, ConfigFile), &c)
	return c.Audit.Sink, err
}

// SetAuditSink sets dir's audit.sink: an absolute file path, an https URL
// (http only to a loopback host), or "" for none. A new sink gets every
// line from the first.
func SetAuditSink(dir, sink string) error {
	if err := checkSink(sink); err != nil {
		return err
	}
	unlock, err := orgfiles.Lock(filepath.Join(dir, ConfigFile+".lock"))
	if err != nil {
		return err
	}
	defer unlock()
	var c issuerConfig
	if err := readJSON(filepath.Join(dir, ConfigFile), &c); err != nil {
		return err
	}
	c.Audit.Sink = sink
	return writeJSON(filepath.Join(dir, ConfigFile), c)
}

func checkSink(sink string) error {
	if sink == "" || filepath.IsAbs(sink) && !strings.Contains(sink, "://") {
		return nil
	}
	u, err := url.Parse(sink)
	switch {
	case err != nil || u.Host == "":
		return fmt.Errorf("audit sink %q: an absolute file path or an https URL", sink)
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && isLoopback(u.Hostname()):
		return nil
	}
	return fmt.Errorf("audit sink %q: an https URL (http only to a loopback address)", sink)
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

// sinkCursor is SinkCursorFile: how much of SessionsFile Sink took.
type sinkCursor struct {
	Sink   string `json:"sink"`
	Offset int64  `json:"offset"`
}

// exportMax bounds one export's bytes.
const exportMax = 1 << 20

// ExportAudit hands the sink the lines of SessionsFile it has not taken
// (none set: nothing), at most 1 MiB at a time, and moves the cursor
// once it took them. client is for an URL sink. It returns the bytes
// exported.
func ExportAudit(ctx context.Context, dir string, client *http.Client) (int, error) {
	sink, err := AuditSink(dir)
	if err != nil || sink == "" {
		return 0, err
	}
	var cur sinkCursor
	if err := readJSON(filepath.Join(dir, SinkCursorFile), &cur); err != nil {
		return 0, err
	}
	if cur.Sink != sink {
		cur = sinkCursor{Sink: sink}
	}
	f, err := os.Open(filepath.Join(dir, SessionsFile)) // #nosec G304 -- the issuer's own directory
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	buf := make([]byte, exportMax)
	n, err := f.ReadAt(buf, cur.Offset)
	_ = f.Close()
	if err != nil && err != io.EOF {
		return 0, err
	}
	buf = buf[:bytes.LastIndexByte(buf[:n], '\n')+1]
	if len(buf) == 0 {
		return 0, nil
	}
	if filepath.IsAbs(sink) && !strings.Contains(sink, "://") {
		err = appendFile(sink, buf)
	} else {
		err = post(ctx, client, sink, buf)
	}
	if err != nil {
		return 0, fmt.Errorf("audit sink %s: %w", sink, err)
	}
	cur.Offset += int64(len(buf))
	return len(buf), writeJSON(filepath.Join(dir, SinkCursorFile), cur)
}

func post(ctx context.Context, client *http.Client, u string, body []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := client.Do(req) // #nosec G704 -- the URL the issuer's owner set (SetAuditSink)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("answered %s", resp.Status)
	}
	return nil
}

// AuditSession is one session of the organisation's audit: its open
// line and, once it ended, its close.
type AuditSession struct {
	Machine string           `json:"machine"`
	Open    orgaudit.Record  `json:"open"`
	Close   *orgaudit.Record `json:"close,omitempty"`
}

// AuditView is what nfltr access log reads: the sessions in the order
// they opened, and every finding (the check of each line again, the
// issuer's refusals, lines withheld, machines silent).
type AuditView struct {
	Sessions []AuditSession     `json:"sessions"`
	Findings []orgaudit.Finding `json:"findings"`
}

// ReadAudit reads the organisation's audit in the issuer directory dir at
// now, checking every line against the issuer's verified log.
func ReadAudit(dir string, now time.Time) (AuditView, error) {
	st, err := orgissuer.Lock(dir)
	if err != nil {
		return AuditView{}, err
	}
	defer st.Unlock()
	lines, err := st.Lines()
	if err != nil {
		return AuditView{}, err
	}
	entries, _, err := orgpki.VerifyLog(lines)
	if err != nil {
		return AuditView{}, err
	}
	c := orgpki.LogChecker(orgpki.AuditSigners(entries))
	var v AuditView
	byID := map[string]int{}
	data, err := os.ReadFile(filepath.Join(dir, SessionsFile)) // #nosec G304 -- the issuer's own directory
	if err != nil && !os.IsNotExist(err) {
		return AuditView{}, err
	}
	for line := range bytes.Lines(data) {
		r, ok, fs := c.Add(bytes.TrimSuffix(line, []byte("\n")))
		v.Findings = append(v.Findings, fs...)
		if !ok {
			continue
		}
		key := r.Machine + "/" + r.Session
		i, seen := byID[key]
		switch {
		case r.Kind == orgaudit.KindOpen && !seen:
			byID[key] = len(v.Sessions)
			v.Sessions = append(v.Sessions, AuditSession{Machine: r.Machine, Open: r})
		case r.Kind == orgaudit.KindClose && seen:
			v.Sessions[i].Close = &r
		case r.Kind == orgaudit.KindClose: // its open lost: the close says all
			byID[key] = len(v.Sessions)
			open := r
			open.Kind = orgaudit.KindOpen
			v.Sessions = append(v.Sessions, AuditSession{Machine: r.Machine, Open: open, Close: &r})
		}
	}
	for _, e := range entries {
		if e.Act == orgpki.ActAuditRefused {
			v.Findings = append(v.Findings, orgaudit.Finding{Machine: e.Name, Seq: uint64(e.Number), What: "refused at " + e.Time.UTC().Format(time.RFC3339) + ": " + e.Reason}) // #nosec G115 -- a seq the issuer logged
		}
	}
	heads := map[string]*machineHeads{}
	if err := readJSON(filepath.Join(dir, HeadsFile), &heads); err != nil {
		return AuditView{}, err
	}
	for _, m := range slices.Sorted(maps.Keys(heads)) {
		if heads[m].Head != nil {
			_, fs := c.CheckHead(heads[m].Head)
			v.Findings = append(v.Findings, fs...)
		}
		open := 0
		for _, s := range v.Sessions {
			if s.Machine == m && s.Close == nil {
				open++
			}
		}
		v.Findings = append(v.Findings, orgaudit.Silent(m, heads[m].Heard, open, now)...)
	}
	return v, nil
}
