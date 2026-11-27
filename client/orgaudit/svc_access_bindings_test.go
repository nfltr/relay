// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgaudit

// The audit's binding of spec/proverif/svc_access.pv query 7 (lane SA5,
// nfltr docs/decisions/service-access-2026-11-25.md "SA5"): a reader takes
// a record as machine m's only under the key the issuer certified for m
// (BIND:svc.auditsig). Each row changes one field of the honest line and
// requires a refusal. `make spec-bindings`.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"regexp"
	"testing"

	"github.com/nfltr/relay/client/internal/modelbind"
)

var auditBindings = map[string]func(*testing.T){
	"svc.auditsig": func(t *testing.T) {
		db, web := newMachine(t, "db", 1), newMachine(t, "web", 2)
		honest := writeLog(t, db, "L1", 1)[0]
		if _, ok, fs := checker(db, web).Add(honest); !ok || fs != nil {
			t.Fatalf("the honest line: %v", fs)
		}
		webKey := base64.RawURLEncoding.EncodeToString([]byte(web.key.Public().(ed25519.PublicKey)))
		for name, line := range map[string][]byte{
			"machine":   rechainAs(t, web, honest, "db"),                                            // web's certified key, naming db
			"key":       bytes.Replace(honest, []byte(`"key":"`), []byte(`"key":"`+webKey[:4]), 1),  // another key named
			"signer":    bytes.Replace(honest, []byte(`"signer":"01"`), []byte(`"signer":"02"`), 1), // another certificate named
			"signature": bytes.Replace(honest, []byte(`"sig":"`), []byte(`"sig":"AAAA`), 1),         // the bytes signed changed
			"unknown":   rechainAs(t, newMachine(t, "db", 7), honest, "db"),                         // a key the issuer never certified
		} {
			if bytes.Equal(line, honest) {
				t.Fatalf("%s: the row changed nothing", name)
			}
			if _, ok, _ := checker(db, web).Add(line); ok {
				t.Errorf("%s changed: taken as db's", name)
			}
		}
	},
}

// rechainAs is line's record signed by m's key, naming machine as its own.
func rechainAs(t *testing.T, m machine, line []byte, as string) []byte {
	t.Helper()
	r, err := Parse(line)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Line(r, Signing{Log: r.Log, Seq: r.Seq, Prev: r.Prev, Machine: as, Cert: m.cert, Key: m.key, At: r.At})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestSvcAccessModelBindingsAudit runs every row; each is a BIND id of
// the model, the SA5 one.
func TestSvcAccessModelBindingsAudit(t *testing.T) {
	src, err := os.ReadFile("../../spec/proverif/svc_access.pv")
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	for id, row := range auditBindings {
		rows = append(rows, id)
		t.Run(id, row)
	}
	if err := modelbind.Check(src, regexp.MustCompile(`BIND:(svc\.auditsig)\s`), rows); err != nil {
		t.Fatal(err)
	}
}
