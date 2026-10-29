// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package proto

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestModuleBoundary: the protocol module (the agent wire proto/pb included)
// links nothing of nfltr's but itself and the link layer
// (github.com/nfltr/link, standard library only).
func TestModuleBoundary(t *testing.T) {
	checkDeps(t, "github.com/nfltr/relay/proto/", "github.com/nfltr/link/")
}

func TestSourceFilesCarryLicenseHeader(t *testing.T) {
	checkLicenseHeaders(t, ".")
}

func checkDeps(t *testing.T, allowed ...string) {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", "-test", "-f", "{{.ImportPath}}", "./...").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for p := range strings.FieldsSeq(string(out)) {
		p = strings.TrimSuffix(strings.TrimSuffix(strings.Fields(p)[0], ".test"), "_test")
		if !strings.HasPrefix(p, "github.com/nfltr/") {
			continue
		}
		ok := false
		for _, a := range allowed {
			ok = ok || strings.HasPrefix(p+"/", a) || p == a
		}
		if !ok {
			t.Errorf("links %s", p)
		}
	}
}

func checkLicenseHeaders(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "testdata" {
			return filepath.SkipDir
		}
		switch filepath.Ext(path) {
		case ".go", ".proto", ".yaml":
		default:
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lines := strings.SplitN(string(data), "\n", 4)
		if !strings.Contains(strings.Join(lines[:min(3, len(lines))], "\n"), "SPDX-License-Identifier: Apache-2.0") {
			t.Errorf("%s: no SPDX-License-Identifier: Apache-2.0 header in its first lines", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
