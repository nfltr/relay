// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Command testknobs fails when a _test.go file assigns to a package-level
// variable declared in a non-test file of its package (or, from an external
// foo_test package, to an exported foo.Var): production code must take what a
// test varies as a parameter or field, not as a package-level knob a test
// rewrites (it races with parallel tests and with goroutines left behind).
//
//	go run ./internal/tools/testknobs [-allow scripts/testknobs-allow.txt] dir...
//
// An allow-list line is "<file_test.go path>:<var> <reason>" relative to the
// directory the tool runs in; an entry that no longer matches fails the run.
// Stdlib only; the same file is kept in nfltr-relay's tree.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	allowFile := flag.String("allow", "", "allow-list file")
	flag.Parse()
	allow, err := readAllow(*allowFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "testknobs:", err)
		os.Exit(2)
	}
	var found []string
	for _, root := range flag.Args() {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return err
			}
			if n := d.Name(); n == "vendor" || n == "testdata" || strings.HasPrefix(n, ".") && p != root {
				return filepath.SkipDir
			}
			f, err := scanDir(p)
			found = append(found, f...)
			return err
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "testknobs:", err)
			os.Exit(2)
		}
	}
	sort.Strings(found)
	bad := false
	for _, f := range found { // f = "file:line:var"
		parts := strings.SplitN(f, ":", 3)
		key := parts[0] + ":" + parts[2]
		if _, ok := allow[key]; ok {
			allow[key] = true
			continue
		}
		bad = true
		fmt.Printf("%s:%s: test assigns package-level variable %s of a non-test file (make it a parameter or field, or allow-list it with a reason)\n", parts[0], parts[1], parts[2])
	}
	for k, used := range allow {
		if !used {
			bad = true
			fmt.Printf("stale allow-list entry: %s\n", k)
		}
	}
	if bad {
		os.Exit(1)
	}
}

func readAllow(path string) (map[string]bool, error) {
	m := map[string]bool{}
	if path == "" {
		return m, nil
	}
	f, err := os.Open(path) // #nosec G304 -- the allow-list path is the developer's own command-line argument
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, reason, _ := strings.Cut(line, " ")
		if strings.TrimSpace(reason) == "" {
			return nil, fmt.Errorf("%s: allow-list entry %q has no reason", path, key)
		}
		m[key] = false
	}
	return m, sc.Err()
}

// scanDir returns "file:line:var" for each violation in dir's package.
func scanDir(dir string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil || len(files) == 0 {
		return nil, err
	}
	fset := token.NewFileSet()
	vars := map[string]bool{}
	pkgName := ""
	type tf struct {
		path string
		f    *ast.File
	}
	var tests []tf
	for _, p := range files {
		f, err := parser.ParseFile(fset, p, nil, 0) // object resolution on: Ident.Obj is nil for names declared in another file
		if err != nil {
			return nil, err
		}
		if strings.HasSuffix(p, "_test.go") {
			tests = append(tests, tf{p, f})
			continue
		}
		pkgName = f.Name.Name
		for _, d := range f.Decls {
			if g, ok := d.(*ast.GenDecl); ok && g.Tok == token.VAR {
				for _, s := range g.Specs {
					for _, n := range s.(*ast.ValueSpec).Names {
						if n.Name != "_" {
							vars[n.Name] = true
						}
					}
				}
			}
		}
	}
	var out []string
	for _, t := range tests {
		external := strings.HasSuffix(t.f.Name.Name, "_test")
		check := func(lhs ast.Expr) {
			name := root(lhs, external, pkgName)
			if name != "" && vars[name] {
				out = append(out, fmt.Sprintf("%s:%d:%s", filepath.ToSlash(t.path), fset.Position(lhs.Pos()).Line, name))
			}
		}
		ast.Inspect(t.f, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.AssignStmt:
				if s.Tok != token.DEFINE {
					for _, l := range s.Lhs {
						check(l)
					}
				}
			case *ast.IncDecStmt:
				check(s.X)
			}
			return true
		})
	}
	return out, nil
}

// root names the package-level variable an assignment target writes, or "".
// In an in-package test it is the identifier at the root of the target that
// no declaration in the file binds; in an external test package it is Var of
// pkg.Var.
func root(e ast.Expr, external bool, pkgName string) string {
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.SliceExpr:
			e = x.X
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && external && id.Name == strings.TrimSuffix(pkgName, "_test") && id.Obj == nil {
				return x.Sel.Name
			}
			e = x.X
		case *ast.Ident:
			if external || x.Obj != nil {
				return ""
			}
			return x.Name
		default:
			return ""
		}
	}
}
