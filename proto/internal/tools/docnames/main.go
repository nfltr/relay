// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Command docnames fails when a doc comment of a public package of the
// relay modules names nothing that exists: an unexported identifier, a
// member its type lacks, or a name api/<module>-*.txt records as removed
// that the package does not export again (link's TestDocsNameNoGhosts,
// lane RELAYAPI). Run from the repository root:
//
//	docnames proto client org
//
// It reads every package of all three modules (outside internal/ and
// testdata/), so one module's docs may qualify another's names
// (agentwire.LabelUpdatesKey from client), and checks the docs of the
// modules named. Each module's TestDocsNameNoGhosts runs it on itself.
package main

import (
	"fmt"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var modules = []string{"proto", "client", "org"}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "docnames:", err)
	os.Exit(2)
}

func main() {
	pkgs := map[string]docPkg{}   // by package name
	module := map[string]string{} // package name -> module
	dirOf := map[string]string{}  // package name -> dir
	for _, m := range modules {
		err := filepath.WalkDir(m, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				return nil
			}
			if n := d.Name(); n == "internal" || n == "testdata" || (n != m && strings.HasPrefix(n, ".")) {
				return filepath.SkipDir
			}
			if path != m {
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return filepath.SkipDir // another module (browser's harness)
				}
			}
			name, ok := pkgName(path)
			if !ok {
				return nil
			}
			if prev, dup := dirOf[name]; dup {
				return fmt.Errorf("package name %s in %s and %s: qualified docs are ambiguous", name, prev, path)
			}
			dirOf[name], module[name] = path, m
			pkgs[name] = loadDocPkg(path)
			return nil
		})
		if err != nil {
			fatal(err)
		}
	}
	check := map[string]bool{}
	for _, m := range os.Args[1:] {
		check[m] = true
	}
	removed := removedNames(dirOf)
	var bad []string
	for name, p := range pkgs {
		if !check[module[name]] || generated(dirOf[name]) {
			continue
		}
		for where, text := range p.text {
			seen := map[string]bool{}
			for _, tok := range docToken.FindAllString(text, -1) {
				if seen[tok] {
					continue
				}
				seen[tok] = true
				if why := ghost(name, tok, pkgs, removed); why != "" {
					bad = append(bad, fmt.Sprintf("%s %s's doc: %q %s", dirOf[name], where, tok, why))
				}
			}
		}
	}
	sort.Strings(bad)
	for _, b := range bad {
		fmt.Println(b)
	}
	if len(bad) > 0 {
		os.Exit(1)
	}
}

// pkgName is the package of dir's non-test Go files.
func pkgName(dir string) (string, bool) {
	files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.PackageClauseOnly)
		if err != nil {
			fatal(err)
		}
		return af.Name.Name, true
	}
	return "", false
}

// generated: the package is protoc's (its docs are the .proto comments,
// buf lint's COMMENTS rules check those).
func generated(dir string) bool {
	files, _ := filepath.Glob(filepath.Join(dir, "*.pb.go"))
	return len(files) > 0
}

// docPkg is what a package's docs say and the names it exports.
type docPkg struct {
	text  map[string]string   // doc comment by what it documents: the package, its exported names, struct fields
	names map[string]bool     // exported top-level names and every exported member name
	args  map[string]bool     // parameter names of exported functions and methods: a doc may name them
	types map[string][]string // exported type -> its exported members
}

func loadDocPkg(dir string) docPkg {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, parser.ParseComments)
	if err != nil {
		fatal(err)
	}
	p := docPkg{text: map[string]string{}, names: map[string]bool{}, args: map[string]bool{}, types: map[string][]string{}}
	params := func(fd *ast.FuncDecl) {
		for _, f := range fd.Type.Params.List {
			for _, n := range f.Names {
				p.args[n.Name] = true
			}
		}
	}
	for _, ap := range pkgs {
		d := doc.New(ap, dir, 0)
		p.text["package"] += d.Doc
		values := func(vs []*doc.Value) {
			for _, v := range vs {
				p.text[v.Names[0]] += v.Doc
				for _, n := range v.Names {
					p.names[n] = true
				}
				for _, s := range v.Decl.Specs {
					if vs := s.(*ast.ValueSpec); vs.Names[0].IsExported() {
						p.text[vs.Names[0].Name] += vs.Doc.Text() + vs.Comment.Text()
					}
				}
			}
		}
		values(d.Consts)
		values(d.Vars)
		for _, f := range d.Funcs {
			p.names[f.Name] = true
			p.text[f.Name] += f.Doc
			params(f.Decl)
		}
		for _, ty := range d.Types {
			p.names[ty.Name] = true
			p.text[ty.Name] += ty.Doc
			values(ty.Consts)
			values(ty.Vars)
			member := func(n string) {
				p.names[n] = true
				p.types[ty.Name] = append(p.types[ty.Name], n)
			}
			for _, f := range ty.Funcs {
				p.names[f.Name] = true
				p.text[f.Name] += f.Doc
				params(f.Decl)
			}
			for _, m := range ty.Methods {
				member(m.Name)
				p.text[ty.Name+"."+m.Name] += m.Doc
				params(m.Decl)
			}
			var fields *ast.FieldList
			switch tt := ty.Decl.Specs[0].(*ast.TypeSpec).Type.(type) {
			case *ast.StructType:
				fields = tt.Fields
			case *ast.InterfaceType:
				fields = tt.Methods
			}
			if fields == nil {
				continue
			}
			for _, f := range fields.List {
				for _, n := range f.Names {
					p.text[ty.Name+"."+n.Name] += f.Doc.Text() + f.Comment.Text()
				}
				if ft, ok := f.Type.(*ast.FuncType); ok { // a func field or an interface method
					for _, a := range ft.Params.List {
						for _, n := range a.Names {
							p.args[n.Name] = true
						}
					}
				}
				for _, n := range f.Names {
					if n.IsExported() {
						member(n.Name)
					}
				}
				if len(f.Names) == 0 { // embedded
					if id, ok := ast.Unparen(f.Type).(*ast.Ident); ok && id.IsExported() {
						member(id.Name)
					}
				}
			}
		}
	}
	return p
}

// removedNames are the names api/<module>-*.txt records as removed, by
// package name (apidiff's "- (*T).M: removed", "- X: removed",
// "- ./dir.T.M: removed" relative to the module).
func removedNames(dirOf map[string]string) map[string]map[string]bool {
	byDir := map[string]string{}
	for n, d := range dirOf {
		byDir[d] = n
	}
	out := map[string]map[string]bool{}
	for _, m := range modules {
		files, err := filepath.Glob("api/" + m + "-*.txt")
		if err != nil {
			fatal(err)
		}
		for _, f := range files {
			data, err := os.ReadFile(f) // #nosec G304 -- api/*.txt of this repository, from Glob
			if err != nil {
				fatal(err)
			}
			for _, l := range strings.Split(string(data), "\n") {
				l, ok := strings.CutSuffix(l, ": removed")
				if !ok || !strings.HasPrefix(l, "- ") || strings.HasPrefix(l, "- package ") {
					continue
				}
				l = strings.TrimPrefix(l, "- ")
				pkg := byDir[m]
				if rest, ok := strings.CutPrefix(l, "./"); ok {
					i := strings.LastIndex(rest, "/") + 1
					j := strings.Index(rest[i:], ".") + i
					pkg, l = byDir[filepath.Join(m, rest[:j])], rest[j+1:]
				}
				l = strings.NewReplacer("(*", "", "(", "", ")", "").Replace(l)
				parts := strings.Split(l, ".")
				if out[pkg] == nil {
					out[pkg] = map[string]bool{}
				}
				out[pkg][parts[len(parts)-1]] = true
			}
		}
	}
	return out
}

var (
	docToken = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*`)
	camelLow = regexp.MustCompile(`^[a-z][a-z0-9]*[A-Z][A-Za-z0-9]*$`)
	// camelWord are words of the docs that look like unexported names:
	// prose, an X.509 field (rfc822Name) and an example's variable
	// (machineTLS).
	camelWord = map[string]bool{"macOS": true, "mTLS": true, "gRPC": true, "iOS": true, "rfc822Name": true, "machineTLS": true}
)

// ghost says why tok, a word of package pkg's docs, names nothing; ""
// when it does or is not a Go name of these packages.
func ghost(pkg, tok string, pkgs map[string]docPkg, removed map[string]map[string]bool) string {
	if strings.HasSuffix(tok, ".tla") || strings.HasSuffix(tok, ".cfg") || strings.HasSuffix(tok, ".pv") {
		return "" // a spec file
	}
	parts := strings.Split(tok, ".")
	if _, ok := pkgs[parts[0]]; ok && len(parts) == 2 && !ast.IsExported(parts[1]) {
		return "" // not a Go name: a protocol id ("p2p.v1")
	}
	if q, ok := pkgs[parts[0]]; ok && len(parts) > 1 {
		pkg, parts = parts[0], parts[1:]
		if !q.names[parts[0]] {
			return "is not an exported name of " + pkg
		}
	}
	p := pkgs[pkg]
	if len(parts) > 1 {
		if members, ok := p.types[parts[0]]; ok {
			for _, m := range members {
				if m == parts[1] {
					return ""
				}
			}
			return "is no exported member of " + parts[0]
		}
		return ""
	}
	w := parts[0]
	if camelLow.MatchString(w) && !camelWord[w] && !p.args[w] {
		return "is unexported: name what the caller can use"
	}
	if removed[pkg][w] && !p.names[w] {
		return "was removed (api/*.txt)"
	}
	return ""
}
