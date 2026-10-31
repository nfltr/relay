// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"io"
	"net/http"
	"testing"
)

// The tunnel's response rewriting, as nfltr http's own loop had it
// (moved here with that loop).

func TestRewriteLocalURLs_WithServicePrefix(t *testing.T) {
	body := []byte(`<a href="http://localhost:8080/repo/list">repos</a>`)
	result := rewriteLocalURLs(body, "http://localhost:8080", "fossil", "")
	want := `<a href="/fossil/repo/list">repos</a>`
	if string(result) != want {
		t.Errorf("got %q, want %q", string(result), want)
	}
}

func TestRewriteLocalURLs_WithoutServicePrefix(t *testing.T) {
	body := []byte(`<a href="http://localhost:8080/repo/list">repos</a>`)
	result := rewriteLocalURLs(body, "http://localhost:8080", "", "")
	want := `<a href="/repo/list">repos</a>`
	if string(result) != want {
		t.Errorf("got %q, want %q", string(result), want)
	}
}

func TestRewriteLocalURLs_BaseTag(t *testing.T) {
	body := []byte(`<base href="http://localhost:8080/app/">`)
	result := rewriteLocalURLs(body, "http://localhost:8080", "fossil", "")
	want := `<base href="/fossil/">`
	if string(result) != want {
		t.Errorf("got %q, want %q", string(result), want)
	}
}

func TestRewriteLocalURLs_BaseTag_NoPrefix(t *testing.T) {
	body := []byte(`<base href="http://localhost:8080/app/">`)
	result := rewriteLocalURLs(body, "http://localhost:8080", "", "")
	want := `<base href="/">`
	if string(result) != want {
		t.Errorf("got %q, want %q", string(result), want)
	}
}

func TestRewriteLocalURLs_RootRelative(t *testing.T) {
	body := []byte(`<a href="/timeline">Timeline</a><link rel="stylesheet" href="/style.css">`)
	result := rewriteLocalURLs(body, "http://localhost:8080", "fossil", "")
	want := `<a href="/fossil/timeline">Timeline</a><link rel="stylesheet" href="/fossil/style.css">`
	if string(result) != want {
		t.Errorf("got %q, want %q", string(result), want)
	}
}

func TestRewriteLocalURLs_RootRelative_NoDoublePrefix(t *testing.T) {
	// Absolute URL rewriting produces /fossil/repo; root-relative pass must not double it.
	body := []byte(`<a href="http://localhost:8080/repo">R</a><a href="/timeline">T</a>`)
	result := rewriteLocalURLs(body, "http://localhost:8080", "fossil", "")
	want := `<a href="/fossil/repo">R</a><a href="/fossil/timeline">T</a>`
	if string(result) != want {
		t.Errorf("got %q, want %q", string(result), want)
	}
}

func TestRewriteLocalURLs_RootRelative_NoPrefix(t *testing.T) {
	// Without a service prefix, root-relative URLs must stay unchanged.
	body := []byte(`<a href="/timeline">Timeline</a>`)
	result := rewriteLocalURLs(body, "http://localhost:8080", "", "")
	want := `<a href="/timeline">Timeline</a>`
	if string(result) != want {
		t.Errorf("got %q, want %q", string(result), want)
	}
}

func TestRewriteLocalURLs_CSSUrl(t *testing.T) {
	body := []byte(`body { background: url('/images/bg.png'); }`)
	result := rewriteLocalURLs(body, "http://localhost:8080", "fossil", "")
	want := `body { background: url('/fossil/images/bg.png'); }`
	if string(result) != want {
		t.Errorf("got %q, want %q", string(result), want)
	}
}

func TestRewriteLocalURLs_BrowsePrefix_RootRelative(t *testing.T) {
	body := []byte(`<a href="/timeline">Timeline</a><link rel="stylesheet" href="/style.css">`)
	result := rewriteLocalURLs(body, "http://localhost:8080", "fossil", "/browse/my-agent-01")
	want := `<a href="/browse/my-agent-01/fossil/timeline">Timeline</a><link rel="stylesheet" href="/browse/my-agent-01/fossil/style.css">`
	if string(result) != want {
		t.Errorf("got  %q\nwant %q", string(result), want)
	}
}

func TestRewriteLocalURLs_BrowsePrefix_AbsoluteURL(t *testing.T) {
	body := []byte(`<a href="http://localhost:8080/repo/list">repos</a>`)
	result := rewriteLocalURLs(body, "http://localhost:8080", "fossil", "/browse/my-agent-01")
	want := `<a href="/browse/my-agent-01/fossil/repo/list">repos</a>`
	if string(result) != want {
		t.Errorf("got  %q\nwant %q", string(result), want)
	}
}

func TestRewriteLocalURLs_BrowsePrefix_NoDoublePrefix(t *testing.T) {
	// Mix of absolute and root-relative must not produce doubled browse prefix.
	body := []byte(`<a href="http://localhost:8080/repo">R</a><a href="/timeline">T</a>`)
	result := rewriteLocalURLs(body, "http://localhost:8080", "fossil", "/browse/my-agent-01")
	want := `<a href="/browse/my-agent-01/fossil/repo">R</a><a href="/browse/my-agent-01/fossil/timeline">T</a>`
	if string(result) != want {
		t.Errorf("got  %q\nwant %q", string(result), want)
	}
}

func TestRewriteLocalURLs_BrowsePrefix_BaseTag(t *testing.T) {
	body := []byte(`<base href="http://localhost:8080/app/">`)
	result := rewriteLocalURLs(body, "http://localhost:8080", "fossil", "/browse/my-agent-01")
	want := `<base href="/browse/my-agent-01/fossil/">`
	if string(result) != want {
		t.Errorf("got  %q\nwant %q", string(result), want)
	}
}

func TestRewriteLocalURLs_BrowsePrefix_CSSUrl(t *testing.T) {
	body := []byte(`body { background: url('/images/bg.png'); }`)
	result := rewriteLocalURLs(body, "http://localhost:8080", "fossil", "/browse/my-agent-01")
	want := `body { background: url('/browse/my-agent-01/fossil/images/bg.png'); }`
	if string(result) != want {
		t.Errorf("got  %q\nwant %q", string(result), want)
	}
}

func TestRewriteLocalURLs_BrowsePrefix_NoServicePrefix(t *testing.T) {
	// Browse prefix without service prefix: uses /browse/<agentID>/ as basePath.
	body := []byte(`<a href="/timeline">T</a>`)
	result := rewriteLocalURLs(body, "http://localhost:8080", "", "/browse/my-agent-01")
	want := `<a href="/browse/my-agent-01/timeline">T</a>`
	if string(result) != want {
		t.Errorf("got  %q\nwant %q", string(result), want)
	}
}

func TestIsStreamingResponse(t *testing.T) {
	tests := []struct {
		name string
		ct   string
		te   []string
		want bool
	}{
		{"SSE", "text/event-stream", nil, true},
		{"SSE with charset", "text/event-stream; charset=utf-8", nil, true},
		{"NDJSON", "application/x-ndjson", nil, true},
		{"stream+json", "application/stream+json", nil, true},
		{"chunked transfer", "application/json", []string{"chunked"}, true},
		{"plain JSON", "application/json", nil, false},
		{"HTML", "text/html", nil, false},
		{"binary", "application/octet-stream", nil, false},
		{"empty", "", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Header:           http.Header{"Content-Type": {tt.ct}},
				TransferEncoding: tt.te,
			}
			if got := isStreamingResponse(resp); got != tt.want {
				t.Errorf("isStreamingResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestForwardRoutes: the first path segment selects a named route (its
// prefix stripped), anything else the default route.
func TestForwardRoutes(t *testing.T) {
	rt, err := parseRoutes([]Route{{Backend: "http://default:80"}, {Prefix: "fossil", Backend: "http://localhost:8080"}, {Prefix: "gitea", Backend: "http://localhost:3000"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ url, prefix, target, path string }{
		{"fossil/repo/list", "fossil", "http://localhost:8080", "/repo/list"},
		{"gitea/user/repo", "gitea", "http://localhost:3000", "/user/repo"},
		{"fossil", "fossil", "http://localhost:8080", ""},
		{"unknown/page", "", "http://default:80", "unknown/page"},
		{"", "", "http://default:80", ""},
	} {
		got := rt.forward(c.url, nil)
		if got.prefix != c.prefix || got.targetBase != c.target || got.strippedPath != c.path {
			t.Errorf("forward(%q) = %+v, want prefix %q target %q path %q", c.url, got, c.prefix, c.target, c.path)
		}
	}
}

// A text body over the rewrite cap reaches the visitor whole, unrewritten,
// with its own length (it was once cut at the cap and ended cleanly).
func TestResponseBodyOverRewriteCapIsWhole(t *testing.T) {
	const size = maxRewriteBody + 1<<20
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": {"application/json"}},
		ContentLength: size,
		Body:          io.NopCloser(io.LimitReader(zeroReader{}, size)),
	}
	body, streaming, rewritten, err := responseBody(resp, resolvedForward{targetBase: "http://localhost:8080"}, "")
	if err != nil || streaming || rewritten {
		t.Fatalf("streaming=%v rewritten=%v err=%v, want neither and nil", streaming, rewritten, err)
	}
	n, err := io.Copy(io.Discard, body)
	if err != nil || n != size {
		t.Fatalf("visitor gets %d of %d bytes (err %v)", n, size, err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }
