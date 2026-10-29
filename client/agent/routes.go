// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// routeTable maps a path prefix (e.g., "api") to a backend URL.
// The empty-string key "" is the default/fallback route.
type routeTable map[string]*url.URL

// parseRoutes converts []Route into a routeTable, validating each backend URL.
func parseRoutes(routes []Route) (routeTable, error) {
	t := make(routeTable, len(routes))
	for _, r := range routes {
		if r.Backend == "" {
			return nil, fmt.Errorf("route with prefix %q has empty Backend", r.Prefix)
		}
		u, err := url.Parse(r.Backend)
		if err != nil {
			return nil, fmt.Errorf("route %q: invalid backend URL %q: %w", r.Prefix, r.Backend, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("route %q: backend URL must use http or https, got %q", r.Prefix, u.Scheme)
		}
		t[r.Prefix] = u
	}
	return t, nil
}

// RouteNames returns a comma-separated list of non-default route prefixes.
// This is sent to the server in the x-routes metadata header so the server
// knows which named routes this agent handles.
func (rt routeTable) routeNames() string {
	var names []string
	for k := range rt {
		if k != "" {
			names = append(names, k)
		}
	}
	return strings.Join(names, ",")
}

// defaultRoute returns the default (fallback) route entry, or nil if none.
type routeEntry struct {
	prefix  string
	backend *url.URL
}

func (rt routeTable) defaultRoute() *routeEntry {
	if u, ok := rt[""]; ok {
		return &routeEntry{prefix: "", backend: u}
	}
	return nil
}

// resolvedForward holds the forwarding target for a single incoming request.
type resolvedForward struct {
	// targetBase is the backend base URL (e.g. "http://localhost:3000")
	targetBase string
	// strippedPath is the request URL with the matched prefix removed.
	// This is passed as the path component to the backend.
	strippedPath string
	// prefix is the matched route prefix (empty for the default route).
	prefix string
	// rewriteHost sends the backend its own host (Config.RewriteHost).
	rewriteHost bool
}

// SplitRoute splits a relay request URL (no leading "/", e.g.
// "api/users?x=1") into its first path segment, which names a route, and
// the rest ("/users?x=1", or "?x=1"), which a named route forwards.
func SplitRoute(reqURL string) (first, rest string) {
	if i := strings.IndexAny(reqURL, "/?"); i >= 0 {
		return reqURL[:i], reqURL[i:]
	}
	return reqURL, ""
}

// TargetURL is the backend URL for a request: rel (its path and query,
// with a route's prefix already stripped) appended to the backend URL's own
// path, so a route to http://host/github sends rel "/tasks" to
// http://host/github/tasks. rel's query replaces the backend's.
func TargetURL(backend, rel string) (string, error) {
	u, err := url.Parse(backend)
	if err != nil {
		return "", fmt.Errorf("parse backend URL %q: %w", backend, err)
	}
	if rel == "" {
		return u.String(), nil
	}
	if !strings.HasPrefix(rel, "/") && !strings.HasPrefix(rel, "?") {
		rel = "/" + rel // the default route's whole path; never read as a scheme
	}
	r, err := url.Parse(rel)
	if err != nil {
		return "", fmt.Errorf("parse request path %q: %w", rel, err)
	}
	u.RawPath = strings.TrimRight(u.EscapedPath(), "/") + r.EscapedPath()
	if u.Path, err = url.PathUnescape(u.RawPath); err != nil {
		return "", fmt.Errorf("parse request path %q: %w", rel, err)
	}
	u.RawQuery, u.Fragment, u.RawFragment = r.RawQuery, "", ""
	return u.String(), nil
}

// forward computes the full forwarding details for reqURL.
func (rt routeTable) forward(reqURL string, service []string) resolvedForward {
	// A request the relay names a service for (agentservices.RequestHeader,
	// a services agent's share) goes to that route, at its root.
	if len(service) > 0 {
		if u, ok := rt[service[0]]; ok && service[0] != "" && len(service) == 1 {
			return resolvedForward{targetBase: strings.TrimRight(u.String(), "/"), strippedPath: reqURL}
		}
		return resolvedForward{strippedPath: reqURL}
	}
	firstSeg, rest := SplitRoute(reqURL)

	if u, ok := rt[firstSeg]; ok && firstSeg != "" {
		return resolvedForward{
			prefix:       firstSeg,
			targetBase:   strings.TrimRight(u.String(), "/"),
			strippedPath: rest,
		}
	}

	// Default route.
	if def, ok := rt[""]; ok {
		return resolvedForward{
			targetBase:   strings.TrimRight(def.String(), "/"),
			strippedPath: reqURL,
		}
	}

	return resolvedForward{strippedPath: reqURL}
}

// splitHostPort splits an address of the form "host:port" into its components.
// Returns an error when the address is malformed or the port is non-numeric.
func splitHostPort(addr string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid server address %q: %w", addr, err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port in server address %q: %w", addr, err)
	}
	return h, n, nil
}
