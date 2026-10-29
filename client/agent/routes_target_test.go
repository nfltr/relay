// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import "testing"

// A named route strips its prefix and keeps the backend URL's own path
// (developer-day demo gap 3: `--route /github=http://host/github` sent
// `/github/tasks` to `/tasks`); the default route forwards the whole path
// under its backend's path.
func TestRoutedTargetURL(t *testing.T) {
	rt, err := parseRoutes([]Route{
		{Backend: "http://localhost:8080"},
		{Prefix: "api", Backend: "http://localhost:3000"},
		{Prefix: "github", Backend: "http://hooks.local:9000/github"},
		{Prefix: "v1", Backend: "http://h/base/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	app, _ := parseRoutes([]Route{{Backend: "http://h/app"}})
	for req, want := range map[string]string{
		"github":             "http://hooks.local:9000/github",
		"github/":            "http://hooks.local:9000/github/",
		"github/tasks":       "http://hooks.local:9000/github/tasks",
		"github/tasks/1?x=1": "http://hooks.local:9000/github/tasks/1?x=1",
		"github?x=1":         "http://hooks.local:9000/github?x=1",
		"api/users":          "http://localhost:3000/users",
		"v1/items":           "http://h/base/items",
		"index.html":         "http://localhost:8080/index.html",
		"":                   "http://localhost:8080",
		"a%2Fb/c":            "http://localhost:8080/a%2Fb/c",
		"x:y/z":              "http://localhost:8080/x:y/z",
	} {
		fwd := rt.forward(req, nil)
		got, err := TargetURL(fwd.targetBase, fwd.strippedPath)
		if err != nil || got != want {
			t.Errorf("%q -> %q, %v; want %q", req, got, err, want)
		}
	}
	fwd := app.forward("static/x.css", nil)
	if got, _ := TargetURL(fwd.targetBase, fwd.strippedPath); got != "http://h/app/static/x.css" {
		t.Errorf("default route with a path: %q", got)
	}
}
