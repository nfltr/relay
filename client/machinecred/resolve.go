// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package machinecred

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nfltr/relay/client/relayoutage"
)

// MachineFunc is the machine id of machine name of the caller's account;
// "" name: the caller's own machine.
type MachineFunc func(ctx context.Context, name string) (string, error)

// ErrNoMachine: the account has no machine of the name (the relay's 404).
var ErrNoMachine = errors.New("no machine of that name in this account")

// Machines is a MachineFunc over the relay's HTTP API at base, as the
// machine whose certificate hc presents (hc nil: a 30 s client that waits
// out a relay outage).
func Machines(base string, hc *http.Client) MachineFunc {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second, Transport: relayoutage.Throttled(nil)}
	}
	return func(ctx context.Context, name string) (string, error) {
		u := strings.TrimRight(base, "/") + "/api/v1/machines/resolve"
		if name != "" {
			u += "?name=" + url.QueryEscape(name)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close() //nolint:errcheck
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode == http.StatusNotFound && name != "" {
			return "", fmt.Errorf("machine %q: %w (HTTP 404: %s)", name, ErrNoMachine, strings.TrimSpace(string(data)))
		}
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("machine %q: HTTP %d: %s", name, resp.StatusCode, strings.TrimSpace(string(data)))
		}
		var out struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(data, &out); err != nil || out.ID == "" {
			return "", fmt.Errorf("machine %q: the relay named no machine id", name)
		}
		return out.ID, nil
	}
}
