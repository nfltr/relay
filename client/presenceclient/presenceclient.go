// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package presenceclient is the client of the relay presence API
// (nfltr.presence.v1: GET /api/v1/presence/agents and the
// /api/v1/presence/events long-poll). It names no task, worker or tenant and
// decides nothing: a woken caller re-reads its own inventory and its
// coordinator still chooses what runs where.
package presenceclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	spb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	presencev1 "github.com/nfltr/relay/proto/nfltr/presence/v1"
)

// Paths of the presence API.
const (
	AgentsPath = "/api/v1/presence/agents"
	EventsPath = "/api/v1/presence/events"
)

// MaxWait bounds one long-poll (the relay caps it at the same value).
const MaxWait = 25 * time.Second

// ErrUnsupported means the relay does not serve presence (404/405/501).
var ErrUnsupported = errors.New("relay presence API unsupported")

// Error is a typed relay error answer: the HTTP status and the
// nfltr.relay.v1.ErrorReason name from its google.rpc.ErrorInfo.
type Error struct {
	HTTPStatus int
	Reason     string
	Message    string
}

// Error implements error. allow:wrapper
func (e *Error) Error() string {
	return fmt.Sprintf("relay presence: HTTP %d %s: %s", e.HTTPStatus, e.Reason, e.Message)
}

// Get performs one authenticated relay GET of pathAndQuery. Each surface
// supplies its own base URL, credentials and HTTP client.
type Get func(ctx context.Context, pathAndQuery string) (body []byte, status int, err error)

var unmarshal = protojson.UnmarshalOptions{DiscardUnknown: true}

func call(ctx context.Context, get Get, pathAndQuery string, out proto.Message) error {
	body, status, err := get(ctx, pathAndQuery)
	switch {
	case err != nil:
		return err
	case status == http.StatusNotFound || status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented:
		return ErrUnsupported
	case status != http.StatusOK:
		return typedError(status, body)
	}
	if err := unmarshal.Unmarshal(body, out); err != nil {
		return fmt.Errorf("relay presence: malformed answer: %w", err)
	}
	return nil
}

func typedError(status int, body []byte) error {
	e := &Error{HTTPStatus: status, Message: string(body)}
	var st spb.Status
	if unmarshal.Unmarshal(body, &st) == nil {
		e.Message = st.GetMessage()
		for _, d := range st.GetDetails() {
			var info errdetails.ErrorInfo
			if d.UnmarshalTo(&info) == nil {
				e.Reason = info.GetReason()
			}
		}
	}
	return e
}

// List returns the agents the caller may reach whose labels equal every
// selector entry, and the feed cursor taken before the snapshot.
func List(ctx context.Context, get Get, selector map[string]string) (*presencev1.ListAgentsResponse, error) {
	q := url.Values{}
	for k, v := range selector {
		q.Set("selector["+k+"]", v)
	}
	path := AgentsPath
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var resp presencev1.ListAgentsResponse
	if err := call(ctx, get, path, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Watch performs one long-poll after cursor, waiting at most wait.
func Watch(ctx context.Context, get Get, cursor string, wait time.Duration) (*presencev1.WatchResponse, error) {
	q := url.Values{"cursor": {cursor}, "wait_ms": {strconv.FormatInt(max(min(wait, MaxWait).Milliseconds(), 0), 10)}}
	var resp presencev1.WatchResponse
	if err := call(ctx, get, EventsPath+"?"+q.Encode(), &resp); err != nil {
		return nil, err
	}
	if resp.GetCursor() == "" {
		return nil, errors.New("relay presence: answer without a cursor")
	}
	return &resp, nil
}

// Wait returns the relay's current cursor at once when cursor is empty (the
// baseline to take before reading inventory). Otherwise it blocks until the
// relay reports a presence change (or a reset) after cursor and returns the
// new cursor, or ctx ends (cursor, ctx.Err()), or the feed fails (cursor,
// err).
func Wait(ctx context.Context, get Get, cursor string) (string, error) {
	for {
		wait := time.Duration(0)
		if cursor != "" {
			wait = MaxWait
			if deadline, ok := ctx.Deadline(); ok {
				wait = min(wait, time.Until(deadline))
			}
			if wait <= 0 {
				return cursor, context.DeadlineExceeded
			}
		}
		resp, err := Watch(ctx, get, cursor, wait)
		if ctx.Err() != nil {
			return cursor, ctx.Err()
		}
		if err != nil {
			return cursor, err
		}
		if cursor == "" || len(resp.GetEvents()) > 0 || resp.GetReset_() {
			return resp.GetCursor(), nil
		}
		cursor = resp.GetCursor()
	}
}
