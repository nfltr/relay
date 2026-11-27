// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"fmt"
	"maps"
	"sync"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentwire"
)

// ErrLabelUpdatesUnsupported: the relay of the agent's current connection
// does not apply label updates (no agentwire.LabelUpdatesKey in its accept).
var ErrLabelUpdatesUnsupported = errors.New("agent: the relay does not apply label updates: update the relay")

// labelUpdates is the agent's label update set (SetLabels) and the
// ConnectHTTP stream it goes on: the newest accepted one (a move's new
// stream once it is up). Each stream gets the whole set, so a reconnect
// resends it and a resend changes nothing.
type labelUpdates struct {
	mu        sync.Mutex
	set       map[string]string
	gen       int                               // the current stream's attach
	connected bool                              // a stream is current
	send      func(*pb.HTTPProxyResponse) error // the current stream's; nil when its relay applies none
}

func labelFrame(set map[string]string) *pb.HTTPProxyResponse {
	return &pb.HTTPProxyResponse{Labels: &pb.LabelUpdate{Labels: set}}
}

// SetLabels implements Agent.
func (a *agent) SetLabels(labels map[string]string) error {
	if err := agentwire.CheckLabelUpdate(labels); err != nil {
		return err
	}
	l := &a.labelUpdates
	l.mu.Lock()
	defer l.mu.Unlock()
	l.set = maps.Clone(labels)
	switch {
	case !l.connected:
		return nil // sent when a stream is accepted
	case l.send == nil:
		return ErrLabelUpdatesUnsupported
	}
	if err := l.send(labelFrame(l.set)); err != nil {
		return fmt.Errorf("agent: send label update: %w", err) // the next stream gets the set
	}
	return nil
}

// attach makes a newly accepted stream the one updates go on, sending it
// the set when its relay applies updates (applies); detach, when the
// stream ended, unless a newer one attached since.
func (l *labelUpdates) attach(send func(*pb.HTTPProxyResponse) error, applies bool) (detach func(), err error) {
	if l == nil {
		return func() {}, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gen++
	gen := l.gen
	l.connected, l.send = true, nil
	if applies {
		l.send = send
		if len(l.set) > 0 {
			err = send(labelFrame(l.set))
		}
	}
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.gen == gen {
			l.connected, l.send = false, nil
		}
	}, err
}
