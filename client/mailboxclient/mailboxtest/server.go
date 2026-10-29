// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package mailboxtest is an in-memory stand-in for the relay's mailbox
// routes (append, pull with a short long-poll, ack) for client tests. The
// relay's own contract test pins the real server to the same client.
package mailboxtest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	mailboxv1 "github.com/nfltr/relay/proto/nfltr/mailbox/v1"
)

// Server holds one owner's mailboxes.
type Server struct {
	URL   string
	Owner string

	mu    sync.Mutex
	boxes map[string][]*mailboxv1.Envelope
	seq   map[string]uint64
}

// New serves an empty owner's mailboxes until the test ends.
func New(t *testing.T, owner string) *Server {
	s := &Server{Owner: owner, boxes: map[string][]*mailboxv1.Envelope{}, seq: map[string]uint64{}}
	srv := httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(srv.Close)
	s.URL = srv.URL
	return s
}

// Put appends payload as sent by sender (of kind).
func (s *Server) Put(mailbox string, kind mailboxv1.SenderKind, sender string, payload []byte) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq[mailbox]++
	s.boxes[mailbox] = append(s.boxes[mailbox], &mailboxv1.Envelope{Seq: s.seq[mailbox], SenderKind: kind, Sender: sender, Payload: payload, AppendedAt: timestamppb.Now()})
	return s.seq[mailbox]
}

// Queued is the mailbox's unacknowledged envelopes.
func (s *Server) Queued(mailbox string) []*mailboxv1.Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*mailboxv1.Envelope(nil), s.boxes[mailbox]...)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	rest, _ := strings.CutPrefix(r.URL.Path, "/api/v1/mailboxes/")
	name, verb, _ := strings.Cut(rest, "/")
	body, _ := io.ReadAll(r.Body)
	reply := func(m proto.Message) {
		w.Header().Set("Content-Type", "application/json")
		data, _ := protojson.Marshal(m)
		_, _ = w.Write(data)
	}
	switch verb {
	case "messages":
		var in mailboxv1.AppendMessageRequest
		if protojson.Unmarshal(body, &in) != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		reply(&mailboxv1.AppendMessageResponse{Seq: s.Put(name, mailboxv1.SenderKind_SENDER_KIND_API_KEY, s.Owner, in.GetPayload()), Owner: s.Owner})
	case "messages:pull":
		var in mailboxv1.PullMessagesRequest
		_ = protojson.Unmarshal(body, &in)
		deadline := time.Now().Add(min(in.GetWait().AsDuration(), time.Second))
		for {
			var out []*mailboxv1.Envelope
			for _, e := range s.Queued(name) {
				if e.GetSeq() > in.GetAfterSeq() {
					out = append(out, e)
				}
			}
			if len(out) > 0 || !time.Now().Before(deadline) {
				reply(&mailboxv1.PullMessagesResponse{Envelopes: out, Owner: s.Owner})
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	case "messages:ack":
		var in mailboxv1.AckMessagesRequest
		_ = protojson.Unmarshal(body, &in)
		s.mu.Lock()
		kept := s.boxes[name][:0]
		for _, e := range s.boxes[name] {
			if e.GetSeq() > in.GetThroughSeq() {
				kept = append(kept, e)
			}
		}
		s.boxes[name] = kept
		s.mu.Unlock()
		reply(&mailboxv1.AckMessagesResponse{})
	default:
		http.NotFound(w, r)
	}
}
