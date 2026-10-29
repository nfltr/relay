// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/nfltr/relay/proto/wire/turnwire"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CallServer is a local HTTP + WebSocket server that bridges a browser
// to the remote CLI for WebRTC signaling and text chat.
//
// Architecture:
//
//	Browser ←WS→ CallServer ←FrameRTC/FrameChat→ SignalConn ←→ remote peer
//
// Media flows directly via WebRTC (browser-to-browser) once signaling
// completes.  The CallServer only relays signaling and text-chat frames.
// FrameConn carries a call's signaling frames between the two CLIs (a
// SignalConn: relay stream, plus the direct TCP channel once it connects).
type FrameConn interface {
	WriteFrame(*Frame) error
	ReadFrame() (*Frame, error)
}

type CallServer struct {
	sig      FrameConn     // signaling to the remote CLI
	listener net.Listener  // 127.0.0.1:<random>
	token    string        // random token for URL auth
	role     string        // "initiator" or "responder"
	stun     string        // STUN server URL for the browser
	htmlFunc func() string // returns the call.html page

	// TURN servers the page adds to its ICE servers beside STUN; nil means
	// none. Set before Run; validated with ValidateICEServers by the caller.
	TURN []turnwire.ICEServer

	// Browser WebSocket (set once browser connects).
	wsMu      sync.Mutex
	ws        *wsConn
	wsDone    chan struct{} // closed when browser WS disconnects
	peerReady bool          // set if FrameRTCReady arrived before browser WS
	pending   [][]byte      // frames received before browser WS connected

	// Shutdown coordination.
	shutdownOnce sync.Once
	done         chan struct{}
}

// NewCallServer creates a CallServer bound to 127.0.0.1 with a random port.
// sig carries the signaling frames to the remote peer's CallServer.
// role is "initiator" or "responder".
// stunServer is the STUN server URL (e.g. "stun.l.google.com:19302").
// htmlFunc returns the HTML page content to serve.
func NewCallServer(sig FrameConn, role, stunServer string, htmlFunc func() string) (*CallServer, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("p2p call: listen: %w", err)
	}

	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		ln.Close() //nolint:errcheck
		return nil, fmt.Errorf("p2p call: generate token: %w", err)
	}

	return &CallServer{
		sig:      sig,
		listener: ln,
		token:    hex.EncodeToString(tokenBytes),
		role:     role,
		stun:     stunServer,
		htmlFunc: htmlFunc,
		wsDone:   make(chan struct{}),
		done:     make(chan struct{}),
	}, nil
}

// URL returns the localhost URL with auth token that should be opened
// in the browser.
func (s *CallServer) URL() string {
	return fmt.Sprintf("http://%s/?token=%s&role=%s", s.listener.Addr(), s.token, s.role)
}

// Run starts the HTTP server and blocks until the call ends (hangup,
// context cancellation, or the signaling ending).  The caller should
// open the browser before or after calling Run.
func (s *CallServer) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handlePage)
	mux.HandleFunc("/ws", s.handleWS)

	srv := &http.Server{
		Handler:     mux,
		ReadTimeout: 30 * time.Second,
	}

	// Start HTTP server.
	srvErr := make(chan error, 1)
	go func() {
		srvErr <- srv.Serve(s.listener)
	}()

	// Start the peer→WS bridge (signaling frames from the peer to the browser).
	go s.bridgePeerToWS()

	// Wait for shutdown trigger.
	select {
	case <-ctx.Done():
	case <-s.done:
	case err := <-srvErr:
		if err != nil && err != http.ErrServerClosed {
			slog.Error("call server error", "err", err)
		}
	}

	// Graceful shutdown.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)

	s.wsMu.Lock()
	if s.ws != nil {
		_ = s.ws.Close()
	}
	s.wsMu.Unlock()

	return nil
}

// Close triggers shutdown of the call server.
func (s *CallServer) Close() {
	s.shutdownOnce.Do(func() {
		close(s.done)
	})
}

// handlePage serves the call HTML page.
func (s *CallServer) handlePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("token") != s.token {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	html := s.htmlFunc()
	// Inject STUN server URL and TURN servers (base64 JSON: safe inside the
	// page's quoted JS string; empty means no TURN).
	html = strings.ReplaceAll(html, "{{STUN_SERVER}}", s.stun)
	turn := ""
	if len(s.TURN) > 0 {
		b, _ := json.Marshal(s.TURN)
		turn = base64.StdEncoding.EncodeToString(b)
	}
	html = strings.ReplaceAll(html, "{{TURN_SERVERS}}", turn)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, html)
}

// handleWS upgrades to WebSocket and starts the WS→peer bridge.
func (s *CallServer) handleWS(w http.ResponseWriter, r *http.Request) {
	// Validate token.
	if r.URL.Query().Get("token") != s.token {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Validate Origin (prevent DNS rebinding attacks).
	origin := r.Header.Get("Origin")
	if origin != "" {
		expected := fmt.Sprintf("http://%s", s.listener.Addr())
		if origin != expected {
			http.Error(w, "Origin mismatch", http.StatusForbidden)
			return
		}
	}

	ws, err := upgradeWS(w, r)
	if err != nil {
		slog.Error("ws upgrade failed", "err", err)
		return
	}

	s.wsMu.Lock()
	if s.ws != nil {
		// Only one browser connection allowed.
		s.wsMu.Unlock()
		_ = ws.Close()
		return
	}
	s.ws = ws
	s.wsMu.Unlock()

	// Notify remote peer that our browser is ready.
	_ = s.sig.WriteFrame(&Frame{Type: FrameRTCReady})

	// Deliver any frames that arrived before the browser connected.
	s.wsMu.Lock()
	if s.peerReady {
		_ = ws.WriteMessage(wsOpText, []byte(`{"type":"peer-ready"}`))
	}
	for _, p := range s.pending {
		_ = ws.WriteMessage(wsOpText, p)
	}
	s.pending = nil
	s.wsMu.Unlock()

	// WS→peer bridge: read from the browser WebSocket, send to the peer.
	defer func() {
		close(s.wsDone)
		s.Close()
	}()
	for {
		opcode, payload, err := ws.ReadMessage()
		if err != nil {
			return
		}
		if opcode == wsOpClose {
			return
		}

		text := string(payload)

		// Check for hangup from browser.
		if strings.Contains(text, `"type":"hangup"`) {
			_ = s.sig.WriteFrame(&Frame{Type: FrameDone})
			return
		}

		// Check if it's a chat message.
		if strings.Contains(text, `"type":"chat"`) {
			_ = s.sig.WriteFrame(&Frame{Type: FrameChat, Text: text})
			continue
		}

		// All other messages are WebRTC signaling (SDP/ICE).
		_ = s.sig.WriteFrame(&Frame{Type: FrameRTC, Text: text})
	}
}

// bridgePeerToWS reads the peer's signaling frames and forwards them to the
// browser WebSocket.
func (s *CallServer) bridgePeerToWS() {
	defer s.Close()
	// However the peer leaves (FrameDone, or its connection closing first, as
	// when its process exits before a relayed FrameDone arrives), the page
	// hears the call ended instead of waiting on a dead call.
	defer func() {
		s.wsMu.Lock()
		ws := s.ws
		s.wsMu.Unlock()
		if ws != nil {
			_ = ws.WriteMessage(wsOpText, []byte(`{"type":"hangup"}`))
		}
	}()
	for {
		f, err := s.sig.ReadFrame()
		if err != nil {
			return
		}

		switch f.Type {
		case FrameRTC, FrameChat:
			s.wsMu.Lock()
			ws := s.ws
			if ws == nil {
				// Buffer until browser connects.
				s.pending = append(s.pending, []byte(f.Text))
			}
			s.wsMu.Unlock()
			if ws != nil {
				_ = ws.WriteMessage(wsOpText, []byte(f.Text))
			}

		case FrameRTCReady:
			// Remote browser is ready — tell our browser.
			s.wsMu.Lock()
			ws := s.ws
			if ws == nil {
				s.peerReady = true
			}
			s.wsMu.Unlock()
			if ws != nil {
				_ = ws.WriteMessage(wsOpText, []byte(`{"type":"peer-ready"}`))
			}

		case FrameDone: // remote hung up
			return
		}
	}
}
