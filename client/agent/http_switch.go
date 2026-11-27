// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
)

// switchWatch follows the responses of an HTTP/1 session the agent reads
// the requests of (the identity rewriter, the E2EE stream path) and tells
// the request side whether the app switched protocols. A session goes on
// as bytes only after the app's 101 to an upgrade or a 2xx to a CONNECT
// (RFC 9110 sections 7.8 and 9.3.6): an app that ignores an Upgrade
// header and answers keeps the connection HTTP, and its next request is
// read (and rewritten) as one (svc_access.pv README "every request of a
// session is rewritten until the app switches protocol").
//
// The request side calls expect before it writes each request, then
// switched; the response side passes each write to the client to seen
// once it was written, and end at the app's end. Responses reach the
// client as the app wrote them: the watch reads a copy.
type switchWatch struct {
	pw   *io.PipeWriter
	reqs chan watchedReq
	off  atomic.Bool   // the watch ended: seen copies nothing
	done chan struct{} // closed when the watch ends
}

type watchedReq struct {
	method   string
	switched chan bool // nil when the request asked for no switch
}

// watchQueue bounds the requests written that the app has not answered:
// expect waits beyond it (they were all written, so the app can answer).
const watchQueue = 64

var errWatchEnded = errors.New("switch watch ended")

func newSwitchWatch() *switchWatch {
	pr, pw := io.Pipe()
	w := &switchWatch{pw: pw, reqs: make(chan watchedReq, watchQueue), done: make(chan struct{})}
	go w.follow(pr)
	return w
}

// expect queues req, before it is written. It returns what switched
// waits on: nil for a request that asks for no switch.
func (w *switchWatch) expect(req *http.Request) chan bool {
	r := watchedReq{method: req.Method}
	if req.Method == http.MethodConnect || req.Header.Get("Upgrade") != "" {
		r.switched = make(chan bool, 1)
	}
	select {
	case w.reqs <- r:
	case <-w.done:
		return nil // no switch is ever seen again
	}
	return r.switched
}

// switched waits for the app's final answer to the request expect
// returned ch for: true only when it switched protocols.
func (w *switchWatch) switched(ch chan bool) bool {
	if ch == nil {
		return false
	}
	select {
	case s := <-ch:
		return s
	case <-w.done:
		select { // follow answers before it ends
		case s := <-ch:
			return s
		default:
			return false
		}
	}
}

// requestsEnd is the request side's end: no expect follows.
func (w *switchWatch) requestsEnd() { close(w.reqs) }

// seen is p, written to the client.
func (w *switchWatch) seen(p []byte) {
	if !w.off.Load() {
		_, _ = w.pw.Write(p) // an error: the watch ended
	}
}

// end is the app's end.
func (w *switchWatch) end() { _ = w.pw.Close() }

// follow reads the responses, each to the request queued before it. It
// ends at a switch, at the app's end or at bytes that answer no request
// (an app that is not HTTP/1, or not keeping to it): after those, no
// request switches.
func (w *switchWatch) follow(pr *io.PipeReader) {
	defer close(w.done)
	defer func() {
		w.off.Store(true)
		_ = pr.CloseWithError(errWatchEnded) // a seen waiting on the pipe returns
	}()
	br := bufio.NewReader(pr)
	for {
		if _, err := br.Peek(1); err != nil {
			return
		}
		var r watchedReq
		select {
		case q, ok := <-w.reqs:
			if !ok {
				return
			}
			r = q
		default:
			return // a response before its request was written: not one
		}
		sw, err := switchedBy(br, r.method)
		if r.switched != nil {
			r.switched <- sw && err == nil
		}
		if sw || err != nil {
			return
		}
	}
}

// switchedBy reads from br the answers to a request of method: its
// interim responses, then its final one, body included. True for a
// switch (101, or a 2xx to CONNECT), after which br is another protocol.
func switchedBy(br *bufio.Reader, method string) (bool, error) {
	req := &http.Request{Method: method}
	for {
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			return false, err
		}
		switch {
		case resp.StatusCode == http.StatusSwitchingProtocols,
			method == http.MethodConnect && resp.StatusCode/100 == 2:
			return true, nil
		case resp.StatusCode/100 == 1: // 100 Continue, 103: the final answer follows
			continue
		}
		_, err = io.Copy(io.Discard, resp.Body)
		return false, err
	}
}

// watchedWriter is a session's writer to the client whose writes w sees.
type watchedWriter struct {
	io.Writer
	w *switchWatch
}

func (c watchedWriter) Write(p []byte) (int, error) {
	n, err := c.Writer.Write(p)
	c.w.seen(p[:n])
	return n, err
}
