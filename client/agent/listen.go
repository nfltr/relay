// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"net"
)

// Listen connects an agent for cfg (New and Connect with opts) and returns
// a net.Listener for the HTTP requests visitors send it through the relay,
// to serve with http.Serve:
//
//	ln, err := agent.Listen(ctx, agent.Config{
//	    ServerAddr: "rpc.example.com:443", AgentID: "my-app", APIKey: key, TLS: true,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	log.Fatal(http.Serve(ln, handler))
//
// The listener is the agent's only backend: a loopback TCP port (Addr) the
// agent forwards each request to, as it forwards to any Route's Backend, so
// cfg.Routes must be nil. Closing the listener stops the agent; once the
// agent stopped with an error (Err), Accept returns it.
func Listen(ctx context.Context, cfg Config, opts ...Option) (net.Listener, error) {
	if cfg.Routes != nil {
		return nil, errors.New("agent.Listen: cfg.Routes must be nil (the listener is the backend)")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	cfg.Routes = []Route{{Backend: "http://" + ln.Addr().String()}}
	a := New(cfg, opts...)
	if err := a.Connect(ctx); err != nil {
		_ = ln.Close()
		return nil, err
	}
	go func() { <-a.Done(); _ = ln.Close() }()
	return &relayListener{Listener: ln, agent: a}, nil
}

type relayListener struct {
	net.Listener
	agent Agent
}

func (l *relayListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		select {
		case <-l.agent.Done():
			if aerr := l.agent.Err(); aerr != nil {
				return nil, aerr
			}
		default:
		}
	}
	return c, err
}

func (l *relayListener) Close() error {
	l.agent.Close()
	return l.Listener.Close()
}
