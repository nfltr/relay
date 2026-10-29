// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build conformance

package wg

// WireGuard interop harness for the protocol conformance suite
// (tests/conformance/protocols/wg/run.sh, make conformance-protocols).
//
// nfltr's tunnels speak WireGuard over RelayBind, never UDP: the relay
// carries the sealed packets. TestWGInteropPeer stands in for the relay with
// a UDP socket, so a stock peer (kernel WireGuard, wireguard-go) sees plain
// WireGuard on the wire while nfltr's own tunnel code (NewTunnel or
// NewForwardingTunnel, buildIPC, RelayBind, PresharedKeyFromFile) runs
// unchanged on the other side. The bridge forwards every sealed packet to the
// stock peer's last source address, as the relay forwards to the current
// session, and tags inbound packets with the stock peer's key.
//
// Env: WG_INTEROP_ROLE client|exit, WG_PRIVATE_KEY, WG_PEER_PUBLIC_KEY (the
// stock peer), WG_PSK_FILE (pairing key file, optional), WG_LOCAL_ADDR,
// WG_PEER_ADDR (stock tunnel address; exit: the client's /32),
// WG_PEER_ENDPOINT (client: stock UDP endpoint), WG_UDP_LISTEN (:51900),
// WG_CONTROL (:9000), WG_ALLOW and WG_LAN (exit: allow-list entry, and the
// host the LAN servers bind on :8080 allowed / :8081 not).
//
// Control (plain HTTP on the real network, for run.sh): /status (last
// handshake, rx bytes), /get?url= (client: GET through the tunnel, answers
// "<len> <sha256>"), /rehandshake, /pub?key= (PublicKeyFromPrivate),
// /psk?file= (PresharedKeyFromFile), /blobsum (sha256 of /blob).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// interopBlob is what the nfltr side serves at /blob: 4 MiB, deterministic,
// so a multi-packet transfer both ways is checked by its digest.
var interopBlob = func() []byte {
	b := make([]byte, 4<<20)
	for i := range b {
		b[i] = byte(i*7 + i>>13)
	}
	return b
}()

func interopEnv(t *testing.T, k string) string {
	v := os.Getenv(k)
	if v == "" {
		t.Fatalf("%s is required", k)
	}
	return v
}

func TestWGInteropPeer(t *testing.T) {
	role := os.Getenv("WG_INTEROP_ROLE")
	if role == "" {
		t.Skip("WG_INTEROP_ROLE unset: run by tests/conformance/protocols/wg/run.sh")
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	peer := interopEnv(t, "WG_PEER_PUBLIC_KEY")
	cfg := TunnelConfig{PrivateKey: interopEnv(t, "WG_PRIVATE_KEY"), LocalAddress: netip.MustParseAddr(interopEnv(t, "WG_LOCAL_ADDR"))}
	if f := os.Getenv("WG_PSK_FILE"); f != "" {
		psk, err := PresharedKeyFromFile(f)
		if err != nil {
			t.Fatal(err)
		}
		cfg.PresharedKey = psk
	}
	peerAddr := netip.MustParseAddr(interopEnv(t, "WG_PEER_ADDR"))

	udp, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("0.0.0.0"+os.Getenv("WG_UDP_LISTEN"))))
	if err != nil {
		t.Fatal(err)
	}
	var last atomic.Pointer[netip.AddrPort]
	if ep := os.Getenv("WG_PEER_ENDPOINT"); ep != "" {
		a := netip.MustParseAddrPort(ep)
		last.Store(&a)
	}

	bind := NewRelayBind()
	var tun Tunnel
	switch role {
	case "client":
		cfg.PeerPublicKey = peer
		cfg.AllowedIPs = []netip.Prefix{netip.PrefixFrom(peerAddr, 32)}
		tun = NewTunnel(logger)
	case "exit":
		allow, err := ParseDestinationPolicy([]string{interopEnv(t, "WG_ALLOW")}, nil)
		if err != nil {
			t.Fatal(err)
		}
		tun = NewForwardingTunnel(logger, allow)
	default:
		t.Fatalf("WG_INTEROP_ROLE=%s: want client or exit", role)
	}
	if err := tun.Start(context.Background(), cfg, bind); err != nil {
		t.Fatal(err)
	}
	defer tun.Close() //nolint:errcheck
	if role == "exit" {
		if err := tun.AddPeer(peer, peerAddr); err != nil {
			t.Fatal(err)
		}
	}

	// The relay stand-in: sealed packets out to the stock peer's last
	// address, and in from wherever it sends them now (its roaming).
	go func() {
		for {
			for pkt := range bind.Outbound() {
				if a := last.Load(); a != nil {
					_, _ = udp.WriteToUDPAddrPort(pkt.Data, *a)
				}
			}
			time.Sleep(10 * time.Millisecond) // the device reopened the bind
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := udp.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			last.Store(&from)
			_ = bind.Deliver(peer, buf[:n])
		}
	}()

	blob := http.NewServeMux()
	blob.HandleFunc("/blob", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(interopBlob) })
	blob.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "NFLTR-NETSTACK-OK\n") })
	var client *http.Client
	switch role {
	case "client":
		ln, err := tun.Net().ListenTCPAddrPort(netip.AddrPortFrom(cfg.LocalAddress, 8000))
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = http.Serve(ln, blob) }()
		client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: tun.Net().DialContext}}
	case "exit":
		lan := interopEnv(t, "WG_LAN")
		allowed := http.NewServeMux()
		allowed.HandleFunc("/blob", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(interopBlob) })
		allowed.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "WG-ALLOWED\n") })
		go func() { t.Error(http.ListenAndServe(lan+":8080", allowed)) }()
		go func() {
			t.Error(http.ListenAndServe(lan+":8081", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "WG-NOT-ALLOWED\n")
			})))
		}()
	}

	ctl := http.NewServeMux()
	ctl.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		st, err := tun.PeerStatus(peer)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var hs int64
		if !st.LastHandshake.IsZero() {
			hs = st.LastHandshake.Unix()
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"last_handshake": hs, "rx_bytes": st.RxBytes})
	})
	ctl.HandleFunc("/rehandshake", func(w http.ResponseWriter, _ *http.Request) {
		if err := tun.Rehandshake(peer); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	ctl.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
		if client == nil {
			http.Error(w, "client role only", http.StatusBadRequest)
			return
		}
		resp, err := client.Get(r.URL.Query().Get("url"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close() //nolint:errcheck
		h := sha256.New()
		n, err := io.Copy(h, resp.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		fmt.Fprintf(w, "%d %s\n", n, hex.EncodeToString(h.Sum(nil)))
	})
	ctl.HandleFunc("/blobsum", func(w http.ResponseWriter, _ *http.Request) {
		s := sha256.Sum256(interopBlob)
		fmt.Fprintf(w, "%d %s\n", len(interopBlob), hex.EncodeToString(s[:]))
	})
	ctl.HandleFunc("/pub", func(w http.ResponseWriter, r *http.Request) {
		pub, err := PublicKeyFromPrivate(r.URL.Query().Get("key"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fmt.Fprintln(w, pub)
	})
	ctl.HandleFunc("/psk", func(w http.ResponseWriter, r *http.Request) {
		psk, err := PresharedKeyFromFile(r.URL.Query().Get("file"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fmt.Fprintln(w, psk)
	})
	logger.Info("wg interop harness ready", "role", role, "udp", udp.LocalAddr(), "paired", cfg.PresharedKey != "")
	t.Fatal(http.ListenAndServe(interopEnv(t, "WG_CONTROL"), ctl))
}
