// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package wg

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// forwardTUN is a gvisor-based TUN device that intercepts all incoming TCP
// connections via gvisor's TCP forwarder and proxies them to the real network.
// This is used by the "wg serve" agent to forward tunnel traffic to LAN
// destinations without needing explicit port listeners.
type forwardTUN struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan tun.Event
	notifyHandle   *channel.NotificationHandle
	incomingPacket chan *buffer.View
	// closed ends Read and a WriteNotify blocked on incomingPacket; the
	// stack's goroutines may still call WriteNotify while Close runs, so
	// incomingPacket itself is never closed (a send on it would panic).
	closed chan struct{}
	mtu    int
	once   sync.Once
}

// CreateForwardingTUN creates a gvisor TUN that intercepts all incoming TCP
// connections and proxies each to the real network. Unlike netstack.CreateNetTUN,
// this installs a TCP forwarder at the stack level so no explicit listeners are
// needed — any destination address:port combination is accepted and forwarded.
//
// allow is the set of destinations connections may reach; every other
// destination is refused (TCP RST, UDP dropped) and logged.
func CreateForwardingTUN(localAddr netip.Addr, mtu int, allow DestinationPolicy, logger *slog.Logger) (tun.Device, error) {
	opts := stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocolWithOptions(ipv4.Options{
				AllowExternalLoopbackTraffic: true,
			}),
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4},
		HandleLocal:        false,
	}

	dev := &forwardTUN{
		ep:             channel.New(1024, uint32(mtu), ""),
		stack:          stack.New(opts),
		events:         make(chan tun.Event, 10),
		incomingPacket: make(chan *buffer.View),
		closed:         make(chan struct{}),
		mtu:            mtu,
	}

	// Enable TCP SACK.
	sackEnabled := tcpip.TCPSACKEnabled(true)
	if tcpipErr := dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabled); tcpipErr != nil {
		return nil, fmt.Errorf("TCP SACK: %v", tcpipErr)
	}

	dev.notifyHandle = dev.ep.AddNotify(dev)

	if tcpipErr := dev.stack.CreateNIC(1, dev.ep); tcpipErr != nil {
		return nil, fmt.Errorf("CreateNIC: %v", tcpipErr)
	}

	// Enable promiscuous mode so the NIC accepts packets destined for any
	// address (not just our CGNAT IP).  This is essential for exit-node
	// forwarding where the destination is an arbitrary LAN address.
	if tcpipErr := dev.stack.SetPromiscuousMode(1, true); tcpipErr != nil {
		return nil, fmt.Errorf("SetPromiscuousMode: %v", tcpipErr)
	}
	// Enable spoofing so the NIC can send responses from addresses that are
	// not assigned to it (i.e. the real destination's address).
	if tcpipErr := dev.stack.SetSpoofing(1, true); tcpipErr != nil {
		return nil, fmt.Errorf("SetSpoofing: %v", tcpipErr)
	}

	// Add local address.
	var proto tcpip.NetworkProtocolNumber
	if localAddr.Is4() {
		proto = ipv4.ProtocolNumber
	} else {
		proto = ipv6.ProtocolNumber
	}
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          proto,
		AddressWithPrefix: tcpip.AddrFromSlice(localAddr.AsSlice()).WithPrefix(),
	}
	if tcpipErr := dev.stack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); tcpipErr != nil {
		return nil, fmt.Errorf("AddProtocolAddress: %v", tcpipErr)
	}

	// Add default routes.
	dev.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	dev.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})

	// Install TCP forwarder — intercepts all incoming TCP SYN packets.
	tcpForwarder := tcp.NewForwarder(dev.stack, 0, 1024, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		dstAddr := net.JoinHostPort(id.LocalAddress.String(), itoa(int(id.LocalPort)))

		if !destinationAllowed(allow, id) {
			logger.Warn("wg forwarder: refused destination outside --allow", "proto", "tcp", "dst", dstAddr, "src", id.RemoteAddress.String())
			r.Complete(true) // send RST
			return
		}

		var wq waiter.Queue
		ep, tcpipErr := r.CreateEndpoint(&wq)
		if tcpipErr != nil {
			logger.Debug("forwarder: handshake failed", "dst", dstAddr, "error", tcpipErr)
			r.Complete(true)
			return
		}
		r.Complete(false)

		// Wrap into a net.Conn.
		tunnelConn := gonet.NewTCPConn(&wq, ep)

		// Dial the real destination.
		realConn, err := net.DialTimeout("tcp", dstAddr, 10*time.Second)
		if err != nil {
			logger.Debug("forwarder: dial failed", "dst", dstAddr, "error", err)
			_ = tunnelConn.Close()
			return
		}

		logger.Debug("forwarder: connected", "dst", dstAddr)

		// Bidirectional copy.
		go func() {
			defer func() { _ = tunnelConn.Close() }()
			defer func() { _ = realConn.Close() }()
			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(realConn, tunnelConn); done <- struct{}{} }()
			go func() { _, _ = io.Copy(tunnelConn, realConn); done <- struct{}{} }()
			<-done
		}()
	})
	dev.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	// Install UDP forwarder — intercepts all incoming UDP packets and proxies them.
	udpForwarder := udp.NewForwarder(dev.stack, func(r *udp.ForwarderRequest) bool { // always handled: dropped, never answered with ICMP
		id := r.ID()
		dstAddr := net.JoinHostPort(id.LocalAddress.String(), itoa(int(id.LocalPort)))

		if !destinationAllowed(allow, id) {
			logger.Warn("wg forwarder: refused destination outside --allow", "proto", "udp", "dst", dstAddr, "src", id.RemoteAddress.String())
			return true
		}

		var wq waiter.Queue
		ep, tcpipErr := r.CreateEndpoint(&wq)
		if tcpipErr != nil {
			logger.Debug("udp forwarder: create endpoint failed", "dst", dstAddr, "error", tcpipErr)
			return true
		}
		tunnelConn := gonet.NewUDPConn(&wq, ep)

		realConn, dialErr := net.Dial("udp", dstAddr)
		if dialErr != nil {
			logger.Debug("udp forwarder: dial failed", "dst", dstAddr, "error", dialErr)
			_ = tunnelConn.Close()
			return true
		}

		logger.Debug("udp forwarder: connected", "dst", dstAddr)

		go func() {
			defer func() { _ = tunnelConn.Close() }()
			defer func() { _ = realConn.Close() }()
			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(realConn, tunnelConn); done <- struct{}{} }()
			go func() { _, _ = io.Copy(tunnelConn, realConn); done <- struct{}{} }()
			<-done
		}()
		return true
	})
	dev.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	logger.Info("forwarding TUN created", "local_addr", localAddr, "mtu", mtu)
	// NOTE: Do NOT send tun.EventUp here.  device.NewDevice() starts a
	// RoutineTUNEventReader goroutine that would race with the explicit
	// dev.Up() call in forwardingTunnel.Start(), causing a double
	// BindUpdate (Close→Open cycle) that can leave the RelayBind in a
	// dirty state and surface "use of closed network connection".
	// The caller is responsible for calling dev.Up() after IpcSet.
	return dev, nil
}

// destinationAllowed applies allow to a forwarded connection's destination.
func destinationAllowed(allow DestinationPolicy, id stack.TransportEndpointID) bool {
	dst, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	return ok && allow.Allows(dst, id.LocalPort)
}

// itoa converts an int to a string without importing strconv.
func itoa(i int) string {
	if i < 0 {
		return "-" + uitoa(uint(-i))
	}
	return uitoa(uint(i))
}

func uitoa(u uint) string {
	if u == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for u > 0 {
		i--
		buf[i] = byte('0' + u%10)
		u /= 10
	}
	return string(buf[i:])
}

// ---------- tun.Device interface ----------

func (t *forwardTUN) Name() (string, error)    { return "fwd-tun", nil }
func (t *forwardTUN) File() *os.File           { return nil }
func (t *forwardTUN) Events() <-chan tun.Event { return t.events }
func (t *forwardTUN) MTU() (int, error)        { return t.mtu, nil }
func (t *forwardTUN) BatchSize() int           { return 1 }

func (t *forwardTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	var view *buffer.View
	select {
	case view = <-t.incomingPacket:
	case <-t.closed:
		return 0, os.ErrClosed
	}
	n, err := view.Read(bufs[0][offset:])
	sizes[0] = n
	return 1, err
}

func (t *forwardTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		if offset >= len(buf) {
			continue
		}
		pkt := buf[offset:]
		if len(pkt) == 0 {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(pkt),
		})
		var proto tcpip.NetworkProtocolNumber
		switch header.IPVersion(pkt) {
		case 4:
			proto = header.IPv4ProtocolNumber
		case 6:
			proto = header.IPv6ProtocolNumber
		default:
			pkb.DecRef()
			continue
		}
		t.ep.InjectInbound(proto, pkb)
		pkb.DecRef()
	}
	return len(bufs), nil
}

// WriteNotify is called by the channel endpoint when a packet is available.
func (t *forwardTUN) WriteNotify() {
	pkt := t.ep.Read()
	if pkt == nil {
		return
	}
	view := pkt.ToView()
	pkt.DecRef()
	select {
	case t.incomingPacket <- view:
	case <-t.closed:
		view.Release()
	}
}

func (t *forwardTUN) Close() error {
	t.once.Do(func() {
		t.ep.RemoveNotify(t.notifyHandle)
		close(t.closed)
		close(t.events) // ends device.RoutineTUNEventReader, which ranges over Events (a goroutine leak otherwise)
		t.stack.Close()
	})
	return nil
}
