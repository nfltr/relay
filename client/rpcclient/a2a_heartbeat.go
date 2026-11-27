// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"fmt"
	"time"

	"github.com/nfltr/relay/proto/pb"
)

// agentHeartbeatInterval is the default frequency for idle tunnel heartbeats.
// Tests may override it to exercise liveness behavior without long sleeps.
var agentHeartbeatInterval = 15 * time.Second

func (a *Agent) heartbeatSendInterval() time.Duration {
	if a.heartbeatInterval > 0 {
		return a.heartbeatInterval
	}
	return agentHeartbeatInterval
}

// heartbeatNeeded is the single admission owner for heartbeat frames. Data
// that is queued, in flight, or recently delivered is already proof-of-life.
func (a *Agent) heartbeatNeeded() bool {
	if a.outboundDataPending.Load() > 0 {
		return false
	}
	ns := a.lastFrameSentAt.Load()
	elapsed := time.Since(a.sendStallEpoch) - time.Duration(ns)
	return elapsed >= a.heartbeatSendInterval()
}

func (a *Agent) sendHeartbeatFrame() error {
	select {
	case a.heartbeatCh <- &pb.TunnelFrame{}:
		return nil
	case <-a.ctx.Done():
		return a.ctx.Err()
	default:
		// One pending heartbeat is enough to keep the tunnel alive.
		return nil
	}
}

// heartbeatLoop schedules liveness frames only while the stream is idle. The
// relay remains the authoritative liveness detector; this loop never treats a
// slow but active data send as a dead connection.
func (a *Agent) heartbeatLoop() {
	defer a.wg.Done()

	ticker := time.NewTicker(a.heartbeatSendInterval())
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			if !a.heartbeatNeeded() {
				continue
			}
			if err := a.sendHeartbeatFrame(); err != nil {
				if a.ctx.Err() != nil {
					return
				}
				a.setStreamErr(fmt.Errorf("rpcclient: send heartbeat: %w", err))
				a.cancel()
				return
			}
		}
	}
}
