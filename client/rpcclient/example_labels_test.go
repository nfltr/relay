// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient_test

import (
	"context"
	"crypto/tls"
	"log"

	"github.com/nfltr/relay/client/rpcclient"
	presencev1 "github.com/nfltr/relay/proto/nfltr/presence/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// An agent changes the labels it advertises without reconnecting: one
// nfltr.presence.v1 UpdateLabelsRequest to the relay's own agent,
// rpcclient.RelayAgentID ("nfltr-relay"), which applies it to the
// connection that sent it. Patch merges into the previous update; without
// it the update replaces the previous one. The labels the agent connected
// with always stay.
func ExampleAgent_updateLabels() {
	var machine tls.Certificate // this machine's certificate
	ctx := context.Background()
	agent, err := rpcclient.Dial(ctx, "grpc.nfltr.xyz:443",
		rpcclient.WithAgentID("builder"),
		rpcclient.WithClientTLS(&tls.Config{Certificates: []tls.Certificate{machine}}),
		rpcclient.WithLabels(map[string]string{"role": "build"}),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer agent.Close() //nolint:errcheck

	req, err := protojson.Marshal(&presencev1.UpdateLabelsRequest{
		Labels: map[string]string{"status": "busy"},
		Patch:  true,
	})
	if err != nil {
		log.Fatal(err)
	}
	reply, err := agent.Invoke(ctx, rpcclient.RelayAgentID, req)
	if err != nil {
		log.Fatal(err)
	}
	var resp presencev1.UpdateLabelsResponse
	if err := protojson.Unmarshal(reply, &resp); err != nil {
		log.Fatal(err)
	}
	log.Println("advertised:", resp.GetLabels()) // role=build status=busy
}
