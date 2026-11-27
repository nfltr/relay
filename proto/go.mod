module github.com/nfltr/relay/proto

go 1.27.0

require (
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.29.0
	github.com/nfltr/link v0.14.0
	google.golang.org/genproto/googleapis/api v0.0.0-20260803160001-6ac0973c030d
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.11
)

require (
	go.opentelemetry.io/otel v1.45.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.45.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260803160001-6ac0973c030d // indirect
)

// Built against the agent wire before nfltr.relay.v1 (client generation 4);
// use v0.23.0 or later.
retract [v0.0.0, v0.22.3]
