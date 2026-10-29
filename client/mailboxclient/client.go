// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package mailboxclient is the client of the relay's mailbox and webhook
// API (nfltr.mailbox.v1 over HTTP JSON): append, pull, ack and list
// mailboxes; create, list and delete webhooks. Callers get plain Go values;
// the wire messages stay here. A refusal is an *Error carrying the relay's
// typed ErrorReason; callers branch on Reason, never on message text.
package mailboxclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	spb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	mailboxv1 "github.com/nfltr/relay/proto/nfltr/mailbox/v1"
)

// Reasons callers branch on: nfltr.relay.v1.ErrorReason names (constants, so
// no package init work; TestReasonNamesMatchTheEnum pins them to the enum).
const (
	ReasonMailboxFull     = "ERROR_REASON_MAILBOX_FULL"
	ReasonLimitExceeded   = "ERROR_REASON_LIMIT_EXCEEDED"
	ReasonUnauthenticated = "ERROR_REASON_UNAUTHENTICATED"
	ReasonWebhookNotFound = "ERROR_REASON_WEBHOOK_NOT_FOUND"
	ReasonUnsupported     = "ERROR_REASON_FEATURE_UNSUPPORTED"
)

// Error is a relay refusal.
type Error struct {
	HTTPStatus int
	// Reason is the ErrorReason name, "" when the relay gave none (an
	// invalid argument, or a relay that does not serve mailboxes).
	Reason  string
	Message string
}

func (e *Error) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("HTTP %d: %s", e.HTTPStatus, e.Message)
	}
	return fmt.Sprintf("%s: %s", e.Reason, e.Message)
}

// ReasonOf is err's Reason, "" when err is not an *Error.
func ReasonOf(err error) string {
	if e, ok := errors.AsType[*Error](err); ok {
		return e.Reason
	}
	return ""
}

// Client calls the relay with an account credential.
type Client struct {
	ProxyURL string
	APIKey   string
	// HTTP defaults to http.DefaultClient; each call is bounded by its
	// context (a pull by its wait plus a margin).
	HTTP *http.Client
}

// SenderKind is how the relay authenticated a sender.
type SenderKind int

const (
	SenderUnspecified   = SenderKind(mailboxv1.SenderKind_SENDER_KIND_UNSPECIFIED)
	SenderAPIKey        = SenderKind(mailboxv1.SenderKind_SENDER_KIND_API_KEY)
	SenderSession       = SenderKind(mailboxv1.SenderKind_SENDER_KIND_SESSION)
	SenderWebhook       = SenderKind(mailboxv1.SenderKind_SENDER_KIND_WEBHOOK)
	SenderLoopbackTrust = SenderKind(mailboxv1.SenderKind_SENDER_KIND_LOOPBACK_TRUST)
)

// Envelope is one pulled message.
type Envelope struct {
	Seq            uint64
	IdempotencyKey string
	ReplaceKey     string
	SenderKind     SenderKind
	Sender         string
	ContentType    string
	Payload        []byte
	AppendedAt     time.Time
	ExpiresAt      time.Time
	DeliveryCount  uint32
	DroppedBefore  uint64
}

// AppendOptions are an append's optional fields.
type AppendOptions struct {
	IdempotencyKey string
	ReplaceKey     string
	ContentType    string
	TTL            time.Duration
	Notify         bool
}

// Appended is an append's result.
type Appended struct {
	Seq       uint64
	Duplicate bool
	Owner     string
}

// Webhook is one listed webhook.
type Webhook struct {
	ID                                                            string
	Mailbox                                                       string
	IngressPath                                                   string
	DroppedRate, DroppedMailboxFull, RejectedTooLarge, Duplicates uint64
}

// Webhook auth schemes.
const (
	AuthBearer = "bearer"
	AuthGitHub = "github"
)

func (c Client) call(ctx context.Context, method, path string, in, out proto.Message) error {
	target := strings.TrimRight(c.ProxyURL, "/") + path
	var body io.Reader
	if in != nil {
		data, err := protojson.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("X-Api-Key", c.APIKey)
	}
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return decodeError(resp.StatusCode, data)
	}
	return protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(data, out)
}

// decodeError reads a google.rpc.Status body; any other body is the
// message of a reason-less Error.
func decodeError(code int, data []byte) error {
	e := &Error{HTTPStatus: code, Message: strings.TrimSpace(string(data))}
	var st spb.Status
	if (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(data, &st) == nil && (st.GetMessage() != "" || len(st.GetDetails()) > 0) {
		e.Message = st.GetMessage()
		for _, d := range st.GetDetails() {
			var info errdetails.ErrorInfo
			if d.UnmarshalTo(&info) == nil {
				e.Reason = info.GetReason()
			}
		}
	}
	return e
}

func mailboxPath(name, suffix string) string {
	return "/api/v1/mailboxes/" + url.PathEscape(name) + suffix
}

// Append stores payload in mailbox.
func (c Client) Append(ctx context.Context, mailbox string, payload []byte, o AppendOptions) (Appended, error) {
	in := &mailboxv1.AppendMessageRequest{Mailbox: mailbox, IdempotencyKey: o.IdempotencyKey, ReplaceKey: o.ReplaceKey, ContentType: o.ContentType, Payload: payload, Notify: o.Notify}
	if o.TTL > 0 {
		in.Ttl = durationpb.New(o.TTL)
	}
	var out mailboxv1.AppendMessageResponse
	if err := c.call(ctx, http.MethodPost, mailboxPath(mailbox, "/messages"), in, &out); err != nil {
		return Appended{}, err
	}
	return Appended{Seq: out.GetSeq(), Duplicate: out.GetDuplicate(), Owner: out.GetOwner()}, nil
}

// Pull returns mailbox's envelopes after the cursor (at most max, 0 = the
// relay's ceiling), waiting up to wait while there are none, and the
// mailbox owner's account identity.
func (c Client) Pull(ctx context.Context, mailbox string, after uint64, max int, wait time.Duration) ([]Envelope, string, error) {
	ctx, cancel := context.WithTimeout(ctx, wait+30*time.Second)
	defer cancel()
	in := &mailboxv1.PullMessagesRequest{Mailbox: mailbox, AfterSeq: after, MaxMessages: uint32(max)}
	if wait > 0 {
		in.Wait = durationpb.New(wait)
	}
	var out mailboxv1.PullMessagesResponse
	if err := c.call(ctx, http.MethodPost, mailboxPath(mailbox, "/messages:pull"), in, &out); err != nil {
		return nil, "", err
	}
	envs := make([]Envelope, 0, len(out.GetEnvelopes()))
	for _, e := range out.GetEnvelopes() {
		envs = append(envs, Envelope{Seq: e.GetSeq(), IdempotencyKey: e.GetIdempotencyKey(), ReplaceKey: e.GetReplaceKey(), SenderKind: SenderKind(e.GetSenderKind()),
			Sender: e.GetSender(), ContentType: e.GetContentType(), Payload: e.GetPayload(), AppendedAt: e.GetAppendedAt().AsTime(), ExpiresAt: e.GetExpiresAt().AsTime(),
			DeliveryCount: e.GetDeliveryCount(), DroppedBefore: e.GetDroppedBefore()})
	}
	return envs, out.GetOwner(), nil
}

// Ack removes mailbox's envelopes through seq.
func (c Client) Ack(ctx context.Context, mailbox string, through uint64) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return c.call(ctx, http.MethodPost, mailboxPath(mailbox, "/messages:ack"), &mailboxv1.AckMessagesRequest{Mailbox: mailbox, ThroughSeq: through}, &mailboxv1.AckMessagesResponse{})
}

// CreateWebhook makes a webhook delivering into mailbox; the secret is
// returned once.
func (c Client) CreateWebhook(ctx context.Context, mailbox, auth string, maxEventsPerMinute, maxBodyBytes int) (Webhook, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var wireAuth mailboxv1.WebhookAuth
	switch auth {
	case AuthBearer:
		wireAuth = mailboxv1.WebhookAuth_WEBHOOK_AUTH_BEARER
	case AuthGitHub:
		wireAuth = mailboxv1.WebhookAuth_WEBHOOK_AUTH_GITHUB
	default:
		return Webhook{}, "", fmt.Errorf("auth must be %q or %q", AuthBearer, AuthGitHub)
	}
	in := &mailboxv1.CreateWebhookRequest{Mailbox: mailbox, Auth: wireAuth,
		Limits: &mailboxv1.WebhookLimits{MaxEventsPerMinute: uint32(max(maxEventsPerMinute, 0)), MaxBodyBytes: uint32(max(maxBodyBytes, 0))}}
	var out mailboxv1.CreateWebhookResponse
	if err := c.call(ctx, http.MethodPost, "/api/v1/webhooks", in, &out); err != nil {
		return Webhook{}, "", err
	}
	return webhookFromWire(out.GetWebhook()), out.GetSecret(), nil
}

func webhookFromWire(w *mailboxv1.Webhook) Webhook {
	c := w.GetCounters()
	return Webhook{ID: w.GetWebhookId(), Mailbox: w.GetMailbox(), IngressPath: w.GetIngressPath(), DroppedRate: c.GetDroppedRateLimited(),
		DroppedMailboxFull: c.GetDroppedMailboxFull(), RejectedTooLarge: c.GetRejectedTooLarge(), Duplicates: c.GetDuplicates()}
}

// ListWebhooks lists the account's webhooks into mailbox.
func (c Client) ListWebhooks(ctx context.Context, mailbox string) ([]Webhook, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out mailboxv1.ListWebhooksResponse
	if err := c.call(ctx, http.MethodGet, "/api/v1/webhooks?mailbox="+url.QueryEscape(mailbox), nil, &out); err != nil {
		return nil, err
	}
	hooks := make([]Webhook, 0, len(out.GetWebhooks()))
	for _, w := range out.GetWebhooks() {
		hooks = append(hooks, webhookFromWire(w))
	}
	return hooks, nil
}

// DeleteWebhook deletes a webhook and its unacknowledged deliveries.
func (c Client) DeleteWebhook(ctx context.Context, id string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out mailboxv1.DeleteWebhookResponse
	err := c.call(ctx, http.MethodDelete, "/api/v1/webhooks/"+url.PathEscape(id), nil, &out)
	return int(out.GetDiscarded()), err
}
