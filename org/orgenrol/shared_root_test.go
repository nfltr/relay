package orgenrol

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/client/mailboxclient"

	"github.com/nfltr/relay/org/orgpki"
)

// shared is relay with the relay's shared-mailbox kinds (relay-server
// internal/application/mailbox/scope.go kindOf, spec/Reach.tla KindOf):
// the first declared touch of a mailbox makes it a broadcast (a holder's
// append, a member's pull) or a drop box (a holder's pull or ack, a
// member's append), for good; a member pulls only a broadcast and appends
// only to a drop box. share is this view's declaration.
type shared struct {
	*relay
	share string
	mu    *sync.Mutex
	kinds map[string]string
}

func newShared(r *relay, share string) shared {
	return shared{relay: r, share: share, mu: &sync.Mutex{}, kinds: map[string]string{}}
}

func (s shared) Declare(share string) Mailbox { s.share = share; return s }

func (s shared) touch(box string, appending, ack bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.kinds[box]
	if !ok && s.share != "" && !(ack && s.share == mailboxclient.ShareMember) {
		k = "dropbox"
		if (s.share == mailboxclient.ShareHolder) == appending && !ack {
			k = "broadcast"
		}
		s.kinds[box] = k
	}
	if s.share == mailboxclient.ShareMember && ((k == "dropbox" && !appending) || (k == "broadcast" && appending)) {
		return errors.New("mailbox " + box + " is a " + k + ": refused to a member")
	}
	return nil
}

func (s shared) Append(ctx context.Context, box string, p []byte, o mailboxclient.AppendOptions) (mailboxclient.Appended, error) {
	if err := s.touch(box, true, false); err != nil {
		return mailboxclient.Appended{}, err
	}
	return s.relay.Append(ctx, box, p, o)
}

func (s shared) Pull(ctx context.Context, box string, after uint64, max int, wait time.Duration) ([]mailboxclient.Envelope, string, error) {
	if err := s.touch(box, false, false); err != nil {
		return nil, "", err
	}
	return s.relay.Pull(ctx, box, after, max, wait)
}

func (s shared) Ack(ctx context.Context, box string, through uint64) error {
	if err := s.touch(box, false, true); err != nil {
		return err
	}
	return s.relay.Ack(ctx, box, through)
}

// On a fresh relay the issuer's first round reads the root back before it
// publishes it (a newer CRL of issuers the owner's machine published); that
// read is a member's, so the root is a broadcast members read, and a
// machine joins. A holder's read made it a drop box no member could read:
// no machine could join an organisation made on a fresh relay (relay org
// v0.1.3 to v0.1.6; spec/orgmove/OrgHolds.tla RootReadable, mutant
// holder-read).
func TestIssuerOnAFreshRelayLeavesTheRootReadable(t *testing.T) {
	clk := &clock{t: time.Now().Truncate(time.Second)}
	o := newOrg(t, clk.Now())
	mb := newShared(newRelay(), mailboxclient.ShareHolder)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Service{Mailbox: mb, Dir: o.dir, Logger: quiet(), Now: clk.Now, Wait: 50 * time.Millisecond}.Run(ctx)
	}()
	t.Cleanup(func() { cancel(); <-done })
	eventually(t, "the root published", func() bool { // read past the kinds: the issuer touches it first
		data, err := latest(ctx, mb.relay, orgpki.RootMailbox(o.id), 0)
		return err == nil && data != nil
	})
	member := mb.Declare(mailboxclient.ShareMember)
	if _, err := latest(ctx, member, orgpki.RootMailbox(o.id), 0); err != nil {
		t.Fatalf("a member reads the root: %v", err)
	}
	j, err := Join(ctx, member, t.TempDir(), o.pins, o.token(t, "web-1", clk.Now()), hang, clk.Now)
	check(t, err)
	if j.Cert.Subject.CommonName != "web-1" {
		t.Fatalf("joined as %q", j.Cert.Subject.CommonName)
	}
}
