// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package relayblob is the client of a relay's content-addressed blob store
// (nfltr.blob.v1, proto/nfltr/blob/v1/blob.proto): resumable verified
// uploads, ranged verified downloads and stat. Bytes are
// named by their SHA-256 and belong to the account whose credential put them.
package relayblob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nfltr/relay/proto/wire/blobwire"
)

// Attempts bounds how often a cut upload part or download resumes in a row.
const Attempts = 5

// Client talks to one relay. The zero values of HTTP, PartBytes and
// StallTimeout mean http.DefaultClient, blobwire.MaxPartBytes and one minute.
type Client struct {
	// BaseURL is the relay's HTTP base (https://host[:port]).
	BaseURL string
	// APIKey is the owner credential.
	APIKey       string
	HTTP         *http.Client
	PartBytes    int64
	StallTimeout time.Duration
}

// Error is a relay answer other than success: its HTTP status and the
// nfltr.relay.v1.ErrorReason name from the google.rpc.Status body.
type Error struct {
	HTTPStatus int
	Reason     string
	Message    string
}

func (e *Error) Error() string {
	return fmt.Sprintf("relay blob HTTP %d %s: %s", e.HTTPStatus, e.Reason, e.Message)
}

// IsNotFound reports a blob the caller may not read (unknown, or another
// account's).
func IsNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.HTTPStatus == http.StatusNotFound
}

// Blob describes a stored blob.
type Blob struct {
	SHA256    string
	SizeBytes int64
	ExpiresAt time.Time
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) partBytes() int64 {
	if c.PartBytes > 0 {
		return c.PartBytes
	}
	return blobwire.MaxPartBytes
}

func (c *Client) stallTimeout() time.Duration {
	if c.StallTimeout > 0 {
		return c.StallTimeout
	}
	return time.Minute
}

func (c *Client) url(sha, suffix string) string {
	return strings.TrimRight(c.BaseURL, "/") + blobwire.PathPrefix + sha + suffix
}

func (c *Client) newRequest(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	if c.APIKey != "" {
		req.Header.Set("X-Api-Key", c.APIKey)
	}
	return req, nil
}

// relayError reads a failed answer's google.rpc.Status.
func relayError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	var st struct {
		Message string `json:"message"`
		Details []struct {
			Reason string `json:"reason"`
		} `json:"details"`
	}
	e := &Error{HTTPStatus: resp.StatusCode, Message: strings.TrimSpace(string(body))}
	if json.Unmarshal(body, &st) == nil && st.Message != "" {
		e.Message = st.Message
		if len(st.Details) > 0 {
			e.Reason = st.Details[0].Reason
		}
	}
	return e
}

// retryable reports an answer a resend may change.
func retryable(err error) bool {
	var e *Error
	if !errors.As(err, &e) {
		return true // transport failure
	}
	return e.HTTPStatus == http.StatusTooManyRequests || e.HTTPStatus == http.StatusRequestTimeout || e.HTTPStatus >= 500
}

// stallContext is cancelled once touch has not been called for d.
func stallContext(ctx context.Context, d time.Duration) (context.Context, func(), func()) {
	ctx, cancel := context.WithCancel(ctx)
	timer := time.AfterFunc(d, cancel)
	return ctx, func() { timer.Reset(d) }, func() { timer.Stop(); cancel() }
}

// progressReader calls touch whenever a read moves bytes.
type progressReader struct {
	r     io.Reader
	touch func()
}

func (p progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.touch()
	}
	return n, err
}

// FileDescriptor is the SHA-256 and size of a local file.
func FileDescriptor(f *os.File) (blobwire.Descriptor, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return blobwire.Descriptor{}, err
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return blobwire.Descriptor{}, err
	}
	return blobwire.Descriptor{SHA256: hex.EncodeToString(h.Sum(nil)), SizeBytes: n}, nil
}

// UploadFile puts the file at path as a blob the caller owns and returns its
// descriptor. It travels in parts of at most PartBytes, each verified by the
// relay; the relay verifies the whole blob before committing it. A cut upload
// resumes from the bytes the relay holds (a probe asks), in this run or the
// next. Uploading a blob the caller holds only refreshes its retention.
func (c *Client) UploadFile(ctx context.Context, path string) (blobwire.Descriptor, error) {
	f, err := os.Open(path)
	if err != nil {
		return blobwire.Descriptor{}, err
	}
	defer func() { _ = f.Close() }()
	desc, err := FileDescriptor(f)
	if err != nil {
		return blobwire.Descriptor{}, fmt.Errorf("hash %s: %w", path, err)
	}
	held, complete, err := c.putPart(ctx, f, desc, 0, 0) // probe: where does the relay stand?
	for failures := 0; ; {
		if err != nil {
			if !retryable(err) || failures+1 >= Attempts {
				return blobwire.Descriptor{}, fmt.Errorf("upload %s: %w", path, err)
			}
			failures++
			held, complete, err = c.putPart(ctx, f, desc, 0, 0)
			continue
		}
		if complete {
			return desc, nil
		}
		prev, end := held, min(held+c.partBytes(), desc.SizeBytes)
		held, complete, err = c.putPart(ctx, f, desc, prev, end)
		switch {
		case err == nil && !complete && held <= prev:
			err = fmt.Errorf("relay holds %d bytes after a part ending at %d", held, end)
		case err == nil:
			failures = 0
		}
	}
}

// putPart sends bytes [offset, end) of f as one part and returns the bytes
// the relay holds. A gap answer is not an error: it names where to resume.
func (c *Client) putPart(ctx context.Context, f *os.File, object blobwire.Descriptor, offset, end int64) (int64, bool, error) {
	part := io.NewSectionReader(f, offset, end-offset)
	h := sha256.New()
	if _, err := io.Copy(h, part); err != nil {
		return 0, false, err
	}
	if _, err := part.Seek(0, io.SeekStart); err != nil {
		return 0, false, err
	}
	ctx, touch, stop := stallContext(ctx, c.stallTimeout())
	defer stop()
	req, err := c.newRequest(ctx, http.MethodPut, c.url(object.SHA256, ""), progressReader{r: part, touch: touch})
	if err != nil {
		return 0, false, err
	}
	req.ContentLength = end - offset
	if req.ContentLength == 0 {
		req.Body = http.NoBody
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Range", blobwire.FormatContentRange(offset, end-offset, object.SizeBytes))
	req.Header.Set(blobwire.HeaderContentDigest, blobwire.FormatDigest(hex.EncodeToString(h.Sum(nil))))
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = resp.Body.Close() }()
	held, convErr := strconv.ParseInt(resp.Header.Get(blobwire.HeaderUploadOffset), 10, 64)
	if resp.StatusCode != http.StatusOK {
		err := relayError(resp)
		var e *Error
		if errors.As(err, &e) && e.Reason == "ERROR_REASON_BLOB_UPLOAD_GAP" && convErr == nil {
			return held, false, nil
		}
		return 0, false, err
	}
	var status struct {
		SHA256   string `json:"sha256"`
		Complete bool   `json:"complete"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err := json.Unmarshal(body, &status); err != nil || convErr != nil || status.SHA256 != object.SHA256 || held < 0 || held > object.SizeBytes {
		return 0, false, &Error{HTTPStatus: resp.StatusCode, Message: "unexpected upload answer " + string(body)}
	}
	return held, status.Complete, nil
}

// DownloadFile streams blob sha into outputPath, reading with the owner
// credential. Bytes go to
// <outputPath>.part; a cut transfer resumes with a Range request. The file is
// verified against sha (and the relay's Repr-Digest) before it is renamed
// into place: unverified bytes are never used.
func (c *Client) DownloadFile(ctx context.Context, sha, outputPath string) error {
	sha, err := blobwire.NormalizeSHA256(sha)
	if err != nil {
		return err
	}
	part := outputPath + ".part"
	for range Attempts {
		var retry bool
		if retry, err = c.downloadAttempt(ctx, sha, part); err == nil {
			return os.Rename(part, outputPath)
		}
		if !retry {
			_ = os.Remove(part)
			return err
		}
	}
	return fmt.Errorf("blob %s: download did not complete after %d attempts (partial bytes kept in %s): %w", sha, Attempts, part, err)
}

func (c *Client) downloadAttempt(ctx context.Context, sha, part string) (retry bool, err error) {
	f, err := os.OpenFile(part, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return false, err
	}
	ctx, touch, stop := stallContext(ctx, c.stallTimeout())
	defer stop()
	req, err := c.newRequest(ctx, http.MethodGet, c.url(sha, ""), nil)
	if err != nil {
		return false, err
	}
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return true, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
		if err := f.Truncate(0); err != nil {
			return false, err
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return false, err
		}
	case http.StatusPartialContent:
		if !strings.HasPrefix(resp.Header.Get("Content-Range"), fmt.Sprintf("bytes %d-", offset)) {
			return true, errors.Join(errors.New("relay answered the resume with range "+resp.Header.Get("Content-Range")), f.Truncate(0))
		}
	case http.StatusRequestedRangeNotSatisfiable:
		return true, errors.Join(errors.New("partial download is not a prefix of the blob"), f.Truncate(0))
	default:
		err := relayError(resp)
		return retryable(err), err
	}
	if declared, ok, _ := blobwire.ParseDigest(resp.Header.Get(blobwire.HeaderReprDigest)); !ok || declared != sha {
		return false, fmt.Errorf("blob %s: relay declared digest %q", sha, resp.Header.Get(blobwire.HeaderReprDigest))
	}
	if _, err := io.Copy(f, progressReader{r: resp.Body, touch: touch}); err != nil {
		return true, fmt.Errorf("blob %s download was cut: %w", sha, err)
	}
	got, err := FileDescriptor(f)
	if err != nil {
		return false, err
	}
	if got.SHA256 != sha {
		return false, fmt.Errorf("blob %s integrity mismatch: downloaded sha256=%s (%d bytes)", sha, got.SHA256, got.SizeBytes)
	}
	return false, nil
}

// do runs one metadata RPC (JSON) and decodes its answer into out.
func (c *Client) do(ctx context.Context, method, url string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := c.newRequest(ctx, method, url, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return relayError(resp)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(out)
}

// Stat describes a blob the caller owns.
func (c *Client) Stat(ctx context.Context, sha string) (Blob, error) {
	var out struct {
		Blob struct {
			SHA256    string    `json:"sha256"`
			SizeBytes string    `json:"size_bytes"` // int64 travels as a JSON string
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"blob"`
	}
	if err := c.do(ctx, http.MethodGet, c.url(sha, ":stat"), nil, &out); err != nil {
		return Blob{}, err
	}
	size, err := strconv.ParseInt(out.Blob.SizeBytes, 10, 64)
	if err != nil {
		return Blob{}, fmt.Errorf("stat %s: size %q: %w", sha, out.Blob.SizeBytes, err)
	}
	return Blob{SHA256: out.Blob.SHA256, SizeBytes: size, ExpiresAt: out.Blob.ExpiresAt}, nil
}
