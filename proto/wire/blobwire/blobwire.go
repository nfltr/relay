// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package blobwire is the HTTP wire format of nfltr.blob.v1 byte transfer
// (proto/nfltr/blob/v1/blob.proto), shared by the relay that parses it and
// the client that writes it: header names, the part's Content-Range and the
// RFC 9530 sha-256 digest fields. No I/O.
package blobwire

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Headers and path of the byte routes.
const (
	PathPrefix          = "/api/v1/blobs/"
	HeaderUploadOffset  = "Upload-Offset"
	HeaderContentDigest = "Content-Digest"
	HeaderReprDigest    = "Repr-Digest"
)

// ErrMalformed marks a header that does not parse.
var ErrMalformed = errors.New("malformed blob transfer header")

// MaxPartBytes is the largest part one upload request may carry.
const MaxPartBytes = 64 << 20

// Descriptor names a blob: its SHA-256 (lowercase hex) and size.
type Descriptor struct {
	SHA256    string
	SizeBytes int64
}

// NormalizeSHA256 lowercases a SHA-256 hex digest and refuses anything that
// is not 64 hex characters.
func NormalizeSHA256(sha string) (string, error) {
	sha = strings.ToLower(strings.TrimSpace(sha))
	if len(sha) != 64 {
		return "", fmt.Errorf("sha256 %q must be 64 hex characters", sha)
	}
	if _, err := hex.DecodeString(sha); err != nil {
		return "", fmt.Errorf("sha256 %q is not hex", sha)
	}
	return sha, nil
}

// FormatContentRange is the Content-Range of a part of length bytes at
// offset of a total-byte object; length 0 gives the probe form "bytes */total".
func FormatContentRange(offset, length, total int64) string {
	if length == 0 {
		return fmt.Sprintf("bytes */%d", total)
	}
	return fmt.Sprintf("bytes %d-%d/%d", offset, offset+length-1, total)
}

// ParseContentRange parses "bytes FIRST-LAST/TOTAL" or the probe
// "bytes */TOTAL" (offset 0, length 0) and checks the part lies within total.
func ParseContentRange(v string) (offset, length, total int64, err error) {
	spec, ok := strings.CutPrefix(strings.TrimSpace(v), "bytes ")
	if !ok {
		return 0, 0, 0, fmt.Errorf("%w: Content-Range %q", ErrMalformed, v)
	}
	span, totalText, ok := strings.Cut(spec, "/")
	if !ok {
		return 0, 0, 0, fmt.Errorf("%w: Content-Range %q has no total", ErrMalformed, v)
	}
	if total, err = parseNonNegative(totalText); err != nil {
		return 0, 0, 0, fmt.Errorf("%w: Content-Range total %q", ErrMalformed, totalText)
	}
	if span == "*" {
		return 0, 0, total, nil
	}
	firstText, lastText, ok := strings.Cut(span, "-")
	first, err1 := parseNonNegative(firstText)
	last, err2 := parseNonNegative(lastText)
	if !ok || err1 != nil || err2 != nil || last < first || last >= total {
		return 0, 0, 0, fmt.Errorf("%w: Content-Range %q", ErrMalformed, v)
	}
	return first, last - first + 1, total, nil
}

func parseNonNegative(s string) (int64, error) {
	if s == "" || strings.TrimLeft(s, "0123456789") != "" {
		return 0, ErrMalformed
	}
	return strconv.ParseInt(s, 10, 64)
}

// FormatDigest is the RFC 9530 field value carrying one hex SHA-256.
func FormatDigest(shaHex string) string {
	raw, _ := hex.DecodeString(shaHex)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(raw) + ":"
}

// ParseDigest returns the lowercase hex SHA-256 of an RFC 9530
// Content-Digest/Repr-Digest value; other algorithms are ignored. ok is false
// when the value names no sha-256.
func ParseDigest(v string) (shaHex string, ok bool, err error) {
	for member := range strings.SplitSeq(v, ",") {
		key, value, _ := strings.Cut(strings.TrimSpace(member), "=")
		if !strings.EqualFold(strings.TrimSpace(key), "sha-256") {
			continue
		}
		b64, found := strings.CutPrefix(strings.TrimSpace(value), ":")
		if b64, found2 := strings.CutSuffix(b64, ":"); found && found2 {
			if raw, err := base64.StdEncoding.DecodeString(b64); err == nil && len(raw) == 32 {
				return hex.EncodeToString(raw), true, nil
			}
		}
		return "", false, fmt.Errorf("%w: sha-256 digest %q", ErrMalformed, value)
	}
	return "", false, nil
}
