// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package blobv1

import "testing"

// TestBlobServiceMethods: StatBlob is the one typed blob RPC (no read
// grants, no delete: a hold ends with the relay's retention).
func TestBlobServiceMethods(t *testing.T) {
	methods := File_nfltr_blob_v1_blob_proto.Services().ByName("BlobService").Methods()
	if methods.Len() != 1 || methods.Get(0).Name() != "StatBlob" {
		t.Fatalf("BlobService has %d methods; want StatBlob only", methods.Len())
	}
}
