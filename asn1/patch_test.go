// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package asn1

import "testing"

// TestDecodeRejectsOversizedElement covers LOCAL PATCH 4/4: a crafted definite
// length must be rejected before allocation rather than triggering a multi-GB
// make([]byte) (OOM) or a makeslice panic.
func TestDecodeRejectsOversizedElement(t *testing.T) {
	ctx := NewContext()
	var out struct {
		A int `asn1:"tag:0"`
	}
	// SEQUENCE (0x30), long-form length of 4 octets (0x84) = 0xFFFFFFFF, but the
	// buffer is only 6 bytes — pre-patch this attempts a ~4 GB allocation.
	crafted := []byte{0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF}

	// Must return an error, and must not panic/OOM.
	if _, err := ctx.Decode(crafted, &out); err == nil {
		t.Fatal("expected an error for an oversized element length, got nil")
	}
}
