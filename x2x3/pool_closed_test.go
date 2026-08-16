// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x2x3

import "testing"

// TestForAfterCloseBuildsNothing: Close empties the sender map rather than marking
// the pool, so a delivery arriving after it used to miss the cache and construct a
// fresh sender — with a worker goroutine behind it — into a pool nobody will close
// again. A worker outliving the shutdown meant to end it, still holding a
// connection to a mediation function this element no longer answers for.
func TestForAfterCloseBuildsNothing(t *testing.T) {
	p := NewPool(nil, KeepaliveConfig{}, nil, nil)

	if s := p.For("192.0.2.1:42069"); s == nil {
		t.Fatal("a live pool returned no sender")
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if s := p.For("192.0.2.2:42069"); s != nil {
		t.Error("a closed pool built a new sender, and with it a worker nothing will stop")
	}
	if s := p.For("192.0.2.1:42069"); s != nil {
		t.Error("a closed pool rebuilt a sender for an address it had already closed")
	}
}
