// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x2x3

import "testing"

// TestForAfterCloseBuildsNothing: Close empties the sender map rather than marking
// the pool, so a delivery arriving after it used to miss the cache and construct a
// fresh sender — with a worker goroutine behind it — into a pool nobody will close
// again. A worker outliving the shutdown meant to end it, still holding a
// connection to a mediation function this element no longer answers for.
//
// What a closed pool hands back is a sender that discards, not nil. The assertion
// is on the *type* rather than on nil-ness, because "builds nothing" is the property
// under test and a discarding sender satisfies it: nothing is dialled and no worker
// is started.
func TestForAfterCloseBuildsNothing(t *testing.T) {
	p := NewPool(nil, KeepaliveConfig{}, nil, nil)

	if s := p.For("192.0.2.1:42069"); s == nil {
		t.Fatal("a live pool returned no sender")
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for _, addr := range []string{
		"192.0.2.2:42069", // an address the pool never held
		"192.0.2.1:42069", // one it held and closed
	} {
		s := p.For(addr)
		if s == nil {
			t.Fatalf("a closed pool returned nil for %s; the delivery path may neither "+
				"block nor fault, and a nil interface faults it", addr)
		}
		if _, discarding := s.(discardSender); !discarding {
			t.Errorf("a closed pool built a real sender for %s, and with it a worker nothing will stop", addr)
		}
	}
}

// TestClosedPoolSenderIsSafeToUse is the property the nil return did not have. A
// delivery racing a shutdown is the ordinary case rather than the exotic one — a
// purge, a reconfiguration and an element shutting down are exactly the moments
// product is still being offered — and the offering path is a signalling or
// data-plane path that delivery may neither block nor fault.
func TestClosedPoolSenderIsSafeToUse(t *testing.T) {
	p := NewPool(nil, KeepaliveConfig{}, nil, nil)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s := p.For("192.0.2.1:42069")
	if err := s.Send(&PDU{Type: PDUTypeX2}); err != nil {
		t.Errorf("Send on a closed pool's sender returned %v, want nil", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close on a closed pool's sender returned %v, want nil", err)
	}
}

// TestClosedPoolReportsNoFault: a destination nothing has been sent to is not
// unreachable — the element has not looked. A closed pool's phantom senders must
// not put a fault into an element's status answer.
func TestClosedPoolReportsNoFault(t *testing.T) {
	p := NewPool(nil, KeepaliveConfig{}, nil, nil)
	const addr = "192.0.2.1:42069"
	p.For(addr)

	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if p.UnreachableAt(addr) {
		t.Error("a closed pool reported a destination as unreachable")
	}
	if unreachable, _ := p.UnreachableAmong([]string{addr}); unreachable != 0 {
		t.Errorf("a closed pool counted %d unreachable destinations, want 0", unreachable)
	}
}
