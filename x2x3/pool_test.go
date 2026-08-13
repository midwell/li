// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x2x3

import "testing"

// stubReachable is a Sender with an opinion about a destination it does not have, so the
// counting can be exercised without an MDF to take away.
type stubReachable struct{ down bool }

func (s *stubReachable) Send(*PDU) error   { return nil }
func (s *stubReachable) Close() error      { return nil }
func (s *stubReachable) Unreachable() bool { return s.down }

// TestPoolUnreachableCountsWhatIsWrongAndNotWhose is the shape an element's own status
// answer needs: a quantity. An element may deliver to several agencies at once, and which
// of them is unreachable is that destination's business rather than the element's — so the
// pool answers in numbers and there is nothing here for a fault description to leak.
func TestPoolUnreachableCountsWhatIsWrongAndNotWhose(t *testing.T) {
	p := NewPool(nil, nil, nil)

	if unreachable, inUse := p.Unreachable(); unreachable != 0 || inUse != 0 {
		t.Errorf("a pool that has delivered nothing reports %d of %d unreachable, want 0 of 0; "+
			"an element with no destinations in use has nothing to be wrong", unreachable, inUse)
	}

	p.senders["10.0.60.122:42069"] = &stubReachable{}
	p.senders["10.0.60.123:42069"] = &stubReachable{down: true}

	if unreachable, inUse := p.Unreachable(); unreachable != 1 || inUse != 2 {
		t.Errorf("Unreachable() = %d of %d, want 1 of 2", unreachable, inUse)
	}
}

// TestASenderThatCannotAnswerIsTakenAsReachable pins the lenient direction, deliberately.
//
// A Sender that does not implement Reachability — a test double delivering into a slice —
// has no destination to have an opinion about. Counting it as unreachable would make every
// element built that way report itself faulty, which is how the withdrawn probe failed and
// the failure that gets the whole field ignored.
func TestASenderThatCannotAnswerIsTakenAsReachable(t *testing.T) {
	p := NewPool(nil, nil, nil)
	p.senders["10.0.60.122:42069"] = &recordingSender{}

	if unreachable, inUse := p.Unreachable(); unreachable != 0 || inUse != 1 {
		t.Errorf("Unreachable() = %d of %d, want 0 of 1", unreachable, inUse)
	}
}

// TestAsyncSenderAnswersForTheSenderBehindIt: delivery happens on the worker, so the
// question belongs to the client the queue feeds. Enqueueing establishes nothing about a
// destination, and an AsyncSender that answered from its own Send would always say
// "reachable".
func TestAsyncSenderAnswersForTheSenderBehindIt(t *testing.T) {
	down := NewAsyncSender(&stubReachable{down: true}, 4, nil, nil)
	defer down.Close()
	if !down.Unreachable() {
		t.Error("the queue reports its destination reachable while the sender behind it cannot reach it")
	}

	up := NewAsyncSender(&stubReachable{}, 4, nil, nil)
	defer up.Close()
	if up.Unreachable() {
		t.Error("the queue reports a reachable destination as unreachable")
	}
}
