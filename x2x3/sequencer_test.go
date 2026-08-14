// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x2x3

import (
	"sync"
	"testing"
)

var (
	otherXID = [xidLength]byte{9, 9, 9}
	otherCID = [CorrelationIDLength]byte{9}
)

// TestSequencerStartsAtZeroPerContext is clause 5.3.9's first sentence: the number
// starts at zero and increments by one within a context.
func TestSequencerStartsAtZeroPerContext(t *testing.T) {
	s := NewSequencer()
	for want := range uint32(3) {
		if got := s.Next(sampleXID, sampleCID); got != want {
			t.Errorf("Next() = %d, want %d", got, want)
		}
	}
}

// TestSequencerContextsAreIndependent covers the case a per-connection counter gets
// wrong: two sessions of one warrant, or two warrants, sharing a delivery
// connection. Each is numbered from zero in its own context.
func TestSequencerContextsAreIndependent(t *testing.T) {
	s := NewSequencer()
	s.Next(sampleXID, sampleCID)
	s.Next(sampleXID, sampleCID)

	if got := s.Next(sampleXID, otherCID); got != 0 {
		t.Errorf("a second correlation id starts at %d, want 0", got)
	}
	if got := s.Next(otherXID, sampleCID); got != 0 {
		t.Errorf("a second XID starts at %d, want 0", got)
	}
	if got := s.Next(sampleXID, sampleCID); got != 2 {
		t.Errorf("the first context continued at %d, want 2", got)
	}
	if n := s.Len(); n != 3 {
		t.Errorf("holding %d contexts, want 3", n)
	}
}

// TestSequencerWraps: "once the maximum sequence number is reached, the POI shall
// restart the sequence number from zero".
func TestSequencerWraps(t *testing.T) {
	s := NewSequencer()
	s.Next(sampleXID, sampleCID) // create the context, returning 0

	s.mu.RLock()
	c := s.counters[seqContext{xid: sampleXID, corr: sampleCID}]
	s.mu.RUnlock()
	c.Store(0xFFFFFFFF) // the next number handed out is the last one available

	if got := s.Next(sampleXID, sampleCID); got != 0xFFFFFFFF {
		t.Fatalf("Next() = %d, want 0xFFFFFFFF", got)
	}
	if got := s.Next(sampleXID, sampleCID); got != 0 {
		t.Errorf("Next() after the maximum = %d, want 0", got)
	}
}

// TestSequencerForgetDropsATasksContexts is the leak guard. A warrant covering many
// sessions creates a context per session, so numbering state that outlives tasking
// grows for as long as the process runs — worst in the UPF, which holds the most.
func TestSequencerForgetDropsATasksContexts(t *testing.T) {
	s := NewSequencer()
	s.Next(sampleXID, sampleCID)
	s.Next(sampleXID, otherCID)
	s.Next(otherXID, sampleCID)

	s.Forget(sampleXID)

	if n := s.Len(); n != 1 {
		t.Errorf("holding %d contexts after forgetting one XID, want 1", n)
	}
	if got := s.Next(sampleXID, sampleCID); got != 0 {
		t.Errorf("a reactivated XID resumes at %d, want 0 — a new context starts at zero", got)
	}
	if got := s.Next(otherXID, sampleCID); got != 1 {
		t.Errorf("an untouched context restarted at %d, want 1", got)
	}
}

// TestSequencerIsConcurrent: the number is taken where a PDU is framed, which in the
// UPF is four workers deep. Run under -race; the assertion is that every number in a
// context is handed out exactly once.
func TestSequencerIsConcurrent(t *testing.T) {
	const workers, each = 8, 200
	s := NewSequencer()

	var mu sync.Mutex
	seen := make(map[uint32]int, workers*each)

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				n := s.Next(sampleXID, sampleCID)
				mu.Lock()
				seen[n]++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(seen) != workers*each {
		t.Errorf("%d distinct numbers for %d PDUs: a number was handed out twice", len(seen), workers*each)
	}
	for n := range uint32(workers * each) {
		if seen[n] != 1 {
			t.Errorf("number %d handed out %d times, want once", n, seen[n])
		}
	}
}
