// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x2x3

import (
	"errors"
	"sync"
	"testing"
)

// recordingSender is a test double for the Sender interface. When block is
// non-nil, Send blocks until it is closed, letting a test hold the worker so the
// bounded queue fills.
type recordingSender struct {
	mu     sync.Mutex
	sent   int
	closed bool
	err    error
	block  chan struct{}
}

func (r *recordingSender) Send(*PDU) error {
	if r.block != nil {
		<-r.block
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent++
	return r.err
}

func (r *recordingSender) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

func (r *recordingSender) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sent
}

// TestAsyncSenderDelivers checks enqueued PDUs are delivered to the inner Sender
// and that Close drains the queue and closes the inner Sender.
func TestAsyncSenderDelivers(t *testing.T) {
	rec := &recordingSender{}
	a := NewAsyncSender(rec, 8, nil, nil)
	for range 3 {
		if err := a.Send(&PDU{Type: PDUTypeX2}); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := rec.count(); got != 3 {
		t.Errorf("delivered %d PDUs, want 3", got)
	}
	if !rec.closed {
		t.Error("inner Sender was not closed")
	}
}

// TestAsyncSenderErrorCallback checks a worker delivery error invokes onError.
func TestAsyncSenderErrorCallback(t *testing.T) {
	rec := &recordingSender{err: errors.New("mdf down")}
	var mu sync.Mutex
	errs := 0
	a := NewAsyncSender(rec, 8, func(error) { mu.Lock(); errs++; mu.Unlock() }, nil)
	_ = a.Send(&PDU{Type: PDUTypeX2})
	_ = a.Close()
	mu.Lock()
	defer mu.Unlock()
	if errs != 1 {
		t.Errorf("onError ran %d times, want 1", errs)
	}
}

// TestAsyncSenderDropsWhenFull checks that Send never blocks and drops (invoking
// onDrop) once the buffer is full — the key undetectability property: a stalled
// MDF must not block the caller. With depth 1 and the worker held, at most two
// PDUs are accepted (one in-flight in the worker, one queued), so the rest drop.
func TestAsyncSenderDropsWhenFull(t *testing.T) {
	block := make(chan struct{})
	rec := &recordingSender{block: block}
	var mu sync.Mutex
	drops := 0
	a := NewAsyncSender(rec, 1, nil, func() { mu.Lock(); drops++; mu.Unlock() })

	const n = 10
	for range n {
		if err := a.Send(&PDU{Type: PDUTypeX2}); err != nil {
			t.Fatalf("Send must never return an error: %v", err)
		}
	}
	mu.Lock()
	d := drops
	mu.Unlock()
	if d < n-2 {
		t.Errorf("dropped %d of %d with the worker blocked and depth 1, want >= %d", d, n, n-2)
	}

	close(block) // let the worker drain so Close can finish
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestAsyncSenderBatchesWhatIsAlreadyQueued covers the delivery coalescing added
// for review R36: PDUs that are already waiting share one write, which is where
// the syscall and TLS-record saving comes from. It must never wait for a batch to
// fill, or delivery latency would depend on how idle the target is.
func TestAsyncSenderBatchesWhatIsAlreadyQueued(t *testing.T) {
	rec := &batchRecorder{}
	// Depth well above the number queued, so nothing is dropped.
	a := NewAsyncSender(rec, 256, nil, nil)

	const n = 50
	for i := 0; i < n; i++ {
		if err := a.Send(&PDU{Type: PDUTypeX3}); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	a.Close()

	total, calls := rec.totals()
	if total != n {
		t.Errorf("delivered %d PDUs, want %d", total, n)
	}
	// The point of batching: fewer writes than PDUs. Exactly how many depends on
	// scheduling, so this asserts the property rather than a number.
	if calls >= n {
		t.Errorf("took %d writes for %d PDUs; nothing was batched", calls, n)
	}
}

// batchRecorder counts PDUs and the number of write calls they took.
type batchRecorder struct {
	mu    sync.Mutex
	pdus  int
	calls int
}

func (b *batchRecorder) Send(*PDU) error {
	b.mu.Lock()
	b.pdus++
	b.calls++
	b.mu.Unlock()

	return nil
}

func (b *batchRecorder) SendBatch(pdus []*PDU) error {
	b.mu.Lock()
	b.pdus += len(pdus)
	b.calls++
	b.mu.Unlock()

	return nil
}

// Close satisfies Sender; there is no connection to release.
func (b *batchRecorder) Close() error { return nil }

func (b *batchRecorder) totals() (int, int) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.pdus, b.calls
}
