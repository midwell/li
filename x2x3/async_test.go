// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x2x3

import (
	"errors"
	"os"
	"os/exec"
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
	//nolint:errcheck // test
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
// PDUs that are already waiting share one write, which is where
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

// closeRaceChildEnv names the test whose fault-reproducing body this process is
// running. Both faults land where no test can recover them — a nil dereference on
// the delivery worker, and a send on a closed channel on whichever goroutine
// offered the PDU — so the body runs in a child process and the parent reads its
// exit status.
const closeRaceChildEnv = "X2X3_CLOSE_RACE_CHILD"

// inChildProcess reports whether this process is the child spawned for the named test.
func inChildProcess(name string) bool { return os.Getenv(closeRaceChildEnv) == name }

// runInSubprocess re-runs the test binary for t's test alone, with the marker set,
// and fails t with the child's output if it did not exit cleanly.
func runInSubprocess(t *testing.T) {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), closeRaceChildEnv+"="+t.Name())

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("delivery faulted under Close: %v\n%s", err, out)
	}
}

// TestAsyncSenderCloseDoesNotFaultRealClient closes a sender while its worker is
// draining into the *Client the network functions actually deliver through. A
// closed channel is immediately readable and yields the zero value, so a drain
// that does not check the closed result appends a nil *PDU to the batch and
// SendBatch dereferences it. The test doubles elsewhere in this file survive that
// — they only count — which is why this one uses the real client.
//
// One queued PDU and an immediate Close is the shape that hits it every time: the
// worker is parked on the receive, the send hands the PDU straight to it, and the
// close lands while it is still being scheduled — so it enters the drain with the
// channel already closed.
//
// The client's address is never reached: the fault is in Marshal, which SendBatch
// performs before any I/O.
func TestAsyncSenderCloseDoesNotFaultRealClient(t *testing.T) {
	if !inChildProcess(t.Name()) {
		runInSubprocess(t)
		return
	}

	for range 100 {
		a := NewAsyncSender(NewClient("127.0.0.1:1", nil, KeepaliveConfig{}), 8, nil, nil)
		//nolint:errcheck // Send's error is always nil
		_ = a.Send(&PDU{Type: PDUTypeX3, PayloadFormat: PayloadFormatIPv4})
		//nolint:errcheck // nothing was ever connected
		_ = a.Close()
	}
}

// TestAsyncSenderCloseAddsNothingToTheBatch observes the same window through a
// counting double instead of a real client: what the drain appends when the
// channel closes under it is a nil PDU, and the double delivers it as an extra.
// TestAsyncSenderBatchesWhatIsAlreadyQueued sees it too, as `delivered 51 PDUs,
// want 50`, but only when the scheduling happens to line up; this states the
// window directly.
func TestAsyncSenderCloseAddsNothingToTheBatch(t *testing.T) {
	for range 100 {
		rec := &batchRecorder{}
		a := NewAsyncSender(rec, 8, nil, nil)
		if err := a.Send(&PDU{Type: PDUTypeX3, PayloadFormat: PayloadFormatIPv4}); err != nil {
			t.Fatalf("Send: %v", err)
		}
		if err := a.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		if total, _ := rec.totals(); total != 1 {
			t.Fatalf("delivered %d PDUs for the one that was queued, want 1", total)
		}
	}
}

// TestAsyncSenderSendRacingClose covers the second, separate fault: Send and Close
// share no state at all, so a Send that reaches the channel operation after Close
// has closed it panics on the caller's goroutine — a signalling or data-plane
// goroutine, whose contract is that delivery can neither block it nor fail it.
//
// It also asserts the boundary Close draws: the worker is gone when Close returns,
// so a PDU offered afterwards cannot be delivered.
func TestAsyncSenderSendRacingClose(t *testing.T) {
	if !inChildProcess(t.Name()) {
		runInSubprocess(t)
		return
	}

	for range 200 {
		rec := &recordingSender{}
		a := NewAsyncSender(rec, 4, nil, nil)

		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 64 {
					//nolint:errcheck // Send's error is always nil
					_ = a.Send(&PDU{Type: PDUTypeX3, PayloadFormat: PayloadFormatIPv4})
				}
			}()
		}

		//nolint:errcheck // the double has no connection to release
		_ = a.Close()
		atClose := rec.count()
		wg.Wait()

		if got := rec.count(); got != atClose {
			t.Fatalf("delivered %d PDUs after Close returned", got-atClose)
		}
	}
}

// TestAsyncSenderSendAfterCloseDrops is the deterministic form of the same fault:
// product offered to a closed sender is dropped and reported as a drop, by the
// same means as product dropped for any other reason, and the offering path
// proceeds. Delivery is not permitted to fault the path carrying it.
func TestAsyncSenderSendAfterCloseDrops(t *testing.T) {
	rec := &recordingSender{}
	var mu sync.Mutex
	drops := 0
	a := NewAsyncSender(rec, 8, nil, func() { mu.Lock(); drops++; mu.Unlock() })

	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	delivered := rec.count()

	for range 3 {
		if err := a.Send(&PDU{Type: PDUTypeX3, PayloadFormat: PayloadFormatIPv4}); err != nil {
			t.Fatalf("Send must never return an error: %v", err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if drops != 3 {
		t.Errorf("onDrop ran %d times for 3 PDUs offered to a closed sender, want 3", drops)
	}
	if got := rec.count(); got != delivered {
		t.Errorf("delivered %d PDUs after Close", got-delivered)
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
