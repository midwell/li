// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blockingADMF is an ADMF a test can make hold a request open, refuse it, or answer
// it. The fault channel's new obligations are all about what it learns from its own
// sends, so a stub that only records what arrived cannot drive any of them.
type blockingADMF struct {
	srv *httptest.Server

	// A cancellable context rather than a channel a test closes: the builtin close is
	// shadowed at package scope in response.go, so it is not reachable from a test in
	// this package. Cancel broadcasts to every held handler and is idempotent, which
	// is what a release gate needs anyway.
	release context.Context
	unhold  context.CancelFunc

	status   atomic.Int32
	hold     atomic.Bool
	inFlight atomic.Int32
	peak     atomic.Int32
	total    atomic.Int32
}

func newBlockingADMF(t *testing.T) *blockingADMF {
	t.Helper()

	a := &blockingADMF{}
	a.release, a.unhold = context.WithCancel(context.Background())
	a.status.Store(http.StatusOK)
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := a.inFlight.Add(1)
		for {
			peak := a.peak.Load()
			if n <= peak || a.peak.CompareAndSwap(peak, n) {
				break
			}
		}
		a.total.Add(1)

		if a.hold.Load() {
			<-a.release.Done()
		}
		a.inFlight.Add(-1)
		w.WriteHeader(int(a.status.Load()))
	}))
	// Unblock before Close: Close waits for handlers to return, so a held request
	// would deadlock the cleanup rather than fail the test.
	t.Cleanup(func() {
		a.unblock()
		a.srv.Close()
	})

	return a
}

func (a *blockingADMF) unblock() {
	a.hold.Store(false)
	a.unhold()
}

// awaitTotal waits for n requests to have reached the ADMF.
func (a *blockingADMF) awaitTotal(t *testing.T, n int32) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a.total.Load() >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("only %d reports reached the ADMF, want %d", a.total.Load(), n)
}

// awaitSettled waits for the reporter to have finished with k, so a test can ask what
// the send established rather than what it attempted.
func awaitSettled(t *testing.T, r *Reporter, k reportKey) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		sending := r.sending[k]
		r.mu.Unlock()
		if !sending {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the report never settled")
}

// fixedClock gives a test control of the throttle window without sleeping through it.
func fixedClock(r *Reporter) (advance func(time.Duration)) {
	var (
		mu  sync.Mutex
		now = time.Now().UTC()
	)
	r.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()

		return now
	}

	return func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}
}

// TestAConditionAtPacketRateCostsOneAttempt is the property that makes NotifyAsync
// usable where `go Notify` is not, and it is a property of the *ordering* of the
// throttle against the dispatch rather than of either on its own.
//
// The UPF reports x3FramingLost from the loop that receives copies, so the condition
// recurs per dropped packet. Spawning first and deciding inside the goroutine would
// spawn one per copy — each taking the reporter's mutex, discovering it is throttled
// and exiting — which trades a stall for unbounded goroutine churn on the one path
// that must stay cheap. Deciding first costs a mutex for every copy after the first.
//
// The ADMF holds its answer throughout, because that is when the distinction is
// visible: while an attempt is outstanding the key stays reserved, so the burst
// produces exactly one attempt however long the ADMF takes.
func TestAConditionAtPacketRateCostsOneAttempt(t *testing.T) {
	admf := newBlockingADMF(t)
	admf.hold.Store(true)

	r := NewReporter(admf.srv.URL, "admfID", "neID", nil)
	advance := fixedClock(r)

	const burst = 10000

	goroutinesBefore := runtime.NumGoroutine()
	peakGoroutines := 0
	sample := func() {
		if n := runtime.NumGoroutine() - goroutinesBefore; n > peakGoroutines {
			peakGoroutines = n
		}
	}

	// **Sampled during the burst and not after it**, which is the difference between
	// a test that drives this property and one that only looks as if it does. The
	// goroutines `go Notify` spawns are short-lived — each finds the key reserved,
	// takes the mutex and exits — so a count taken once the loop has finished sees
	// them already gone and passes against the shape that was rejected. Measured this
	// way the two are two orders of magnitude apart: 1 against roughly 160.
	//
	// A synchronous reporter never returns from the first of these at all, because the
	// ADMF is holding it: that failure mode is a hung test, which is precisely what
	// the read loop would do to the datapath queue behind it.
	start := time.Now()
	for i := range burst {
		r.NotifyAsync(NEIssueX3FramingLost, "content copies dropped before framing")
		if i%10 == 0 {
			sample()
		}
	}
	elapsed := time.Since(start)
	sample()

	if elapsed > 2*time.Second {
		t.Errorf("%d reports cost the observing path %s; it must not wait on the ADMF", burst, elapsed)
	}
	// Generous, because it is a mutation detector and not a budget: the fix holds this
	// at 1 and `go Notify` spawns one per copy.
	if peakGoroutines > 25 {
		t.Errorf("the burst reached %d concurrent goroutines; the dispatch is not bounded by the condition", peakGoroutines)
	}

	admf.awaitTotal(t, 1)
	if peak := admf.peak.Load(); peak != 1 {
		t.Errorf("%d concurrent attempts reached the ADMF, want 1", peak)
	}

	admf.unblock()
	k := reportKey{scope: scopeElement, condition: NEIssueX3FramingLost}
	awaitSettled(t, r, k)

	// The window starts at the delivered send, so the condition recurring inside it is
	// still one report.
	r.NotifyAsync(NEIssueX3FramingLost, "content copies dropped before framing")
	awaitSettled(t, r, k)
	if total := admf.total.Load(); total != 1 {
		t.Errorf("%d reports inside one throttle window, want 1", total)
	}

	// And past it, the same condition is reported again: a throttle is a rate limit,
	// not a record that the fault has been dealt with.
	advance(reportThrottle + time.Second)
	r.NotifyAsync(NEIssueX3FramingLost, "content copies dropped before framing")
	admf.awaitTotal(t, 2)
}

// TestAFailedReportIsNotRecordedAsMade pins the accuracy half: the element's account
// of what it has told the ADMF must not diverge from what the ADMF heard.
//
// Committing in front of the send made it diverge twice over. The condition was
// suppressed for a window although nothing was delivered, and — the lasting half — it
// entered the reported set, so if it then cleared, the element retracted a fault the
// ADMF had never been told about: announcing the end of something that, as far as the
// receiver knows, never began.
func TestAFailedReportIsNotRecordedAsMade(t *testing.T) {
	admf := newBlockingADMF(t)
	r := NewReporter(admf.srv.URL, "admfID", "neID", nil)

	admf.status.Store(http.StatusInternalServerError)
	r.NotifyElementFault(NEIssueMDFUnreachable, "MDF3 delivery failing")
	admf.awaitTotal(t, 1)

	// The condition goes away before anyone re-observes it. Nothing may be retracted,
	// because there is nothing at the ADMF for a retraction to refer to.
	sent := admf.total.Load()
	r.NotifyElementClear(NEIssueMDFUnreachable)
	if got := admf.total.Load(); got != sent {
		t.Errorf("a fault the ADMF never received was retracted (%d messages, want %d)", got, sent)
	}

	// And the same condition observed again is reported again rather than suppressed
	// as a repeat of the report that failed. No clock advance: the window never
	// started, because nothing was delivered.
	admf.status.Store(http.StatusOK)
	r.NotifyElementFault(NEIssueMDFUnreachable, "MDF3 delivery failing")
	admf.awaitTotal(t, sent+1)
}

// TestAFailedRetractionLeavesTheFaultRetractable is the other direction, and the one
// with no self-correction: a fault is re-observed and reported again, but nothing
// re-observes a fault that has gone away. Forgetting it in front of the send left the
// ADMF holding a fault this element believed it had cleared and would never mention.
func TestAFailedRetractionLeavesTheFaultRetractable(t *testing.T) {
	admf := newBlockingADMF(t)
	r := NewReporter(admf.srv.URL, "admfID", "neID", nil)

	r.NotifyElementFault(NEIssueX3EgressDown, "X3 egress socket unavailable")
	admf.awaitTotal(t, 1)

	admf.status.Store(http.StatusInternalServerError)
	r.NotifyElementClear(NEIssueX3EgressDown)
	admf.awaitTotal(t, 2)

	admf.status.Store(http.StatusOK)
	r.NotifyElementClear(NEIssueX3EgressDown)
	admf.awaitTotal(t, 3)

	// Retracted once it has actually been retracted, and not before: a fourth attempt
	// finds nothing to clear.
	before := admf.total.Load()
	r.NotifyElementClear(NEIssueX3EgressDown)
	if got := admf.total.Load(); got != before {
		t.Errorf("a fault already retracted was retracted again (%d messages, want %d)", got, before)
	}
}
