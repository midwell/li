// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x1

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
)

// TestAnActivationRacingTheFailSafePurgeLeavesNoOrphan drives the interleaving the
// transition lock exists for, rather than reasoning about it.
//
// A purge reads the tasks it holds and then empties the store. A task activated in
// between is removed from the store without its teardown ever running, so three things
// are true at once: the ADMF has been told the task is active, the element holds
// nothing, and the POI is still applying it. At a triggering function that is content
// interception surviving a purge meant to stop everything — kept alive by the
// keepalives the forgotten trigger goes on earning, and ended only by session release.
//
// The invariant asserted is the one that admits both legal outcomes and excludes the
// orphan: either the store holds the task and the POI was told to apply it, or the
// store holds nothing and the POI was told it was gone. Never a store holding nothing
// while the POI still applies it.
func TestAnActivationRacingTheFailSafePurgeLeavesNoOrphan(t *testing.T) {
	st := store.New()

	var (
		mu      sync.Mutex
		applied bool // what the POI was last told: applied, or removed
		told    bool
	)
	srv := NewServer(st, "neID", OnTaskChange(func(_, next *types.InterceptTask) {
		mu.Lock()
		defer mu.Unlock()
		told = true
		applied = next != nil
	}))

	// The purge is held open between its snapshot and its clear, because that window
	// is a few instructions wide: racing two goroutines at it passes against the
	// defect, which is how this property would have been "verified" without ever
	// reaching the interleaving.
	inWindow := make(chan struct{}, 1)
	proceed := make(chan struct{}, 1)
	afterPurgeSnapshot = func() { inWindow <- struct{}{}; <-proceed }
	t.Cleanup(func() { afterPurgeSnapshot = nil })

	// Lapsed by construction: any idle time exceeds a zero window. Driven through
	// purgeIfLapsed so the path under test is the one the watchdog takes.
	srv.mu.Lock()
	srv.lastSeen = srv.now().Add(-time.Hour)
	srv.mu.Unlock()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.purgeIfLapsed(0)
	}()

	<-inWindow // the purge has read what it will tear down and has not cleared yet

	wg.Add(1)
	go func() {
		defer wg.Done()
		//nolint:errcheck // the acknowledgement is not what this asserts on
		_, _ = srv.Process([]byte(activateXML), admfPeer(t))
	}()

	// Long enough for the activation to land if nothing stops it. Under the
	// transition lock it does not land here at all — it waits, and runs after the
	// purge — which is the fix; without it, it stores the task and tells the POI to
	// apply it inside a window the purge is about to wipe without telling anyone.
	time.Sleep(100 * time.Millisecond)
	proceed <- struct{}{}
	wg.Wait()

	_, held := st.Get(testXID)

	mu.Lock()
	lastApplied, wasTold := applied, told
	mu.Unlock()

	switch {
	case held && (!wasTold || !lastApplied):
		t.Fatalf("the element holds the task and the POI was not told to apply it "+
			"(told=%v applied=%v)", wasTold, lastApplied)
	case !held && wasTold && lastApplied:
		t.Fatal("the store holds nothing and the POI is still applying the task — content " +
			"interception that survived a purge meant to stop everything, with the ADMF " +
			"acknowledged and nothing left to withdraw it")
	}
}

// TestConcurrentOperationsOnOneXIDEndConsistent is the same property for the ordinary
// case: two operations naming one task, both acknowledged, and a POI whose last
// instruction has to describe the tasking the element actually ended up with.
//
// **What this is evidence of, and what it is not.** It runs the two operations against
// each other many times and holds under -race, which is worth having. It is not
// mutation evidence: with the lock removed it still passes, because the interleaving
// that breaks the invariant is a few instructions wide and racing goroutines do not
// reliably land in it. The deterministic evidence for the lock is
// TestAnActivationRacingTheFailSafePurgeLeavesNoOrphan, which holds the window open.
func TestConcurrentOperationsOnOneXIDEndConsistent(t *testing.T) {
	const rounds = 100

	deactivateXML := strings.Replace(
		strings.Replace(activateXML, "ActivateTaskRequest", "DeactivateTaskRequest", 1),
		"ActivateTaskRequest", "DeactivateTaskRequest", 1)

	for round := range rounds {
		st := store.New()

		var (
			mu      sync.Mutex
			applied bool
			told    bool
		)
		srv := NewServer(st, "neID", OnTaskChange(func(_, next *types.InterceptTask) {
			mu.Lock()
			defer mu.Unlock()
			told = true
			applied = next != nil
		}))

		if _, err := srv.Process([]byte(activateXML), admfPeer(t)); err != nil {
			t.Fatalf("seeding the task: %v", err)
		}

		var wg sync.WaitGroup

		wg.Add(2)
		go func() {
			defer wg.Done()
			//nolint:errcheck // acknowledgement not asserted on
			_, _ = srv.Process([]byte(activateXML), admfPeer(t))
		}()
		go func() {
			defer wg.Done()
			//nolint:errcheck // acknowledgement not asserted on
			_, _ = srv.Process([]byte(deactivateXML), admfPeer(t))
		}()
		wg.Wait()

		_, held := st.Get(testXID)

		mu.Lock()
		lastApplied, wasTold := applied, told
		mu.Unlock()

		if !wasTold {
			continue
		}
		if held != lastApplied {
			t.Fatalf("round %d: store holds=%v but the POI was last told applied=%v; "+
				"the notification does not describe the tasking the element holds", round, held, lastApplied)
		}
	}
}

// TestAProbeIsReachableFromInsideACallback pins the risk the transition lock
// introduces, from the side that can actually be asserted.
//
// The POI callbacks run under the lock, so anything a callback calls that also takes it
// deadlocks the provisioning interface outright. Two things follow, and only the second
// is testable here. A callback must not call a Server *transition* method — no callback
// does, they reach the POI's own state — and that would hang rather than fail, which is
// why it is stated in transitionMu's comment rather than asserted. But the fault probes
// and recordActivity must stay reachable while a transition is in flight, because they
// are documented as safe to call from the X1 request goroutine and a GetNEStatus that
// queued behind a DeactivateTask's session walk would break that contract. This drives
// exactly that: both are called from inside a callback, with the transition lock held.
//
// It is the kind of property that holds until somebody adds a convenient-looking lock,
// which is the same reasoning as TestLIBlockCannotReturnFromStart.
func TestAProbeIsReachableFromInsideACallback(t *testing.T) {
	st := store.New()

	// A buffered send rather than close: the builtin close is shadowed at package
	// scope in response.go and is not reachable from a test in this package.
	reached := make(chan struct{}, 1)

	var srv *Server

	srv = NewServer(st, "neID",
		WithFaultProbes(func() *X1Error { return nil }),
		OnTaskChange(func(_, _ *types.InterceptTask) {
			// Under the transition lock, on the same server. Both of these take mu and
			// must not take transitionMu.
			srv.recordActivity()
			_ = srv.unresolvedFaults()
			reached <- struct{}{}
		}))

	if _, err := srv.Process([]byte(activateXML), admfPeer(t)); err != nil {
		t.Fatalf("activate: %v", err)
	}

	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("a fault probe or recordActivity could not run while a transition was in " +
			"flight; they are behind the transition lock and an interrogation now queues " +
			"behind a POI callback")
	}
}
