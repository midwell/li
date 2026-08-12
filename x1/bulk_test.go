// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x1

import (
	"testing"
	"time"

	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
)

// TestDeactivateAllTasksTearsDownWhatItRemoves is the assertion this operation exists to
// satisfy, and the one an implementation is most likely to miss.
//
// Emptying the task list is the easy half. The dangerous half is the side effects: a CC-POI
// told to duplicate a subject's traffic keeps duplicating it, the element reports no tasking,
// an auditing ADMF agrees — and interception continues with its product going nowhere
// attributable. So this asserts the teardown hook ran for every task, which is what withdraws
// duplication.
func TestDeactivateAllTasksTearsDownWhatItRemoves(t *testing.T) {
	st := store.New()
	var tornDown []types.XID
	srv := NewServer(st, "neID", OnDeactivate(func(task types.InterceptTask) {
		tornDown = append(tornDown, task.XID)
	}))
	srv.now = func() time.Time { return zeroTailInstant }

	for _, xid := range []types.XID{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"} {
		st.Activate(types.InterceptTask{
			XID:      xid,
			Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
			Products: []types.ProductType{types.ProductCC},
		})
	}

	resp, err := srv.Process(request("DeactivateAllTasksRequest", ""), admfPeer(t))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if resp.Messages[0].OK == "" {
		t.Fatalf("bulk deactivation was not acknowledged: %+v", resp.Messages[0])
	}

	if st.Len() != 0 {
		t.Errorf("store still holds %d task(s)", st.Len())
	}
	if len(tornDown) != 2 {
		t.Errorf("teardown ran for %d task(s), want 2 — emptying the list without tearing down "+
			"leaves a subject's traffic duplicated with nothing to attribute it to", len(tornDown))
	}
}

// TestDeactivateAllTasksIsEnabledByDefault pins the specification's default, which is the
// surprising one: "By default (if there has been no agreement in advance) then
// DeactivateAllTasks is enabled."
//
// An element with no option set will stop every interception on one authenticated message.
// That is what the standard requires, and it is pinned here so nobody quietly makes it
// opt-in because it feels safer.
func TestDeactivateAllTasksIsEnabledByDefault(t *testing.T) {
	st := store.New()
	st.Activate(types.InterceptTask{
		XID:      testXID,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductIRI},
	})
	srv := NewServer(st, "neID")
	srv.now = func() time.Time { return zeroTailInstant }

	if _, err := srv.Process(request("DeactivateAllTasksRequest", ""), admfPeer(t)); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if st.Len() != 0 {
		t.Error("bulk deactivation is enabled by default and did not take effect")
	}
}

// TestBulkOperationsRefuseWithTheSpecifiedText checks the two refusals against the
// specification's own strings and codes.
//
// The text matters because an ADMF may match on it, and the codes matter more: the standard
// defines 5010 and 8020 for exactly these two conditions, and a generic 1000 would leave an
// ADMF unable to tell "you have this switched off" from "something went wrong".
func TestBulkOperationsRefuseWithTheSpecifiedText(t *testing.T) {
	cases := []struct {
		name     string
		opts     []Option
		req      string
		wantText string
		wantCode int
	}{
		{
			name: "DeactivateAllTasks, disabled", opts: []Option{WithoutDeactivateAllTasks()},
			req: "DeactivateAllTasksRequest",
			// "message", per the specification.
			wantText: "DeactivateAllTasks message is not enabled", wantCode: 5010,
		},
		{
			name: "RemoveAllDestinations, disabled by default", opts: nil,
			req: "RemoveAllDestinationsRequest",
			// "request" here, where the other says "message". The specification's own
			// asymmetry, preserved rather than tidied.
			wantText: "RemoveAllDestinations request is not enabled", wantCode: 8020,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := NewServer(store.New(), "neID", c.opts...)
			srv.now = func() time.Time { return zeroTailInstant }

			resp, err := srv.Process(request(c.req, ""), admfPeer(t))
			if err != nil {
				t.Fatalf("Process: %v", err)
			}
			m := resp.Messages[0]
			if m.ErrorInformation == nil {
				t.Fatalf("want a refusal, got %+v", m)
			}
			if m.ErrorInformation.ErrorDescription != c.wantText {
				t.Errorf("description = %q, want the specification's own %q",
					m.ErrorInformation.ErrorDescription, c.wantText)
			}
			if m.ErrorInformation.ErrorCode != c.wantCode {
				t.Errorf("code = %d, want %d", m.ErrorInformation.ErrorCode, c.wantCode)
			}
		})
	}
}

// TestRemoveAllDestinationsRefusesWhileReferenced covers the specification's guard: "an NE
// shall respond with an error if the ADMF sends a RemoveAllDestinations request while any of
// the Destinations are referenced by Tasks."
//
// The guard matters for the same reason RequireResolvableDIDs does. A task whose destination
// has been removed is a task producing product with nowhere to send it, and the element would
// have caused that itself.
func TestRemoveAllDestinationsRefusesWhileReferenced(t *testing.T) {
	st := store.New()
	srv := NewServer(st, "neID", WithRemoveAllDestinations())
	srv.now = func() time.Time { return zeroTailInstant }
	srv.destinations[testDID] = types.DeliveryEndpoint{
		Type: types.DeliveryX2, Address: "10.0.60.122:42069",
	}

	// A task naming that destination.
	st.Activate(types.InterceptTask{
		XID:      testXID,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductIRI},
		DIDs:     []string{testDID},
	})

	resp, err := srv.Process(request("RemoveAllDestinationsRequest", ""), admfPeer(t))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if resp.Messages[0].ErrorInformation == nil {
		t.Fatal("removal was permitted while a task still referenced a destination")
	}
	// 8010, "Destinations in use", not the generic 1000. The distinction is the same one the
	// disabled-operation codes make: this refusal tells an ADMF to deactivate its tasking and
	// retry, and a generic code tells it only that something went wrong.
	if code := resp.Messages[0].ErrorInformation.ErrorCode; code != errCodeDestinationsInUse {
		t.Errorf("code = %d, want %d", code, errCodeDestinationsInUse)
	}
	if _, held := srv.destinationByDID(testDID); !held {
		t.Error("the destination was removed despite the refusal")
	}

	// With the task gone, the same request succeeds.
	st.Deactivate(testXID)
	resp, err = srv.Process(request("RemoveAllDestinationsRequest", ""), admfPeer(t))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if resp.Messages[0].ErrorInformation != nil {
		t.Fatalf("want removal to succeed once unreferenced, got %+v", resp.Messages[0].ErrorInformation)
	}
	if _, held := srv.destinationByDID(testDID); held {
		t.Error("the destination survived an accepted removal")
	}
}

// TestBulkDeactivationSharesTheFailSafePath checks that the two ways of removing all tasking
// behave identically, because they are the same code.
//
// A second implementation of "deactivate everything" is how one of them ends up forgetting the
// teardown. If this test ever needs different expectations for the two paths, that is the
// symptom.
func TestBulkDeactivationSharesTheFailSafePath(t *testing.T) {
	run := func(viaKeepalive bool) []types.XID {
		st := store.New()
		var tornDown []types.XID
		srv := NewServer(st, "neID", OnDeactivate(func(task types.InterceptTask) {
			tornDown = append(tornDown, task.XID)
		}))
		base := zeroTailInstant
		srv.now = func() time.Time { return base }
		st.Activate(types.InterceptTask{
			XID:      testXID,
			Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
			Products: []types.ProductType{types.ProductCC},
		})

		if viaKeepalive {
			srv.lastSeen = base.Add(-time.Hour)
			srv.purgeIfLapsed(time.Minute)
		} else if _, err := srv.Process(request("DeactivateAllTasksRequest", ""), admfPeer(t)); err != nil {
			t.Fatalf("Process: %v", err)
		}
		if st.Len() != 0 {
			t.Errorf("tasking survived (viaKeepalive=%v)", viaKeepalive)
		}

		return tornDown
	}

	if a, b := run(true), run(false); len(a) != len(b) {
		t.Errorf("the fail-safe tore down %d task(s) and the bulk request %d; they are meant to "+
			"be the same path", len(a), len(b))
	}
}
