// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x1

import (
	"strings"
	"testing"
	"time"

	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
)

// statusOf asks the element for its own status the way a provisioning function does, and
// returns the rendered answer.
func statusOf(t *testing.T, srv *Server) string {
	t.Helper()
	resp, err := srv.Process(request("GetNEStatusRequest", ""), admfPeer(t))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	out, err := marshalResponse(resp)
	if err != nil {
		t.Fatalf("marshalResponse: %v", err)
	}

	return string(out)
}

// TestNEStatusReportsConditionsThatHoldNow is the property the whole design rests on: the
// answer is computed when the question is asked.
//
// Every alternative — retaining pushed faults, expiring them, clearing them explicitly — can
// report a fault that has gone, or fail to report one that arrived. This cannot, and the test
// changes the condition *between* two requests to prove it.
func TestNEStatusReportsConditionsThatHoldNow(t *testing.T) {
	broken := false
	srv := NewServer(store.New(), "neID", WithFaultProbes(func() *X1Error {
		if !broken {
			return nil
		}

		return &X1Error{ErrorCode: 1000, ErrorDescription: "the mediation function is unreachable"}
	}))
	srv.now = func() time.Time { return zeroTailInstant }

	if got := statusOf(t, srv); !strings.Contains(got, "<ns1:neStatus>OK</ns1:neStatus>") {
		t.Errorf("with nothing wrong, want OK\ngot:\n%s", got)
	}

	broken = true
	got := statusOf(t, srv)
	if !strings.Contains(got, "<ns1:neStatus>Faults</ns1:neStatus>") {
		t.Errorf("with a condition holding, want Faults\ngot:\n%s", got)
	}
	if !strings.Contains(got, "the mediation function is unreachable") {
		t.Errorf("the condition is not listed\ngot:\n%s", got)
	}

	// Nothing clears it. The condition simply stops holding, and the next answer reflects
	// that — which is the point of computing rather than retaining.
	broken = false
	if got := statusOf(t, srv); !strings.Contains(got, "<ns1:neStatus>OK</ns1:neStatus>") {
		t.Errorf("once the condition cleared, want OK with no explicit clear\ngot:\n%s", got)
	}
}

// TestTaskWithNoResolvedDestinationIsNotAnElementFault guards a probe that was shipped and
// withdrawn, because re-adding it is the obvious thing to do while reading this package.
//
// "The element holds tasking that no destination resolves for" looks like a condition this
// package can observe alone, and it is — but it is not a *fault*, in any POI this library
// serves. The AMF delivers X2 to the MDF2 in its own configuration; the SMF provisions its
// configured MDF3 at the CC-POI; and the UPF, the one element that does deliver to a task's
// resolved destinations, refuses a content task without one before it is stored. So every
// ordinary task an ADMF provisions without DIDs satisfied the condition, and a deployed AMF
// answered "Faults" while delivering every record correctly.
//
// It was caught by running against a deployment and not by any test here, which is the
// interesting part: the condition is about how the *network functions* deliver, and this
// package cannot see that.
func TestTaskWithNoResolvedDestinationIsNotAnElementFault(t *testing.T) {
	st := store.New()
	srv := NewServer(st, "neID")
	srv.now = func() time.Time { return zeroTailInstant }

	// Exactly what an ADMF provisions when it names no destinations, which is the documented
	// and supported case for an IRI-POI.
	st.Activate(types.InterceptTask{
		XID:      testXID,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductIRI},
		// No Deliveries: the POI has an MDF address of its own.
	})

	if got := statusOf(t, srv); !strings.Contains(got, "<ns1:neStatus>OK</ns1:neStatus>") {
		t.Errorf("an ordinary task with no resolved destination made the element report itself "+
			"faulty; delivery does not come from the task in any POI this library serves\ngot:\n%s", got)
	}
}

// TestTaskFaultsStayOutOfTheElementStatus keeps the two levels apart, which TS 103 221-1
// separates explicitly: NE status is "OK" or "Faults i.e. NE losing traffic", and those are
// "separate from delivery faults which are reported per XID".
//
// A single warrant's delivery failing must not make the element report itself broken, or an
// ADMF cannot tell "this element is losing traffic" from "one of my warrants is not arriving" —
// and those need different responses.
func TestTaskFaultsStayOutOfTheElementStatus(t *testing.T) {
	st := store.New()
	srv := NewServer(st, "neID")
	srv.now = func() time.Time { return zeroTailInstant }

	// A perfectly deliverable task, plus a per-task fault reported elsewhere over
	// ReportTaskIssue. Nothing about it belongs in the element's own status.
	st.Activate(types.InterceptTask{
		XID:      testXID,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductIRI},
		Deliveries: []types.DeliveryEndpoint{
			{Type: types.DeliveryX2, Address: "10.0.60.122:42069"},
		},
	})

	if got := statusOf(t, srv); !strings.Contains(got, "<ns1:neStatus>OK</ns1:neStatus>") {
		t.Errorf("a task-level concern must not make the element faulty\ngot:\n%s", got)
	}

	// And the task's own fault list stays empty in what the element reports about the task:
	// task faults travel per XID, not in taskStatus.
	resp, err := srv.Process(request("GetTaskDetailsRequest",
		"\n    <ns1:xId>"+string(testXID)+"</ns1:xId>"), admfPeer(t))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	out, err := marshalResponse(resp)
	if err != nil {
		t.Fatalf("marshalResponse: %v", err)
	}
	if !strings.Contains(string(out), "<ns1:listOfFaults/>") {
		t.Errorf("taskStatus should carry an empty fault list\ngot:\n%s", out)
	}
}
