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

// TestNEStatusReportsUndeliverableTasking covers the one condition this package can observe
// without a POI's help: it holds tasking it cannot deliver the product of.
//
// This is a fault about the element, not about one task — the element is producing something
// that goes nowhere — and it is deliberately quantified rather than named. An NE-level answer
// says how much is wrong, never whose: naming the XID or the target here would put interception
// detail in an answer that is not scoped to a warrant.
func TestNEStatusReportsUndeliverableTasking(t *testing.T) {
	st := store.New()
	srv := NewServer(st, "neID")
	srv.now = func() time.Time { return zeroTailInstant }

	st.Activate(types.InterceptTask{
		XID:      testXID,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductCC},
		// No Deliveries: an ADMF named destinations this element never had.
	})

	got := statusOf(t, srv)
	if !strings.Contains(got, "<ns1:neStatus>Faults</ns1:neStatus>") {
		t.Errorf("a task that cannot be delivered is a fault about this element\ngot:\n%s", got)
	}
	if !strings.Contains(got, "1 task(s) require delivery but no destination resolves") {
		t.Errorf("the answer does not say what is wrong\ngot:\n%s", got)
	}
	for _, leak := range []string{string(testXID), "262019876543210"} {
		if strings.Contains(got, leak) {
			t.Errorf("the NE-level answer names %q; it must say how much is wrong, not whose", leak)
		}
	}

	// Give it somewhere to deliver, and the condition stops holding.
	st.Activate(types.InterceptTask{
		XID:      testXID,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductCC},
		Deliveries: []types.DeliveryEndpoint{
			{Type: types.DeliveryX3, Address: "10.0.60.122:42069"},
		},
	})
	if got := statusOf(t, srv); !strings.Contains(got, "<ns1:neStatus>OK</ns1:neStatus>") {
		t.Errorf("with a destination, want OK\ngot:\n%s", got)
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
