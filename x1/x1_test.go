// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x1

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
)

// keepaliveXML is a TS 103 221-1 KeepaliveRequest (ADMF→NE).
const keepaliveXML = `<ns1:X1Request xmlns:ns1="http://uri.etsi.org/03221/X1/2017/10" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <ns1:x1RequestMessage xsi:type="ns1:KeepaliveRequest">
    <ns1:admfIdentifier>admfID</ns1:admfIdentifier>
    <ns1:neIdentifier>neID</ns1:neIdentifier>
    <ns1:version>v1.6.1</ns1:version>
    <ns1:x1TransactionId>tx-ka</ns1:x1TransactionId>
  </ns1:x1RequestMessage>
</ns1:X1Request>`

func supiTarget(v string) types.TargetIdentifier {
	return types.TargetIdentifier{Type: types.TargetSUPI, Value: v}
}

// TestReportNEIssue checks the NE-initiated fault report is a well-formed X1
// ReportNEIssueRequest POSTed to the ADMF, carrying NE-level status only.
func TestReportNEIssue(t *testing.T) {
	var got []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	r := NewReporter(ts.URL, "admfID", "neID", nil)
	if err := r.ReportNEIssue(NEIssueX3EgressDown, "X3 egress socket unavailable"); err != nil {
		t.Fatalf("ReportNEIssue: %v", err)
	}

	body := string(got)
	for _, want := range []string{
		`xsi:type="ns1:ReportNEIssueRequest"`,
		"<ns1:neIdentifier>neID</ns1:neIdentifier>",
		// TypeOfNEIssueMessage is a closed enumeration. This assertion used to
		// require the condition string itself, which is how an entire fault channel
		// came to be schema-invalid without anything noticing (review R41).
		"<ns1:typeOfNeIssueMessage>FaultReport</ns1:typeOfNeIssueMessage>",
		// The condition still has to reach the ADMF — in the field that permits it.
		"x3EgressDown",
		"X3 egress socket unavailable",
		// And as specific a code as the registry offers.
		"<ns1:issueCode>9020</ns1:issueCode>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("report body missing %q\n%s", want, body)
		}
	}
	var probe struct{}
	if err := xml.Unmarshal(got, &probe); err != nil {
		t.Errorf("report body is not valid XML: %v", err)
	}
}

// TestKeepaliveWatchdogPurgesTasking checks the TS 103 221-1 fail-safe: if no X1
// message arrives within the window, all tasking is purged.
func TestKeepaliveWatchdogPurgesTasking(t *testing.T) {
	st := store.New()
	st.Activate(types.InterceptTask{XID: "a", Target: supiTarget("1")})
	srv := NewServer(st, "neID")
	now := time.Now()
	srv.now = func() time.Time { return now }
	srv.recordActivity() // ADMF last seen now

	now = now.Add(3 * time.Second) // within a 5s window
	srv.purgeIfLapsed(5 * time.Second)
	if len(st.Match(supiTarget("1"))) != 1 {
		t.Fatal("purged tasking while still within the keepalive window")
	}

	now = now.Add(5 * time.Second) // now 8s idle > 5s
	srv.purgeIfLapsed(5 * time.Second)
	if len(st.Match(supiTarget("1"))) != 0 {
		t.Error("keepalive lapsed but tasking was not purged")
	}
}

// TestKeepalivePurgeRunsDeactivateHook verifies the fail-safe purge runs the
// per-task OnDeactivate hook (so a POI tears down product it applied elsewhere,
// e.g. UPF CC duplication), clears the store, and is a no-op on subsequent
// lapsed ticks once the store is empty (review R19).
func TestKeepalivePurgeRunsDeactivateHook(t *testing.T) {
	st := store.New()
	st.Activate(types.InterceptTask{XID: "a", Target: supiTarget("1"), Products: []types.ProductType{types.ProductCC}})
	st.Activate(types.InterceptTask{XID: "b", Target: supiTarget("2"), Products: []types.ProductType{types.ProductCC}})
	var torn []types.XID
	srv := NewServer(st, "neID", OnDeactivate(func(task types.InterceptTask) {
		torn = append(torn, task.XID)
	}))
	now := time.Now()
	srv.now = func() time.Time { return now }
	srv.recordActivity()

	now = now.Add(10 * time.Second) // lapsed past a 5s window
	srv.purgeIfLapsed(5 * time.Second)
	if st.Len() != 0 {
		t.Fatalf("store not purged: %d tasks remain", st.Len())
	}
	if len(torn) != 2 {
		t.Fatalf("OnDeactivate ran %d times, want 2 (one per purged task)", len(torn))
	}

	// A second lapsed tick must not re-run the hook (nothing left to tear down).
	torn = nil
	now = now.Add(10 * time.Second)
	srv.purgeIfLapsed(5 * time.Second)
	if len(torn) != 0 {
		t.Errorf("second purge re-ran OnDeactivate %d times, want 0", len(torn))
	}
}

// TestKeepaliveResetsWatchdog checks that an inbound KeepaliveRequest is
// acknowledged and resets the watchdog.
func TestKeepaliveResetsWatchdog(t *testing.T) {
	st := store.New()
	st.Activate(types.InterceptTask{XID: "a", Target: supiTarget("1")})
	srv := NewServer(st, "neID")
	now := time.Now()
	srv.now = func() time.Time { return now }
	srv.recordActivity()

	now = now.Add(4 * time.Second)
	resp, err := srv.Process([]byte(keepaliveXML), admfPeer(t))
	if err != nil {
		t.Fatalf("keepalive: %v", err)
	}
	if resp.Messages[0].Type != "KeepaliveResponse" || resp.Messages[0].OK == "" {
		t.Errorf("keepalive response = %+v, want KeepaliveResponse/OK", resp.Messages[0])
	}

	now = now.Add(4 * time.Second) // 4s since the keepalive, < 5s window
	srv.purgeIfLapsed(5 * time.Second)
	if len(st.Match(supiTarget("1"))) != 1 {
		t.Error("keepalive should have reset the watchdog, but tasking was purged")
	}
}

// activateXML is the ETSI TS 103 221-1 ActivateTaskRequest from the sipgate
// simulator's sim-to-ne examples — an independent implementation's real output.
const activateXML = `<?xml version="1.0" encoding="UTF-8"?>
<ns1:X1Request xmlns:ns1="http://uri.etsi.org/03221/X1/2017/10" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <ns1:x1RequestMessage xsi:type="ns1:ActivateTaskRequest">
    <ns1:admfIdentifier>admfID</ns1:admfIdentifier>
    <ns1:neIdentifier>neID</ns1:neIdentifier>
    <ns1:messageTimestamp>2017-10-06T18:46:21.247432Z</ns1:messageTimestamp>
    <ns1:version>v1.6.1</ns1:version>
    <ns1:x1TransactionId>3741800e-971b-4aa9-85f4-466d2b1adc7f</ns1:x1TransactionId>
    <ns1:taskDetails>
      <ns1:xId>50b93d1e-1b53-4d63-aacb-e4d99811bc0b</ns1:xId>
      <ns1:targetIdentifiers>
        <ns1:targetIdentifier>
          <ns1:e164Number>2125552368</ns1:e164Number>
        </ns1:targetIdentifier>
      </ns1:targetIdentifiers>
      <ns1:deliveryType>X2andX3</ns1:deliveryType>
      <ns1:listOfDIDs>
        <ns1:dId>pre-shared-did</ns1:dId>
      </ns1:listOfDIDs>
    </ns1:taskDetails>
  </ns1:x1RequestMessage>
</ns1:X1Request>`

const testXID = types.XID("50b93d1e-1b53-4d63-aacb-e4d99811bc0b")

func TestProcessActivate(t *testing.T) {
	st := store.New()
	srv := NewServer(st, "neID")

	resp, err := srv.Process([]byte(activateXML), admfPeer(t))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	task, ok := st.Get(testXID)
	if !ok {
		t.Fatal("task was not activated in the store")
	}
	if task.Target.Type != types.TargetGPSI || task.Target.Value != "2125552368" {
		t.Errorf("target = %+v, want GPSI 2125552368", task.Target)
	}
	if !task.WantsProduct(types.ProductIRI) || !task.WantsProduct(types.ProductCC) {
		t.Errorf("products = %v, want IRI+CC (X2andX3)", task.Products)
	}
	if m := st.Match(task.Target); len(m) != 1 || m[0].XID != testXID {
		t.Errorf("Match(target) = %+v", m)
	}

	if len(resp.Messages) != 1 {
		t.Fatalf("got %d response messages, want 1", len(resp.Messages))
	}
	rm := resp.Messages[0]
	if rm.Type != "ActivateTaskResponse" || rm.OK != "AcknowledgedAndCompleted" {
		t.Errorf("response = %+v", rm)
	}
	if rm.X1TransactionID != "3741800e-971b-4aa9-85f4-466d2b1adc7f" || rm.NeIdentifier != "neID" {
		t.Errorf("response header = %+v", rm)
	}
}

func TestOnActivateCallback(t *testing.T) {
	st := store.New()
	var got []types.InterceptTask
	srv := NewServer(st, "neID", OnActivate(func(task types.InterceptTask) {
		got = append(got, task)
	}))

	// A fresh activation fires the callback exactly once, with the stored task.
	if _, err := srv.Process([]byte(activateXML), admfPeer(t)); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("callback fired %d times on activate, want 1", len(got))
	}
	if got[0].XID != testXID {
		t.Errorf("callback task XID = %q, want %q", got[0].XID, testXID)
	}

	// A modify of the same task must not re-fire (the target is already covered).
	modifyXML := strings.Replace(activateXML, "ActivateTaskRequest", "ModifyTaskRequest", 1)
	if _, err := srv.Process([]byte(modifyXML), admfPeer(t)); err != nil {
		t.Fatalf("modify: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("callback fired %d times after same-target modify, want 1 (must not re-scan)", len(got))
	}

	// A modify that RETARGETS to a different identifier must re-fire — the new
	// target's already-present state needs a start-of-interception scan too.
	retargetXML := strings.Replace(modifyXML, "2125552368", "5551234567", 1)
	if _, err := srv.Process([]byte(retargetXML), admfPeer(t)); err != nil {
		t.Fatalf("retarget modify: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("callback fired %d times after retarget modify, want 2", len(got))
	}
	if got[1].Target.Value != "5551234567" {
		t.Errorf("retarget callback target = %q, want 5551234567", got[1].Target.Value)
	}
}

// TestModifyRetargetRunsDeactivateHook verifies a retargeting ModifyTask tears
// down the OLD target's applied state via OnDeactivate (not only scanning the new
// target via OnActivate), so a warrant that moves to a new identifier does not
// leave stale product running for the old one (review R19/R15).
func TestModifyRetargetRunsDeactivateHook(t *testing.T) {
	st := store.New()
	var activated, deactivated []types.TargetIdentifier
	srv := NewServer(st, "neID",
		OnActivate(func(task types.InterceptTask) { activated = append(activated, task.Target) }),
		OnDeactivate(func(task types.InterceptTask) { deactivated = append(deactivated, task.Target) }),
	)
	if _, err := srv.Process([]byte(activateXML), admfPeer(t)); err != nil {
		t.Fatalf("activate: %v", err)
	}
	modifyXML := strings.Replace(activateXML, "ActivateTaskRequest", "ModifyTaskRequest", 1)

	// Same-target modify: no teardown, no re-scan.
	if _, err := srv.Process([]byte(modifyXML), admfPeer(t)); err != nil {
		t.Fatalf("modify: %v", err)
	}
	if len(deactivated) != 0 {
		t.Fatalf("same-target modify ran OnDeactivate %d times, want 0", len(deactivated))
	}

	// Retarget: OnDeactivate fires for the old target, OnActivate for the new.
	retargetXML := strings.Replace(modifyXML, "2125552368", "5551234567", 1)
	if _, err := srv.Process([]byte(retargetXML), admfPeer(t)); err != nil {
		t.Fatalf("retarget: %v", err)
	}
	if len(deactivated) != 1 || deactivated[0].Value != "2125552368" {
		t.Fatalf("retarget OnDeactivate = %+v, want one call for old target 2125552368", deactivated)
	}
	if len(activated) != 2 || activated[1].Value != "5551234567" {
		t.Fatalf("retarget OnActivate = %+v, want new target 5551234567", activated)
	}
}

// TestParseTargetIdentifierTypes locks in the target-identifier element names
// against the ETSI TS 103 221-1 XSD (verified verbatim: supiimsi/supinai/
// peiImei/peiImeisv/gpsiMsisdn/imsi/e164Number — the casing is the schema's own).
// Previously only e164Number was exercised.
func TestParseTargetIdentifierTypes(t *testing.T) {
	cases := []struct {
		elem, val string
		want      types.TargetIdentifierType
	}{
		{"supiimsi", "262019876543210", types.TargetSUPI},
		{"supinai", "user@example.com", types.TargetSUPI},
		{"peiImei", "35342500000001", types.TargetPEI},
		{"peiImeisv", "3534250000000151", types.TargetPEI},
		{"gpsiMsisdn", "4915123456789", types.TargetGPSI},
	}
	for _, c := range cases {
		st := store.New()
		srv := NewServer(st, "neID")
		body := strings.Replace(activateXML,
			"<ns1:e164Number>2125552368</ns1:e164Number>",
			"<ns1:"+c.elem+">"+c.val+"</ns1:"+c.elem+">", 1)
		if _, err := srv.Process([]byte(body), admfPeer(t)); err != nil {
			t.Fatalf("%s: Process: %v", c.elem, err)
		}
		task, ok := st.Get(testXID)
		if !ok {
			t.Fatalf("%s: task not activated", c.elem)
		}
		if task.Target.Type != c.want || task.Target.Value != c.val {
			t.Errorf("%s → target %+v, want {%s %q}", c.elem, task.Target, c.want, c.val)
		}
	}
}

func TestProcessDeactivate(t *testing.T) {
	st := store.New()
	st.Activate(types.InterceptTask{XID: testXID, Target: types.TargetIdentifier{Type: types.TargetGPSI, Value: "2125552368"}})
	srv := NewServer(st, "neID")

	deactivateXML := `<ns1:X1Request xmlns:ns1="http://uri.etsi.org/03221/X1/2017/10" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <ns1:x1RequestMessage xsi:type="ns1:DeactivateTaskRequest">
    <ns1:admfIdentifier>admfID</ns1:admfIdentifier>
    <ns1:neIdentifier>neID</ns1:neIdentifier>
    <ns1:version>v1.6.1</ns1:version>
    <ns1:x1TransactionId>tx-2</ns1:x1TransactionId>
    <ns1:xId>` + string(testXID) + `</ns1:xId>
  </ns1:x1RequestMessage>
</ns1:X1Request>`

	resp, err := srv.Process([]byte(deactivateXML), admfPeer(t))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if _, ok := st.Get(testXID); ok {
		t.Error("task still present after DeactivateTask")
	}
	if resp.Messages[0].Type != "DeactivateTaskResponse" || resp.Messages[0].OK != "AcknowledgedAndCompleted" {
		t.Errorf("response = %+v", resp.Messages[0])
	}
}

// TestServeHTTPWithoutCertificateRejected checks the handler is fail-closed when
// no client certificate reaches it — the shape of a request arriving over plain
// HTTP, or through a proxy that terminated TLS instead of passing it through
// (design D13). The response must still be well-formed X1 the ADMF can decode.
// The authorized round trip over real mutual TLS is TestServeHTTPMutualTLS.
func TestServeHTTPWithoutCertificateRejected(t *testing.T) {
	st := store.New()
	ts := httptest.NewServer(NewServer(st, "neID"))
	defer ts.Close()

	res, err := http.Post(ts.URL+"/X1/NE", "application/xml", strings.NewReader(activateXML))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}

	// The response body must be a well-formed X1Response our own decoder accepts.
	var decoded X1Response
	if err := xml.NewDecoder(res.Body).Decode(&decoded); err != nil {
		t.Fatalf("response is not valid X1Response XML: %v", err)
	}
	if len(decoded.Messages) != 1 {
		t.Fatalf("got %d messages, want 1", len(decoded.Messages))
	}
	if m := decoded.Messages[0]; m.ErrorInformation == nil || m.ErrorInformation.ErrorCode != errCodeADMFCertMismatch {
		t.Errorf("want error %d, got %+v", errCodeADMFCertMismatch, m)
	}
	if _, ok := st.Get(testXID); ok {
		t.Error("task activated without an authenticated ADMF")
	}
}

func TestRejectsUnknownAndBadTarget(t *testing.T) {
	st := store.New()
	srv := NewServer(st, "neID")

	// Unknown request type -> ErrorResponse, nothing stored.
	unknown := strings.Replace(activateXML, "ActivateTaskRequest", "FrobnicateRequest", 1)
	resp, err := srv.Process([]byte(unknown), admfPeer(t))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if resp.Messages[0].Type != "ErrorResponse" || resp.Messages[0].ErrorInformation == nil {
		t.Errorf("unknown type should yield ErrorResponse, got %+v", resp.Messages[0])
	}
	if st.Len() != 0 {
		t.Errorf("store should be empty after error, len=%d", st.Len())
	}
}

// TestTaskDetailsQueryAnswersWhatIsHeld is review R38: a network element keeps its
// tasking in memory, so a restart discards every warrant an ADMF provisioned and
// nothing pushes that fact anywhere. The ADMF's only recourse is to ask — so the
// answer has to be truthful about an absence, not merely about a presence.
func TestTaskDetailsQueryAnswersWhatIsHeld(t *testing.T) {
	st := store.New()
	peer := admfPeer(t)

	// A details query carries its xId at message level, not inside taskDetails, so
	// it is built rather than derived from the activate fixture.
	query := func(msgType, xid string) X1ResponseMessage {
		t.Helper()

		body := `<?xml version="1.0" encoding="UTF-8"?>
<ns1:X1Request xmlns:ns1="http://uri.etsi.org/03221/X1/2017/10" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <ns1:x1RequestMessage xsi:type="ns1:` + msgType + `">
    <ns1:admfIdentifier>admfID</ns1:admfIdentifier>
    <ns1:neIdentifier>neID</ns1:neIdentifier>
    <ns1:messageTimestamp>2017-10-06T18:46:21.247432Z</ns1:messageTimestamp>
    <ns1:version>v1.6.1</ns1:version>
    <ns1:x1TransactionId>3741800e-971b-4aa9-85f4-466d2b1adc7f</ns1:x1TransactionId>
    <ns1:xId>` + xid + `</ns1:xId>
  </ns1:x1RequestMessage>
</ns1:X1Request>`

		return processWith(t, st, peer, body).Messages[0]
	}

	const taskedXID = "50b93d1e-1b53-4d63-aacb-e4d99811bc0b"

	// Nothing tasked: asking about a warrant must say so rather than acknowledge.
	m := query("GetTaskDetailsRequest", taskedXID)
	if m.Type != "ErrorResponse" || m.ErrorInformation == nil || m.ErrorInformation.ErrorCode != errCodeNoSuchTask {
		t.Errorf("query against an untasked element = %+v, want error %d", m, errCodeNoSuchTask)
	}

	// Now task it, and the same query must report the task.
	if _, err := processWith(t, st, peer, activateXML), error(nil); err != nil {
		t.Fatal(err)
	}
	if st.Len() != 1 {
		t.Fatalf("setup: store holds %d tasks, want 1", st.Len())
	}

	m = query("GetTaskDetailsRequest", taskedXID)
	if m.Type != "GetTaskDetailsResponse" || len(m.Tasks) != 1 {
		t.Fatalf("query = %+v, want one task in a GetTaskDetailsResponse", m)
	}

	// The answer has to reach the wire, not just the struct: an ADMF compares it
	// against what it believes it provisioned.
	out, err := marshalResponse(&X1Response{Messages: []X1ResponseMessage{m}})
	if err != nil {
		t.Fatalf("marshalResponse: %v", err)
	}
	for _, want := range []string{"<ns1:taskResponseDetails>", "<ns1:taskDetails>", "<ns1:taskStatus>Active</ns1:taskStatus>"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("response missing %s\ngot:\n%s", want, out)
		}
	}

	// GetAllDetails reports everything held, which is what an audit needs.
	m = query("GetAllDetailsRequest", taskedXID)
	if m.Type != "GetAllDetailsResponse" || len(m.Tasks) != 1 {
		t.Errorf("GetAllDetails = %+v, want one task", m)
	}
}

// TestNEIssueEncodingsAreConformant checks every condition this implementation can
// report against the enumeration TS 103 221-1 actually defines. The failure this
// guards against is not subtle but was invisible: a value outside the enumeration
// is discarded by a conformant ADMF, so the fault it describes is never heard —
// and the test rig, which accepts anything, cannot tell the difference.
func TestNEIssueEncodingsAreConformant(t *testing.T) {
	allowed := map[string]bool{
		neIssueWarning: true, neIssueFaultCleared: true,
		neIssueFaultReport: true, neIssueAlert: true,
	}

	conditions := []string{
		NEIssueX1ListenFailed, NEIssueX3EgressDown, NEIssueMDFUnreachable,
		NEIssueInvalidConfig, NEIssueContentUntasked, NEIssueX3PuntLost,
		NEIssueX3FramingLost, NEIssueX3DeliveryLost, NEIssueX3TagInvalid,
		NEIssueReconcileFailed, NEIssueTaskingPurged, NEIssueTaskingAbsent,
		NEIssueX1AuthFailed,
	}

	// issueCode is conditional, not mandatory: it is required when the condition
	// appears in the registry's issue-code section. A refused provisioning attempt
	// does not — that section has nothing security-related — so omitting it is the
	// conformant choice, and borrowing an unrelated code would misdescribe it. Every
	// other condition must still carry one.
	codeOptional := map[string]bool{NEIssueX1AuthFailed: true}

	for _, c := range conditions {
		e, known := neIssueEncodings[c]
		if !known {
			t.Errorf("%s has no encoding, so it would be reported only generically", c)

			continue
		}

		if !allowed[e.kind] {
			t.Errorf("%s reports type %q, which is not one of the four the schema permits", c, e.kind)
		}

		if e.code == 0 && !codeOptional[c] {
			t.Errorf("%s carries no issue code; the standard asks for the most specific available", c)
		}
	}

	// An unknown condition must still produce a valid message: reporting a fault
	// less specifically beats having it discarded.
	if fallback := encodeNEIssue("something-added-later"); !allowed[fallback.kind] {
		t.Errorf("an unmapped condition yields type %q, which the schema does not permit", fallback.kind)
	}
}
