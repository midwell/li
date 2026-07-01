// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x1

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
)

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

	resp, err := srv.Process([]byte(activateXML))
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
	if _, err := srv.Process([]byte(activateXML)); err != nil {
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
	if _, err := srv.Process([]byte(modifyXML)); err != nil {
		t.Fatalf("modify: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("callback fired %d times after same-target modify, want 1 (must not re-scan)", len(got))
	}

	// A modify that RETARGETS to a different identifier must re-fire — the new
	// target's already-present state needs a start-of-interception scan too.
	retargetXML := strings.Replace(modifyXML, "2125552368", "5551234567", 1)
	if _, err := srv.Process([]byte(retargetXML)); err != nil {
		t.Fatalf("retarget modify: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("callback fired %d times after retarget modify, want 2", len(got))
	}
	if got[1].Target.Value != "5551234567" {
		t.Errorf("retarget callback target = %q, want 5551234567", got[1].Target.Value)
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

	resp, err := srv.Process([]byte(deactivateXML))
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

func TestServeHTTPRoundTrip(t *testing.T) {
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
	if len(decoded.Messages) != 1 || decoded.Messages[0].OK != "AcknowledgedAndCompleted" {
		t.Errorf("decoded response = %+v", decoded.Messages)
	}
	if _, ok := st.Get(testXID); !ok {
		t.Error("task not activated via HTTP")
	}
}

func TestRejectsUnknownAndBadTarget(t *testing.T) {
	st := store.New()
	srv := NewServer(st, "neID")

	// Unknown request type -> ErrorResponse, nothing stored.
	unknown := strings.Replace(activateXML, "ActivateTaskRequest", "FrobnicateRequest", 1)
	resp, err := srv.Process([]byte(unknown))
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
