// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x1

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"text/template"
	"time"
)

// reportThrottle is the minimum interval between reports of the same issue type,
// so a persistent fault (e.g. an unreachable MDF hit on every event) does not
// flood the ADMF.
const reportThrottle = 30 * time.Second

// TS 103 221-1 typeOfNeIssueMessage values for the LI-plane faults a POI reports.
// These are NE-level (no target/warrant identifier). The exact XSD enumeration
// should be confirmed against a conformant ADMF during in-cluster e2e (group 7).
const (
	NEIssueX1ListenFailed = "x1ListenFailed"
	NEIssueX3EgressDown   = "x3EgressDown"
	NEIssueMDFUnreachable = "mdfUnreachable"
	NEIssueInvalidConfig  = "invalidConfig"
	// NEIssueContentUntasked: the datapath delivered content for a session no
	// interception task covers. A triggered POI cannot label such content with a
	// warrant, and a mediation function discards what it cannot attribute, so the
	// content is dropped — but an authorised interception may be silently producing
	// nothing, which only the ADMF can resolve (review R34).
	NEIssueContentUntasked = "contentUntasked"
	// The three places content can be lost on its way to the MDF each get their
	// own type, because the ADMF's response to them differs — datapath capacity,
	// this element's CPU, or the mediation function's ingest rate — and because
	// reports are throttled per type, so sharing one would let whichever fired
	// first hide the others (review R36).
	//
	// NEIssueX3PuntLost: the datapath could not hand the copy to this element at
	// all; its egress socket was full. Datapath-side capacity.
	NEIssueX3PuntLost = "x3PuntLost"
	// NEIssueX3FramingLost: this element received the copy but could not frame it
	// fast enough. Local CPU.
	NEIssueX3FramingLost = "x3FramingLost"
	// NEIssueX3DeliveryLost: the copy was framed but could not be delivered; the
	// queue toward the MDF was full. The mediation function is reachable but
	// slower than the offered rate.
	NEIssueX3DeliveryLost = "x3DeliveryLost"
	// NEIssueX3TagInvalid: the datapath delivered content whose correlation tag is
	// unusable, so the MDF cannot join the content to the session's signalling. The
	// interception is running but its product is not correlatable — a fault the ADMF
	// must know about even though content keeps flowing.
	NEIssueX3TagInvalid = "x3TagInvalid"
)

// Reporter sends NE-initiated X1 issue reports to the ADMF (ETSI TS 103 221-1
// ReportNEIssueRequest). It is how a POI surfaces LI-plane faults — X1 bind
// failure, X3 egress socket down, MDF delivery failing, invalid config — to the
// controlling ADMF over the authorized X1 channel, never to general operator
// logs. Reports carry only NE-level status (no target or warrant identifier),
// preserving undetectability.
type Reporter struct {
	admfURL string
	admfID  string
	neID    string
	client  *http.Client
	now     func() time.Time

	mu       sync.Mutex
	lastSent map[string]time.Time // per issue type, for throttling
}

// NewReporter returns a Reporter that POSTs to the ADMF's X1 endpoint admfURL
// over mutual TLS, identifying itself as neID to the ADMF admfID.
func NewReporter(admfURL, admfID, neID string, tlsConfig *tls.Config) *Reporter {
	return &Reporter{
		admfURL: admfURL,
		admfID:  admfID,
		neID:    neID,
		client: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
			Timeout:   10 * time.Second,
		},
		now:      func() time.Time { return time.Now().UTC() },
		lastSent: make(map[string]time.Time),
	}
}

// reportTemplate emits an X1Request carrying a ReportNEIssueRequest in the
// conventional ns1/xsi wire form (Go's encoding/xml can't produce the xsi:type
// QName cleanly), mirroring the response template.
var reportTemplate = template.Must(template.New("x1report").Funcs(template.FuncMap{
	"esc": escapeXML,
}).Parse(`<?xml version="1.0" encoding="UTF-8"?>
<ns1:X1Request xmlns:ns1="http://uri.etsi.org/03221/X1/2017/10" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <ns1:x1RequestMessage xsi:type="ns1:ReportNEIssueRequest">
    <ns1:admfIdentifier>{{esc .AdmfID}}</ns1:admfIdentifier>
    <ns1:neIdentifier>{{esc .NeID}}</ns1:neIdentifier>
    <ns1:messageTimestamp>{{esc .Timestamp}}</ns1:messageTimestamp>
    <ns1:version>v1.6.1</ns1:version>
    <ns1:x1TransactionId>{{esc .TxID}}</ns1:x1TransactionId>
    <ns1:typeOfNeIssueMessage>{{esc .IssueType}}</ns1:typeOfNeIssueMessage>
    <ns1:description>{{esc .Description}}</ns1:description>
  </ns1:x1RequestMessage>
</ns1:X1Request>`))

// TS 103 221-1 TaskReportType values (clause 6.5.2 / the published XSD
// enumeration). A Triggering Function uses these to tell the LIPF what became of
// an interception it was asked to arrange.
const (
	// TaskReportAllClear: a previously reported fault has cleared.
	TaskReportAllClear = "AllClear"
	// TaskReportWarning: something is wrong but the interception continues.
	TaskReportWarning = "Warning"
	// TaskReportNonTerminatingFault: a fault the interception survives.
	TaskReportNonTerminatingFault = "NonTerminatingFault"
	// TaskReportTerminatingFault: the interception cannot continue. This is what a
	// CC-TF sends when a triggered POI refuses or fails its trigger — the warrant
	// is authorised but no product will be produced, which only the LIPF can act on.
	TaskReportTerminatingFault = "TerminatingFault"
)

// reportTaskTemplate emits an X1Request carrying a ReportTaskIssueRequest. Element
// order follows the ReportTaskIssueRequest xs:sequence: xId, taskReportType, then
// the optional error code and details.
var reportTaskTemplate = template.Must(template.New("x1taskissue").Funcs(template.FuncMap{
	"esc": escapeXML,
}).Parse(`<?xml version="1.0" encoding="UTF-8"?>
<ns1:X1Request xmlns:ns1="http://uri.etsi.org/03221/X1/2017/10" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <ns1:x1RequestMessage xsi:type="ns1:ReportTaskIssueRequest">
    <ns1:admfIdentifier>{{esc .AdmfID}}</ns1:admfIdentifier>
    <ns1:neIdentifier>{{esc .NeID}}</ns1:neIdentifier>
    <ns1:messageTimestamp>{{esc .Timestamp}}</ns1:messageTimestamp>
    <ns1:version>v1.6.1</ns1:version>
    <ns1:x1TransactionId>{{esc .TxID}}</ns1:x1TransactionId>
    <ns1:xId>{{esc .XID}}</ns1:xId>
    <ns1:taskReportType>{{esc .ReportType}}</ns1:taskReportType>
{{- if .Details}}
    <ns1:taskIssueDetails>{{esc .Details}}</ns1:taskIssueDetails>
{{- end}}
  </ns1:x1RequestMessage>
</ns1:X1Request>`))

// ReportTaskIssue POSTs a ReportTaskIssueRequest to the ADMF for a specific
// interception task. TS 33.128 clause 5.2.6 requires this of a Triggering
// Function whose triggered POI answers an error: the warrant exists and is
// authorised, but the product it authorises is not being produced, and the
// triggering function is the only party that knows.
//
// Unlike ReportNEIssue this names an XID, because the issue is with one
// interception rather than with the element. It is therefore not throttled — each
// task's failure is its own fact — and details must still describe the fault
// without naming the target.
func (r *Reporter) ReportTaskIssue(xid, reportType, details string) error {
	var body bytes.Buffer
	if err := reportTaskTemplate.Execute(&body, struct {
		AdmfID, NeID, Timestamp, TxID, XID, ReportType, Details string
	}{
		AdmfID:     r.admfID,
		NeID:       r.neID,
		Timestamp:  r.now().Format(time.RFC3339Nano),
		TxID:       newUUID(),
		XID:        xid,
		ReportType: reportType,
		Details:    details,
	}); err != nil {
		return err
	}

	resp, err := r.client.Post(r.admfURL, "application/xml", &body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("x1: ADMF returned status %d for task issue report", resp.StatusCode)
	}
	return nil
}

// ReportNEIssue POSTs a ReportNEIssueRequest to the ADMF. issueType is a
// TS 103 221-1 typeOfNeIssueMessage (see the NEIssue* constants); description is
// human-readable NE-level text that MUST NOT contain a target or warrant
// identifier. Best-effort — the caller may ignore the returned error.
func (r *Reporter) ReportNEIssue(issueType, description string) error {
	// Throttle repeats of the same issue type so a persistent fault does not
	// flood the ADMF; safe to call on every failed event.
	r.mu.Lock()
	if last, ok := r.lastSent[issueType]; ok && r.now().Sub(last) < reportThrottle {
		r.mu.Unlock()
		return nil
	}
	r.lastSent[issueType] = r.now()
	r.mu.Unlock()

	var body bytes.Buffer
	if err := reportTemplate.Execute(&body, struct {
		AdmfID, NeID, Timestamp, TxID, IssueType, Description string
	}{
		AdmfID:      r.admfID,
		NeID:        r.neID,
		Timestamp:   r.now().Format(time.RFC3339Nano),
		TxID:        newUUID(),
		IssueType:   issueType,
		Description: description,
	}); err != nil {
		return err
	}

	resp, err := r.client.Post(r.admfURL, "application/xml", &body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("x1: ADMF returned status %d for NE issue report", resp.StatusCode)
	}
	return nil
}

// newUUID returns a random RFC 4122 v4 UUID for the x1TransactionId, without an
// external dependency (the li module has none).
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
