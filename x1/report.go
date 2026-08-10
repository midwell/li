// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x1

import (
	"bytes"
	"context"
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
	// nothing, which only the ADMF can resolve.
	NEIssueContentUntasked = "contentUntasked"
	// The three places content can be lost on its way to the MDF each get their
	// own type, because the ADMF's response to them differs — datapath capacity,
	// this element's CPU, or the mediation function's ingest rate — and because
	// reports are throttled per type, so sharing one would let whichever fired
	// first hide the others.
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
	// NEIssueTaskingPurged: the keepalive fail-safe removed all tasking because the
	// party responsible for it went quiet. Interception has stopped — which is the
	// safe direction, since tasking must not outlive the authority for it — but the
	// ADMF has to know it happened rather than infer it from an absence of product.
	NEIssueTaskingPurged = "taskingPurged"
	// NEIssueReconcileFailed: this element could not establish what tasking a POI
	// still holds from before its restart, so it may have left interception running
	// that it cannot withdraw. It is an element-level condition rather than a task
	// one — which warrants they were is exactly what was lost — so it is reported
	// here rather than as a task issue, which would have to name an XID.
	NEIssueReconcileFailed = "reconcileFailed"
	// NEIssueTaskingAbsent: this element has come up with lawful interception
	// enabled and no tasking at all. On a first deployment that is simply true and
	// harmless; after a restart it is the only notice the ADMF gets that the
	// warrants it provisioned are gone, since tasking is held in memory and nothing
	// else announces the loss.
	NEIssueTaskingAbsent = "taskingAbsent"
	// NEIssueX3TagInvalid: the datapath delivered content whose correlation tag is
	// unusable, so the MDF cannot join the content to the session's signalling. The
	// interception is running but its product is not correlatable — a fault the ADMF
	// must know about even though content keeps flowing.
	NEIssueX3TagInvalid = "x3TagInvalid"
	// NEIssueContentTaskOverlap: more than one interception task covers the same
	// session, and this element delivers each duplicated packet under exactly one of
	// them. The task with the lowest XID receives the session's content in full and
	// the others receive none of it. Which warrants overlap is the ADMF's to know
	// and not this element's to say, so the report carries only that it happened.
	NEIssueContentTaskOverlap = "contentTaskOverlap"
	// NEIssueX1AuthFailed: a peer holding an LI-CA certificate tried to provision
	// this element under an identity it is not bound to, or one this element does
	// not answer to. Nothing is malfunctioning — the request was refused — but
	// somebody inside the LI trust domain is attempting to task or untask network
	// elements, and this channel is the only place that can be said.
	NEIssueX1AuthFailed = "x1AuthFailed"
)

// TS 103 221-1 table 6.5.4-1: TypeOfNEIssueMessage is a closed enumeration, not
// free text. Anything else is schema-invalid and a conformant ADMF discards the
// message — which for a fault channel means the fault is never heard.
const (
	neIssueWarning      = "Warning"
	neIssueFaultCleared = "FaultCleared"
	neIssueFaultReport  = "FaultReport"
	neIssueAlert        = "Alert"
)

// Status/fault and issue codes from TS 103 221-1 table 6.7-3, which the same table
// instructs implementers to use as specifically as they can. IssueCode is required
// when the code belongs to the section matching the message type.
const (
	issueCodeNonTerminatingFault = 9020
	issueCodeTerminatingFault    = 9030
	issueCodeKeepalivesNotRcvd   = 9050
	issueCodeDatabaseCleared     = 10000
)

// neIssueEncoding is how a condition this implementation knows about is expressed
// in the two fields the standard provides for it. The condition itself stays in
// the free-text description, where arbitrary strings are allowed and an ADMF can
// still tell one fault from another.
type neIssueEncoding struct {
	kind string
	code int
}

// neIssueEncodings maps each condition onto conformant fields. Where the registry
// has a code that names the condition exactly, it is used: a purge follows
// keepalives that stopped arriving (9050), and an element that has come up holding
// nothing is the "database cleared" the specification lists among the reasons to
// send this message at all (10000).
var neIssueEncodings = map[string]neIssueEncoding{
	NEIssueX1ListenFailed:  {neIssueFaultReport, issueCodeTerminatingFault},
	NEIssueX3EgressDown:    {neIssueFaultReport, issueCodeNonTerminatingFault},
	NEIssueMDFUnreachable:  {neIssueFaultReport, issueCodeNonTerminatingFault},
	NEIssueInvalidConfig:   {neIssueFaultReport, issueCodeNonTerminatingFault},
	NEIssueContentUntasked: {neIssueFaultReport, issueCodeNonTerminatingFault},
	NEIssueX3PuntLost:      {neIssueFaultReport, issueCodeNonTerminatingFault},
	NEIssueX3FramingLost:   {neIssueFaultReport, issueCodeNonTerminatingFault},
	NEIssueX3DeliveryLost:  {neIssueFaultReport, issueCodeNonTerminatingFault},
	NEIssueX3TagInvalid:    {neIssueFaultReport, issueCodeNonTerminatingFault},
	NEIssueReconcileFailed: {neIssueFaultReport, issueCodeNonTerminatingFault},
	// Nothing has broken — every packet is delivered under some warrant — so this is
	// a Warning rather than a FaultReport. What it warns of is that one warrant's
	// product is complete at the cost of another's being empty.
	NEIssueContentTaskOverlap: {neIssueWarning, issueCodeNonTerminatingFault},
	NEIssueTaskingPurged:      {neIssueFaultReport, issueCodeKeepalivesNotRcvd},
	NEIssueTaskingAbsent:      {neIssueAlert, issueCodeDatabaseCleared},
	// A rejected provisioning attempt is not a fault — nothing has broken and
	// interception is unaffected — so it is an Alert rather than a FaultReport, the
	// enumeration value clause 6.5.4 pairs with a current security issue on the NE.
	// It carries no issue code: that field is conditional, required only when the
	// condition appears in the registry's issue-code section, and that section holds
	// nothing security-related to name. Inventing a code, or borrowing a fault code
	// for something that is not a fault, would tell the ADMF something untrue.
	NEIssueX1AuthFailed: {neIssueAlert, 0},
}

// encodeNEIssue returns the wire fields for a condition. An unrecognised one still
// yields a valid message: emitting an invalid enumeration would lose the report
// entirely, which is worse than reporting it less specifically.
func encodeNEIssue(condition string) neIssueEncoding {
	if e, ok := neIssueEncodings[condition]; ok {
		return e
	}

	return neIssueEncoding{neIssueFaultReport, issueCodeNonTerminatingFault}
}

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
    <ns1:typeOfNeIssueMessage>{{esc .Kind}}</ns1:typeOfNeIssueMessage>
    <ns1:description>{{esc .Description}}</ns1:description>
{{- if .IssueCode}}
    <ns1:issueCode>{{.IssueCode}}</ns1:issueCode>
{{- end}}
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

// Notify reports an NE-level issue and discards the outcome. It is the form the
// network functions call: an issue report is best-effort by design — the LI plane
// must not surface faults through anything but this channel, so a failed report
// has nowhere to go and nothing to do — and expressing that as a
// void call keeps every call site from blank-assigning an error the linter then
// flags. A nil Reporter is a no-op, so a network function with no ADMF configured
// need not guard every call — though existing callers may still, and must when
// they hold the Reporter behind an interface (a nil interface value cannot be
// called at all).
//
// It stays silent on failure for the same reason ReportNEIssue does: writing the
// error anywhere general would be the very disclosure this plane exists to avoid.
func (r *Reporter) Notify(issueType, description string) {
	if r == nil {
		return
	}
	//nolint:errcheck // fire-and-forget by design; see the doc comment
	_ = r.ReportNEIssue(issueType, description)
}

// NotifyTask reports a per-task issue and discards the outcome — the task-scoped
// counterpart to Notify, wrapping ReportTaskIssue for the same reason.
func (r *Reporter) NotifyTask(xid, reportType, details string) {
	if r == nil {
		return
	}
	//nolint:errcheck // fire-and-forget by design; see the doc comment
	_ = r.ReportTaskIssue(xid, reportType, details)
}

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

	resp, err := r.postXML(r.admfURL, &body)
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

	// The condition leads the description because that is the only field on this
	// message where it may legitimately appear, and an ADMF still needs to tell one
	// fault from another.
	encoding := encodeNEIssue(issueType)

	var body bytes.Buffer
	if err := reportTemplate.Execute(&body, struct {
		AdmfID, NeID, Timestamp, TxID, Kind, Description string
		IssueCode                                        int
	}{
		AdmfID:      r.admfID,
		NeID:        r.neID,
		Timestamp:   r.now().Format(time.RFC3339Nano),
		TxID:        newUUID(),
		Kind:        encoding.kind,
		IssueCode:   encoding.code,
		Description: issueType + ": " + description,
	}); err != nil {
		return err
	}

	resp, err := r.postXML(r.admfURL, &body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("x1: ADMF returned status %d for NE issue report", resp.StatusCode)
	}
	return nil
}

// NewUUID returns a random RFC 4122 v4 UUID — the form TS 103 221-1 requires of
// an x1TransactionId, an XID and a DID alike. Exported because a Triggering
// Function allocates XIDs and DIDs of its own and should not reimplement the
// generator to do it.
func NewUUID() string {
	return newUUID()
}

// postXML sends an X1 request body to url and returns the response, which the
// caller must close. It exists so both report kinds go out the same way, and
// because net/http's Post helper carries no context — this plane's requests are
// bounded by the client's own timeout, but the linter is right that the shape
// should be explicit.
func (r *Reporter) postXML(url string, body *bytes.Buffer) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/xml")

	return r.client.Do(req)
}

// newUUID returns a random RFC 4122 v4 UUID for the x1TransactionId, without an
// external dependency (the li module has none).
func newUUID() string {
	var b [16]byte
	//nolint:errcheck // crypto/rand.Read never returns an error
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
