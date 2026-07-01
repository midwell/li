// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x1

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/xml"
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
	"esc": func(s string) string {
		var b bytes.Buffer
		_ = xml.EscapeText(&b, []byte(s))
		return b.String()
	},
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
