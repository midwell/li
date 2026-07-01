// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x1

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
)

const maxRequestBytes = 1 << 20

// responseTemplate emits an X1Response in the conventional TS 103 221-1 wire
// form (xsi/ns1 prefixes, xsi:type QName), which Go's encoding/xml can't
// produce cleanly. Input is still parsed structurally with encoding/xml.
var responseTemplate = template.Must(template.New("x1resp").Funcs(template.FuncMap{
	"esc": func(s string) string {
		var b bytes.Buffer
		_ = xml.EscapeText(&b, []byte(s))
		return b.String()
	},
}).Parse(`<?xml version="1.0" encoding="UTF-8"?>
<ns1:X1Response xmlns:ns1="http://uri.etsi.org/03221/X1/2017/10" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">{{range .Messages}}
  <ns1:x1ResponseMessage xsi:type="ns1:{{.Type}}">
    <ns1:admfIdentifier>{{esc .AdmfIdentifier}}</ns1:admfIdentifier>
    <ns1:neIdentifier>{{esc .NeIdentifier}}</ns1:neIdentifier>
    <ns1:messageTimestamp>{{esc .MessageTimestamp}}</ns1:messageTimestamp>
    <ns1:version>{{esc .Version}}</ns1:version>
    <ns1:x1TransactionId>{{esc .X1TransactionID}}</ns1:x1TransactionId>
{{- if .OK}}
    <ns1:oK>{{esc .OK}}</ns1:oK>
{{- else if .ErrorInformation}}
    <ns1:errorInformation>
      <ns1:errorCode>{{.ErrorInformation.ErrorCode}}</ns1:errorCode>
      <ns1:errorDescription>{{esc .ErrorInformation.ErrorDescription}}</ns1:errorDescription>
    </ns1:errorInformation>
{{- end}}
  </ns1:x1ResponseMessage>{{end}}
</ns1:X1Response>`))

// marshalResponse renders an X1Response to its wire form.
func marshalResponse(resp *X1Response) ([]byte, error) {
	var b bytes.Buffer
	if err := responseTemplate.Execute(&b, resp); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Server is an http.Handler implementing the X1 network-element endpoint
// (TS 103 221-1). It applies received tasking to Store. Mount it at the X1 path
// the ADMF is configured to use (e.g. "/X1/NE"). It logs nothing about task
// content, to keep interception undetectable.
type Server struct {
	store      *store.Store
	neID       string
	now        func() time.Time
	onActivate func(types.InterceptTask)

	mu       sync.Mutex
	lastSeen time.Time // time of the last X1 message from the ADMF (keepalive watchdog)
}

// Option customises a Server.
type Option func(*Server)

// OnActivate registers a callback run after a task is successfully activated
// (an ActivateTaskRequest — not a modify or deactivate). A POI uses it to apply
// interception to state that already exists when the warrant arrives, e.g. the
// AMF scanning already-registered UEs to emit StartOfInterception records. The
// callback runs synchronously on the X1 request goroutine, so it must not block.
func OnActivate(fn func(types.InterceptTask)) Option {
	return func(s *Server) { s.onActivate = fn }
}

// NewServer returns an X1 Server backed by s, identifying itself as neID.
func NewServer(s *store.Store, neID string, opts ...Option) *Server {
	srv := &Server{store: s, neID: neID, now: func() time.Time { return time.Now().UTC() }}
	for _, opt := range opts {
		opt(srv)
	}
	return srv
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "X1 requires POST", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	resp, err := s.Process(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out, err := marshalResponse(resp)
	if err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write(out)
}

// Process parses an X1 request body, applies each message to the store, and
// returns the response envelope. Exposed for testing without HTTP.
func (s *Server) Process(body []byte) (*X1Response, error) {
	var req X1Request
	if err := xml.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("x1: malformed request: %w", err)
	}
	// Any well-formed X1 message means the ADMF is alive — feeds the keepalive
	// watchdog (TS 103 221-1: the ADMF sends KeepaliveRequest at least every
	// TIME_P1; if they lapse the NE purges tasking).
	s.recordActivity()
	resp := &X1Response{}
	for _, m := range req.Messages {
		resp.Messages = append(resp.Messages, s.apply(m))
	}
	return resp, nil
}

func (s *Server) recordActivity() {
	s.mu.Lock()
	s.lastSeen = s.now()
	s.mu.Unlock()
}

// WatchKeepalive enforces the TS 103 221-1 keepalive fail-safe: if no X1 message
// arrives from the ADMF within timeout, all tasking is purged (the controlling
// ADMF is presumed gone, so warrants must not persist). It blocks — run it in a
// goroutine; timeout must be > 0.
func (s *Server) WatchKeepalive(timeout time.Duration) {
	s.recordActivity() // seed, so a freshly-started NE does not purge immediately
	ticker := time.NewTicker(timeout / 2)
	for range ticker.C {
		s.purgeIfLapsed(timeout)
	}
}

// purgeIfLapsed clears all tasking when no X1 message has arrived within timeout.
func (s *Server) purgeIfLapsed(timeout time.Duration) {
	s.mu.Lock()
	idle := s.now().Sub(s.lastSeen)
	s.mu.Unlock()
	if idle > timeout {
		s.store.DeactivateAll()
	}
}

func (s *Server) apply(m X1RequestMessage) X1ResponseMessage {
	rm := X1ResponseMessage{
		AdmfIdentifier:   m.AdmfIdentifier,
		NeIdentifier:     s.neID,
		MessageTimestamp: s.now().Format(time.RFC3339Nano),
		Version:          m.Version,
		X1TransactionID:  m.X1TransactionID,
	}

	var err error
	switch localType(m.Type) {
	case "ActivateTaskRequest", "ModifyTaskRequest":
		// StartOfInterception fires on a fresh activation, and on a modify that
		// retargets to a *different* identifier (the new target's already-present
		// state needs a scan too) — but not on a modify that leaves the target
		// unchanged, which would re-emit for UEs already covered.
		isModify := localType(m.Type) == "ModifyTaskRequest"
		var prevTarget types.TargetIdentifier
		if isModify && m.TaskDetails != nil {
			if old, ok := s.store.Get(types.XID(m.TaskDetails.XID)); ok {
				prevTarget = old.Target
			}
		}
		var task types.InterceptTask
		task, err = s.activate(m)
		if err == nil && s.onActivate != nil && (!isModify || task.Target != prevTarget) {
			s.onActivate(task)
		}
		rm.Type = strings.Replace(localType(m.Type), "Request", "Response", 1)
	case "DeactivateTaskRequest":
		if m.XID == "" {
			err = fmt.Errorf("missing xId")
		} else {
			s.store.Deactivate(types.XID(m.XID))
		}
		rm.Type = "DeactivateTaskResponse"
	case "KeepaliveRequest":
		// Liveness from the ADMF (TS 103 221-1). Process already recorded the
		// activity that resets the watchdog; just acknowledge.
		rm.Type = "KeepaliveResponse"
	case "PingRequest":
		rm.Type = "PingResponse"
	default:
		err = fmt.Errorf("unsupported request type %q", localType(m.Type))
	}

	if err != nil {
		rm.Type = "ErrorResponse"
		rm.ErrorInformation = &X1Error{ErrorCode: 1, ErrorDescription: err.Error()}
	} else {
		rm.OK = "AcknowledgedAndCompleted"
	}
	return rm
}

func (s *Server) activate(m X1RequestMessage) (types.InterceptTask, error) {
	if m.TaskDetails == nil {
		return types.InterceptTask{}, fmt.Errorf("missing taskDetails")
	}
	task, err := taskFromDetails(*m.TaskDetails)
	if err != nil {
		return types.InterceptTask{}, err
	}
	if !s.store.Activate(task) {
		return types.InterceptTask{}, fmt.Errorf("invalid task")
	}
	return task, nil
}

// taskFromDetails maps X1 TaskDetails onto an interception task. DID→MDF-address
// resolution (via CreateDestination) is not yet handled, so Deliveries is left
// empty until destinations are provisioned.
func taskFromDetails(td TaskDetails) (types.InterceptTask, error) {
	if td.XID == "" {
		return types.InterceptTask{}, fmt.Errorf("missing xId")
	}
	if len(td.TargetIdentifiers) == 0 {
		return types.InterceptTask{}, fmt.Errorf("no target identifier")
	}
	target, err := mapTarget(td.TargetIdentifiers[0])
	if err != nil {
		return types.InterceptTask{}, err
	}
	products, err := deliveryProducts(td.DeliveryType)
	if err != nil {
		return types.InterceptTask{}, err
	}
	return types.InterceptTask{XID: types.XID(td.XID), Target: target, Products: products}, nil
}

func mapTarget(t TargetIdentifier) (types.TargetIdentifier, error) {
	switch {
	case t.SUPIIMSI != "":
		return types.TargetIdentifier{Type: types.TargetSUPI, Value: t.SUPIIMSI}, nil
	case t.IMSI != "":
		return types.TargetIdentifier{Type: types.TargetSUPI, Value: t.IMSI}, nil
	case t.SUPINAI != "":
		return types.TargetIdentifier{Type: types.TargetSUPI, Value: t.SUPINAI}, nil
	case t.PEIIMEI != "":
		return types.TargetIdentifier{Type: types.TargetPEI, Value: t.PEIIMEI}, nil
	case t.PEIIMEISV != "":
		return types.TargetIdentifier{Type: types.TargetPEI, Value: t.PEIIMEISV}, nil
	case t.GPSIMSISDN != "":
		return types.TargetIdentifier{Type: types.TargetGPSI, Value: t.GPSIMSISDN}, nil
	case t.E164Number != "":
		return types.TargetIdentifier{Type: types.TargetGPSI, Value: t.E164Number}, nil
	}
	return types.TargetIdentifier{}, fmt.Errorf("unsupported target identifier")
}

func deliveryProducts(dt string) ([]types.ProductType, error) {
	switch dt {
	case "X2Only":
		return []types.ProductType{types.ProductIRI}, nil
	case "X3Only":
		return []types.ProductType{types.ProductCC}, nil
	case "X2andX3":
		return []types.ProductType{types.ProductIRI, types.ProductCC}, nil
	}
	return nil, fmt.Errorf("unknown deliveryType %q", dt)
}

// localType strips any namespace prefix from an xsi:type value
// ("ns1:ActivateTaskRequest" -> "ActivateTaskRequest").
func localType(t string) string {
	if i := strings.LastIndex(t, ":"); i >= 0 {
		return t[i+1:]
	}
	return t
}
