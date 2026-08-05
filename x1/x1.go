// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x1

import (
	"bytes"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
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
	store        *store.Store
	neID         string
	admfID       string // responsible ADMF; empty disables the "expected ADMF" check
	now          func() time.Time
	onActivate   func(types.InterceptTask)
	onDeactivate func(types.InterceptTask)

	mu       sync.Mutex
	lastSeen time.Time // time of the last X1 message from the ADMF (keepalive watchdog)
	// requireDIDs refuses a CC task whose destinations are unknown, rather than
	// accepting it and delivering nothing.
	requireDIDs bool
	// destinations maps a provisioned DID to the endpoint it names
	// (CreateDestination). A task carries DIDs rather than addresses, so this is
	// how an NE learns where to deliver product — configuration is not a
	// substitute, since one NE may serve several agencies' destinations.
	destinations map[string]types.DeliveryEndpoint
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

// OnDeactivate registers a callback run after a task is successfully deactivated,
// with the task as it was before removal. A POI uses it to undo interception it
// applied to existing state (e.g. the SMF clearing mid-session CC duplication).
// It runs synchronously on the X1 request goroutine, so it must not block.
func OnDeactivate(fn func(types.InterceptTask)) Option {
	return func(s *Server) { s.onDeactivate = fn }
}

// RequireResolvableDIDs makes the server refuse a task that requests content
// delivery but names destinations it does not know.
//
// The default is deliberately lenient, because an ADMF may legitimately task an
// IRI-POI whose MDF address comes from configuration and name DIDs it never
// provisioned — which is what real ADMFs do. That leniency is wrong for a
// *triggered* POI: its triggering function has no other way to discover that the
// destination it provisioned has been lost (a restart, say), so an acknowledgement
// it cannot honour leaves content being dropped while the triggering function
// believes interception is running (review R37).
func RequireResolvableDIDs() Option {
	return func(s *Server) { s.requireDIDs = true }
}

// WithADMF names the ADMF responsible for this network element. When set, a
// request asserting a different ADMF identifier is refused even if that
// identifier is properly bound into the peer's certificate — certification by
// the LI CA is not by itself authority to task this NE (TS 103 221-1 error 1040).
func WithADMF(admfID string) Option {
	return func(s *Server) { s.admfID = admfID }
}

// NewServer returns an X1 Server backed by s, identifying itself as neID.
func NewServer(s *store.Store, neID string, opts ...Option) *Server {
	srv := &Server{
		store:        s,
		neID:         neID,
		now:          func() time.Time { return time.Now().UTC() },
		destinations: make(map[string]types.DeliveryEndpoint),
	}
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
	// The peer certificate authenticates the request beyond the handshake
	// (TS 103 221-1 clause 8.2.4); mutual TLS guarantees it is present and
	// CA-verified in any conformant deployment.
	var peer *x509.Certificate
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		peer = r.TLS.PeerCertificates[0]
	}
	resp, err := s.Process(body, peer)
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
// returns the response envelope. peer is the certificate the requester presented
// (nil if none), against which each message is authenticated. Exposed for testing
// without HTTP.
func (s *Server) Process(body []byte, peer *x509.Certificate) (*X1Response, error) {
	var req X1Request
	if err := xml.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("x1: malformed request: %w", err)
	}
	resp := &X1Response{}
	authenticated := false
	for _, m := range req.Messages {
		rm, ok := s.applyAuthenticated(m, peer)
		authenticated = authenticated || ok
		resp.Messages = append(resp.Messages, rm)
	}
	// An authenticated X1 message means the responsible ADMF is alive — this feeds
	// the keepalive watchdog (TS 103 221-1: the ADMF sends KeepaliveRequest at least
	// every TIME_P1; if they lapse the NE purges tasking). Unauthenticated traffic
	// must not reset it, or anyone able to reach the X1 port could hold the
	// fail-safe open indefinitely while the real ADMF is gone.
	if authenticated {
		s.recordActivity()
	}
	return resp, nil
}

// applyAuthenticated authenticates a request message and, only if it passes,
// applies it. The bool reports whether the peer authenticated for this message.
func (s *Server) applyAuthenticated(m X1RequestMessage, peer *x509.Certificate) (X1ResponseMessage, bool) {
	if code, desc := s.authenticate(m, peer); code != 0 {
		return X1ResponseMessage{
			Type:             "ErrorResponse",
			AdmfIdentifier:   m.AdmfIdentifier,
			NeIdentifier:     s.neID,
			MessageTimestamp: s.now().Format(time.RFC3339Nano),
			Version:          m.Version,
			X1TransactionID:  m.X1TransactionID,
			ErrorInformation: &X1Error{ErrorCode: code, ErrorDescription: desc},
		}, false
	}
	return s.apply(m), true
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
// It clears the store first, then runs the deactivation hook over the tasks that
// were present, so a POI re-evaluating against the (now empty) task set actually
// tears its product down — e.g. the SMF clearing UPF CC duplication. Clearing the
// store alone is not a complete purge (review R19 / design D11 Part B). After the
// first purge the snapshot is empty, so subsequent lapsed ticks are no-ops.
func (s *Server) purgeIfLapsed(timeout time.Duration) {
	s.mu.Lock()
	idle := s.now().Sub(s.lastSeen)
	s.mu.Unlock()
	if idle <= timeout {
		return
	}
	tasks := s.store.Snapshot()
	s.store.DeactivateAll()
	if s.onDeactivate != nil {
		for _, t := range tasks {
			s.onDeactivate(t)
		}
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
	var code int // TS 103 221-1 error code; 0 means "pick the generic one"
	switch localType(m.Type) {
	case "ActivateTaskRequest", "ModifyTaskRequest":
		// StartOfInterception fires on a fresh activation, and on a modify that
		// retargets to a *different* identifier (the new target's already-present
		// state needs a scan too) — but not on a modify that leaves the target
		// unchanged, which would re-emit for UEs already covered.
		isModify := localType(m.Type) == "ModifyTaskRequest"
		var prevTask types.InterceptTask
		var hadPrev bool
		if isModify && m.TaskDetails != nil {
			prevTask, hadPrev = s.store.Get(types.XID(m.TaskDetails.XID))
		}
		var task types.InterceptTask
		task, err = s.activate(m)
		if err == nil {
			retargeted := isModify && hadPrev && task.Target != prevTask.Target
			if s.onActivate != nil && (!isModify || retargeted) {
				s.onActivate(task)
			}
			// A retarget must undo product/state applied for the old target (e.g.
			// clear the SMF's CC duplication on the old target's sessions), which
			// re-evaluates against the now-updated task set. (review R19/R15)
			if retargeted && s.onDeactivate != nil {
				s.onDeactivate(prevTask)
			}
		}
		rm.Type = strings.Replace(localType(m.Type), "Request", "Response", 1)
	case "DeactivateTaskRequest":
		if m.XID == "" {
			err = fmt.Errorf("missing xId")
		} else {
			// Capture the task before removal so a POI can undo state it applied
			// for the target (e.g. clear mid-session CC on the SMF).
			task, existed := s.store.Get(types.XID(m.XID))
			s.store.Deactivate(types.XID(m.XID))
			if existed && s.onDeactivate != nil {
				s.onDeactivate(task)
			}
		}
		rm.Type = "DeactivateTaskResponse"
	case "CreateDestinationRequest":
		err = s.createDestination(m.DestinationDetails)
		rm.Type = "CreateDestinationResponse"
	case "KeepaliveRequest":
		// Liveness from the ADMF (TS 103 221-1). Process already recorded the
		// activity that resets the watchdog; just acknowledge.
		rm.Type = "KeepaliveResponse"
	case "PingRequest":
		rm.Type = "PingResponse"
	default:
		err = fmt.Errorf("unsupported request type %q", localType(m.Type))
		code = errCodeUnsupportedRequest
	}

	if err != nil {
		rm.Type = "ErrorResponse"
		if code == 0 {
			code = errCodeGeneric
		}
		rm.ErrorInformation = &X1Error{ErrorCode: code, ErrorDescription: err.Error()}
	} else {
		rm.OK = "AcknowledgedAndCompleted"
	}
	return rm
}

// createDestination records a delivery destination against its DID. Re-creating
// an existing DID is an error per TS 103 221-1 clause 6.3.1.1, so a
// misconfiguration cannot silently redirect an agency's product elsewhere.
func (s *Server) createDestination(d *DestinationDetails) error {
	if d == nil {
		return fmt.Errorf("missing destinationDetails")
	}
	if d.DID == "" {
		return fmt.Errorf("missing dId")
	}
	if _, err := deliveryProducts(d.DeliveryType); err != nil {
		return err
	}
	endpoint, err := deliveryEndpoint(*d)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.destinations[d.DID]; exists {
		return fmt.Errorf("destination already present")
	}
	s.destinations[d.DID] = endpoint
	return nil
}

// deliveryEndpoint maps provisioned destination details onto the endpoint the
// X2/X3 senders dial.
func deliveryEndpoint(d DestinationDetails) (types.DeliveryEndpoint, error) {
	if d.Address.IPAddressAndPort == nil {
		return types.DeliveryEndpoint{}, fmt.Errorf("unsupported deliveryAddress")
	}
	ap := d.Address.IPAddressAndPort
	host := ap.Address.IPv4
	if host == "" {
		// An IPv6 literal needs brackets before it can be joined to a port.
		if ap.Address.IPv6 == "" {
			return types.DeliveryEndpoint{}, fmt.Errorf("deliveryAddress carries no IP address")
		}
		host = "[" + ap.Address.IPv6 + "]"
	}
	if ap.Port == 0 {
		return types.DeliveryEndpoint{}, fmt.Errorf("deliveryAddress carries no port")
	}
	// X3Only destinations deliver content, X2Only signalling; X2andX3 is recorded
	// as X3 here only when the task that references it wants CC, so keep the
	// delivery type the provisioner stated.
	dt := types.DeliveryX3
	if d.DeliveryType == "X2Only" {
		dt = types.DeliveryX2
	}
	return types.DeliveryEndpoint{
		Type:    dt,
		Address: host + ":" + strconv.FormatUint(uint64(ap.Port), 10),
	}, nil
}

// resolveDIDs turns the DIDs a task references into delivery endpoints, skipping
// any that were never provisioned.
//
// Skipping rather than rejecting is deliberate. A task naming an unprovisioned DID
// is arguably malformed, but an ADMF is entitled to task an IRI-POI whose MDF2
// address comes from configuration — which is how this implementation has always
// worked, and what the sipgate simulator does — so failing the task here would
// stop interception working against every ADMF that does not call
// CreateDestination first. The strictness belongs at the point of delivery
// instead: a POI that has no destination for the product it was asked to produce
// must refuse to produce it, which is where an unresolvable destination becomes
// visible (as a reported fault) rather than silent.
func (s *Server) resolveDIDs(dids []string) []types.DeliveryEndpoint {
	if len(dids) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	var out []types.DeliveryEndpoint
	for _, did := range dids {
		if endpoint, ok := s.destinations[did]; ok {
			out = append(out, endpoint)
		}
	}
	return out
}

func (s *Server) activate(m X1RequestMessage) (types.InterceptTask, error) {
	if m.TaskDetails == nil {
		return types.InterceptTask{}, fmt.Errorf("missing taskDetails")
	}
	task, err := s.taskFromDetails(*m.TaskDetails)
	if err != nil {
		return types.InterceptTask{}, err
	}
	if !s.store.Activate(task) {
		return types.InterceptTask{}, fmt.Errorf("invalid task")
	}
	return task, nil
}

// taskFromDetails maps X1 TaskDetails onto an interception task, resolving the
// DIDs it references against the destinations provisioned with CreateDestination.
func (s *Server) taskFromDetails(td TaskDetails) (types.InterceptTask, error) {
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
	// A provisioned ProductID replaces the XID in delivered PDU headers, and a
	// provisioned CorrelationID is the value to stamp on them (TS 103 221-1
	// clause 6.2.1.2). Both are optional in TS 103 221-1 and mandatory for an
	// LI_T3 trigger; a POI that needs them enforces that itself, since an
	// IRI-POI tasked by a real ADMF legitimately receives neither.
	var correlation uint64
	if td.CorrelationID != "" {
		correlation, err = strconv.ParseUint(td.CorrelationID, 10, 64)
		if err != nil {
			return types.InterceptTask{}, fmt.Errorf("invalid correlationID")
		}
	}
	deliveries := s.resolveDIDs(td.ListOfDIDs)
	if s.requireDIDs && slices.Contains(products, types.ProductCC) && !hasDelivery(deliveries, types.DeliveryX3) {
		// Accepting this would mean duplicating a subject's traffic and discarding
		// every copy, while the party that asked for it is told all is well.
		return types.InterceptTask{}, fmt.Errorf("no known X3 destination")
	}

	return types.InterceptTask{
		XID:           types.XID(td.XID),
		Target:        target,
		Products:      products,
		ProductID:     types.XID(td.ProductID),
		CorrelationID: correlation,
		Deliveries:    deliveries,
	}, nil
}

// hasDelivery reports whether the endpoints include one of the given type.
func hasDelivery(endpoints []types.DeliveryEndpoint, t types.DeliveryType) bool {
	for _, e := range endpoints {
		if e.Type == t && e.Address != "" {
			return true
		}
	}

	return false
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
	case t.Extension != nil:
		return mapExtensionTarget(t.Extension)
	}
	return types.TargetIdentifier{}, fmt.Errorf("unsupported target identifier")
}

// mapExtensionTarget maps the 3GPP LI_T3 packet-detection criteria onto a target
// identifier. Only FSEID is supported — it is what the CC-POI's datapath can
// match on. The other criteria of TS 33.128 table 6.2.3-7 (PDRID, QERID,
// NetworkInstance, GTPTunnelDirection, FTEID, PDR) are rejected rather than
// ignored: silently accepting a criterion we do not evaluate would intercept
// either nothing or everything, and both are worse than a refused trigger the
// Triggering Function can report.
func mapExtensionTarget(ext *TargetIdentifierExtension) (types.TargetIdentifier, error) {
	if ext.UPFT3 == nil || len(ext.UPFT3.Identifiers) == 0 {
		return types.TargetIdentifier{}, fmt.Errorf("unsupported target identifier extension")
	}
	id := ext.UPFT3.Identifiers[0]
	if id.FSEID == nil || id.FSEID.SEID == 0 {
		return types.TargetIdentifier{}, fmt.Errorf("unsupported detection criterion")
	}
	return types.TargetIdentifier{
		Type:  types.TargetFSEID,
		Value: strconv.FormatUint(id.FSEID.SEID, 10),
	}, nil
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
