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

// The TS 103 221-1 deliveryType values, which appear both as something this
// element parses from a request and as something it emits in a details answer.
const (
	deliveryX2Only  = "X2Only"
	deliveryX3Only  = "X3Only"
	deliveryX2andX3 = "X2andX3"
)

// The two X1 response shapes: an acknowledgement, or an error carrying a code.
const (
	ackOK         = "AcknowledgedAndCompleted"
	errorResponse = "ErrorResponse"
)

// responseTemplate emits an X1Response in the conventional TS 103 221-1 wire
// form (xsi/ns1 prefixes, xsi:type QName), which Go's encoding/xml can't
// produce cleanly. Input is still parsed structurally with encoding/xml.
var responseTemplate = template.Must(template.New("x1resp").Funcs(template.FuncMap{
	"esc": func(v any) string {
		var b bytes.Buffer
		//nolint:errcheck // writing to a bytes.Buffer cannot fail
		_ = xml.EscapeText(&b, []byte(fmt.Sprintf("%s", v)))
		return b.String()
	},
	// A details answer has to say what was tasked in the same vocabulary the
	// request used, so an ADMF can compare it against what it believes it sent.
	"targetElement": func(t types.TargetIdentifierType) string {
		switch t {
		case types.TargetPEI:
			return "peiImei"
		case types.TargetGPSI:
			return "gpsiMsisdn"
		case types.TargetFSEID:
			// A triggered task's criterion is a session, not a subscriber; it has no
			// plain identifier element, so report it in the extension's terms.
			return "targetIdentifierExtension"
		default:
			return "supiimsi"
		}
	},
	"deliveryType": func(p []types.ProductType) string {
		iri := slices.Contains(p, types.ProductIRI)
		cc := slices.Contains(p, types.ProductCC)
		switch {
		case iri && cc:
			return deliveryX2andX3
		case cc:
			return deliveryX3Only
		default:
			return deliveryX2Only
		}
	},
}).Parse(`<?xml version="1.0" encoding="UTF-8"?>
<ns1:X1Response xmlns:ns1="http://uri.etsi.org/03221/X1/2017/10" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">{{range .Messages}}
  <ns1:x1ResponseMessage xsi:type="ns1:{{.Type}}">
    <ns1:admfIdentifier>{{esc .AdmfIdentifier}}</ns1:admfIdentifier>
    <ns1:neIdentifier>{{esc .NeIdentifier}}</ns1:neIdentifier>
    <ns1:messageTimestamp>{{esc .MessageTimestamp}}</ns1:messageTimestamp>
    <ns1:version>{{esc .Version}}</ns1:version>
    <ns1:x1TransactionId>{{esc .X1TransactionID}}</ns1:x1TransactionId>
{{- range .Tasks}}
    <ns1:taskResponseDetails>
      <ns1:taskDetails>
        <ns1:xId>{{esc .XID}}</ns1:xId>
        <ns1:targetIdentifiers>
{{- range .Targets}}
          <ns1:targetIdentifier>
            <ns1:{{targetElement .Type}}>{{esc .Value}}</ns1:{{targetElement .Type}}>
          </ns1:targetIdentifier>
{{- end}}
        </ns1:targetIdentifiers>
        <ns1:deliveryType>{{deliveryType .Products}}</ns1:deliveryType>
      </ns1:taskDetails>
      <ns1:taskStatus>{{if eq (printf "%s" .State) "active"}}Active{{else}}Inactive{{end}}</ns1:taskStatus>
    </ns1:taskResponseDetails>
{{- end}}
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
	// onAuthFailure is told the X1 error code when a peer fails clause 8.2.4
	// authentication. Nil leaves such failures unreported, which is the earlier
	// behaviour: refused and invisible.
	onAuthFailure func(code int)
	// canApply asks the POI whether it can actually carry out a task before it is
	// acknowledged. Nil accepts everything, which is right for a POI whose only
	// question about a task is answered by this package.
	canApply func(types.InterceptTask) error

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

// CanApply registers a check run before a task is stored or acknowledged. An
// error refuses the activation or modification, with the error's text as the
// description the requesting function receives.
//
// It exists for the things only the POI can answer. A triggered CC-POI is given
// detection criteria it may be unable to evaluate — an identifier naming state its
// datapath does not hold — and accepting one would leave the triggering function
// believing an interception is running that can never produce anything. That is
// undiscoverable from the outside, which is why the answer has to come before the
// acknowledgement rather than from a callback after it.
//
// The check runs synchronously on the X1 request goroutine, so it must not block.
// It must not apply anything either: a task it approves may still be refused
// afterwards for a reason this package owns.
func CanApply(fn func(types.InterceptTask) error) Option {
	return func(s *Server) { s.canApply = fn }
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
// believes interception is running.
func RequireResolvableDIDs() Option {
	return func(s *Server) { s.requireDIDs = true }
}

// OnAuthFailure registers a callback run when a peer fails TS 103 221-1 clause
// 8.2.4 authentication — presenting a certificate the LI CA issued, but asserting
// an identity it is not bound to, or one this element does not answer to. It is
// given the X1 error code the peer was refused with.
//
// A POI wires this to its ADMF reporter. Without it an attack on the provisioning
// interface is refused correctly and then recorded nowhere, since this plane
// deliberately keeps out of operator logs. The callback runs synchronously on the
// X1 request goroutine, so it must not block.
func OnAuthFailure(fn func(code int)) Option {
	return func(s *Server) { s.onAuthFailure = fn }
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
	//nolint:errcheck // a peer that hung up mid-response is not actionable, and must not be logged
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
		// Someone reached this interface with a certificate from the LI CA and tried to
		// task or untask this element as somebody they are not. Refusing it is not
		// enough on its own: undetectability means we deliberately log nothing, so
		// without this the most security-relevant event this interface can witness
		// would leave no trace anywhere at all. Clause 6.5.4 anticipates that, listing
		// a current security issue on the NE among the reasons to report.
		//
		// Only the error code reaches the ADMF, never the identifier the peer asserted:
		// that is attacker-chosen text, and an LI management channel is the last place
		// to start echoing it. The Reporter throttles per condition, so a peer
		// hammering the interface produces one report per interval, not a flood — the
		// report is a signal to go and look, not an audit trail.
		if s.onAuthFailure != nil {
			s.onAuthFailure(code)
		}

		return X1ResponseMessage{
			Type:             errorResponse,
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
//
// It returns when stop is closed. A network function passes nil, since the
// fail-safe must run for as long as the element can hold tasking; a nil channel
// never becomes ready, so the watchdog simply never stops. Tests pass a real
// channel so each one does not leave a ticker and a goroutine behind.
func (s *Server) WatchKeepalive(timeout time.Duration, stop <-chan struct{}) {
	s.recordActivity() // seed, so a freshly-started NE does not purge immediately
	ticker := time.NewTicker(timeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.purgeIfLapsed(timeout)
		case <-stop:
			return
		}
	}
}

// purgeIfLapsed clears all tasking when no X1 message has arrived within timeout.
// It clears the store first, then runs the deactivation hook over the tasks that
// were present, so a POI re-evaluating against the (now empty) task set actually
// tears its product down — e.g. the SMF clearing UPF CC duplication. Clearing the
// store alone is not a complete purge. After the first purge the snapshot is
// empty, so subsequent lapsed ticks are no-ops.
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
		//
		// An activation naming an XID this element already holds replaces it rather
		// than being refused, which is deliberate: re-provisioning is how an ADMF
		// restores tasking after an element restarts, and refusing it
		// would break the recovery path the fault reporting exists to trigger.
		// Modifying tasking that is *not* held has no such reading and is refused
		// below.
		isModify := localType(m.Type) == "ModifyTaskRequest"
		var prevTask types.InterceptTask
		var hadPrev bool
		if isModify && m.TaskDetails != nil {
			prevTask, hadPrev = s.store.Get(types.XID(m.TaskDetails.XID))
		}
		switch {
		case isModify && m.TaskDetails == nil:
			err = fmt.Errorf("missing taskDetails")
		case m.TaskDetails != nil && len(m.TaskDetails.ListOfServiceTypes) > 0:
			// This element applies no service-type scoping, so honouring the task as
			// sent would intercept every service for the target when a narrower set
			// was authorised — more product than the warrant allows, and silently.
			// TS 33.128 prescribes the remedy for exactly this: an IRI-POI receiving a
			// ServiceType it does not support "shall reject the task with an
			// appropriate error". Refusing lets the LIPF see the mismatch and narrow
			// the warrant by other means; accepting hides it.
			//
			// The code is the "unsupported request" one rather than a guess at a more
			// specific entry: the TS 103 221-1 error registry is in that document's
			// text, not its schema, so a better-fitting value should be substituted
			// once confirmed rather than invented here.
			err = fmt.Errorf("service-type scoping is not supported")
			code = errCodeUnsupportedRequest
		case isModify && !hadPrev:
			// Applying this would silently create the task, leaving the ADMF believing
			// it had adjusted an interception that never existed here — the same class
			// of undetected divergence as tasking lost to a restart. Answering
			// "no such task" is what lets it activate the warrant instead.
			err = fmt.Errorf("no such task")
			code = errCodeNoSuchTask
		default:
			var task types.InterceptTask
			task, err = s.activate(m)
			if err == nil {
				retargeted := isModify && hadPrev && !slices.Equal(task.Targets, prevTask.Targets)
				if s.onActivate != nil && (!isModify || retargeted) {
					s.onActivate(task)
				}
				// A retarget must undo product/state applied for the old target (e.g.
				// clear the SMF's CC duplication on the old target's sessions), which
				// re-evaluates against the now-updated task set.
				if retargeted && s.onDeactivate != nil {
					s.onDeactivate(prevTask)
				}
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
	case "GetTaskDetailsRequest", "GetAllDetailsRequest":
		// A provisioning function has no other way to discover that this element has
		// lost the tasking it was given — a restart discards it, and nothing pushes
		// that fact anywhere. Answering these is what lets an ADMF audit and
		// re-provision instead of believing an interception is running that is not
		// — which TS 103 221-1 also requires.
		if localType(m.Type) == "GetAllDetailsRequest" {
			rm.Tasks = s.store.Snapshot()
		} else if t, found := s.store.Get(types.XID(m.XID)); found {
			rm.Tasks = []types.InterceptTask{t}
		} else if m.XID == "" {
			// xId is mandatory on this request in the schema.
			err = fmt.Errorf("missing xId")
		} else {
			// Reporting "no such task" is the whole point: it is the answer that
			// tells an ADMF its warrant is not in place here.
			err = fmt.Errorf("no such task")
			code = errCodeNoSuchTask
		}
		rm.Type = strings.Replace(localType(m.Type), "Request", "Response", 1)
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
		rm.Type = errorResponse
		if code == 0 {
			code = errCodeGeneric
		}
		rm.ErrorInformation = &X1Error{ErrorCode: code, ErrorDescription: err.Error()}
	} else {
		rm.OK = ackOK
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
	if d.DeliveryType == deliveryX2Only {
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
	// Asked before the task is stored, so a refusal leaves nothing behind: a task in
	// the store is a task this element reports as active and acts on.
	if s.canApply != nil {
		if err := s.canApply(task); err != nil {
			return types.InterceptTask{}, err
		}
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
	// Every identifier is mapped, and one unmappable identifier refuses the whole
	// task. Taking the ones we understand and dropping the rest would narrow the
	// interception below what was ordered while answering that it had been applied.
	targets := make([]types.TargetIdentifier, 0, len(td.TargetIdentifiers))
	for _, ti := range td.TargetIdentifiers {
		target, err := mapTarget(ti)
		if err != nil {
			return types.InterceptTask{}, err
		}
		targets = append(targets, target)
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
		Targets:       targets,
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
	// The plain TS 103 221-1 criteria of table 6.2.3-7. These come after the
	// subscriber identifiers deliberately: a task carrying both is targeting a
	// subscriber, and the subscriber identifier is the one an IRI-POI can act on.
	case t.GTPUTunnelID != "":
		return types.TargetIdentifier{Type: types.TargetFTEID, Value: t.GTPUTunnelID}, nil
	case t.IPv4Address != "":
		return types.TargetIdentifier{Type: types.TargetUEIPv4, Value: t.IPv4Address}, nil
	case t.IPv6Address != "":
		return types.TargetIdentifier{Type: types.TargetUEIPv6, Value: t.IPv6Address}, nil
	case t.TCPPort != "":
		return types.TargetIdentifier{Type: types.TargetTCPPort, Value: t.TCPPort}, nil
	case t.UDPPort != "":
		return types.TargetIdentifier{Type: types.TargetUDPPort, Value: t.UDPPort}, nil
	case t.Extension != nil:
		return mapExtensionTarget(t.Extension)
	}
	return types.TargetIdentifier{}, fmt.Errorf("unsupported target identifier")
}

// mapExtensionTarget maps the 3GPP LI_T3 packet-detection criteria of TS 33.128
// table 6.2.3-7 onto a target identifier. Clause 6.2.3 requires a CC-POI to support
// "at least the identifier types given in table 6.2.3-7", so all of them are
// accepted here: the three plain TS 103 221-1 arms are handled in mapTarget, and
// the seven extension arms in mapUPFLIT3Identifier.
//
// Accepting a criterion at this layer means it can be *provisioned*. Whether the
// CC-POI can then evaluate it against its own session state is a separate question
// answered further in — and a criterion it cannot evaluate is still refused there
// rather than accepted and ignored.
func mapExtensionTarget(ext *TargetIdentifierExtension) (types.TargetIdentifier, error) {
	if ext.UPFT3 == nil || len(ext.UPFT3.Identifiers) == 0 {
		return types.TargetIdentifier{}, fmt.Errorf("unsupported target identifier extension")
	}
	return mapUPFLIT3Identifier(ext.UPFT3.Identifiers[0])
}

// mapUPFLIT3Identifier maps one arm of the UPFLIT3TargetIdentifier choice. Each arm
// is refused rather than defaulted when its value is unusable: a criterion that
// resolves to nothing would arm an interception that produces no product, and one
// that resolves to everything would collect beyond the warrant.
func mapUPFLIT3Identifier(id UPFLIT3Identifier) (types.TargetIdentifier, error) {
	switch {
	case id.FSEID != nil:
		if id.FSEID.SEID == 0 {
			return types.TargetIdentifier{}, fmt.Errorf("FSEID criterion carries no SEID")
		}

		return types.TargetIdentifier{
			Type:  types.TargetFSEID,
			Value: strconv.FormatUint(id.FSEID.SEID, 10),
		}, nil

	case id.FTEID != nil:
		// The address is optional in the schema. Where it is absent the criterion is
		// the TEID alone, which cannot separate two tunnels sharing one; that is the
		// triggering function's choice to make, not ours to refuse.
		v := strconv.FormatUint(uint64(id.FTEID.TEID), 10)
		if addr := id.FTEID.IPv4Address; addr != "" {
			v += "@" + addr
		} else if addr := id.FTEID.IPv6Address; addr != "" {
			v += "@" + addr
		}

		return types.TargetIdentifier{Type: types.TargetFTEID, Value: v}, nil

	case id.PDRID != nil:
		return types.TargetIdentifier{
			Type:  types.TargetPDRID,
			Value: strconv.FormatUint(uint64(*id.PDRID), 10),
		}, nil

	case id.QERID != nil:
		return types.TargetIdentifier{
			Type:  types.TargetQERID,
			Value: strconv.FormatUint(uint64(*id.QERID), 10),
		}, nil

	case id.NetworkInstance != "":
		// xs:hexBinary in the schema, so it is carried and compared as the octets it
		// encodes rather than as a name.
		return types.TargetIdentifier{
			Type:  types.TargetNetworkInstance,
			Value: strings.ToLower(id.NetworkInstance),
		}, nil

	case id.GTPTunnelDirection != "":
		// A closed enumeration. Anything else is refused: an unrecognised direction
		// would either match nothing or both directions, and both are wrong in a way
		// the triggering function could not detect.
		switch id.GTPTunnelDirection {
		case GTPDirectionOutbound, GTPDirectionInbound:
			return types.TargetIdentifier{
				Type:  types.TargetGTPTunnelDirection,
				Value: id.GTPTunnelDirection,
			}, nil
		default:
			return types.TargetIdentifier{}, fmt.Errorf(
				"GTPTunnelDirection %q is not one of the enumerated values", id.GTPTunnelDirection)
		}

	case id.PDR != "":
		return types.TargetIdentifier{
			Type:  types.TargetPDR,
			Value: strings.ToLower(id.PDR),
		}, nil
	}

	return types.TargetIdentifier{}, fmt.Errorf("unsupported detection criterion")
}

func deliveryProducts(dt string) ([]types.ProductType, error) {
	switch dt {
	case deliveryX2Only:
		return []types.ProductType{types.ProductIRI}, nil
	case deliveryX3Only:
		return []types.ProductType{types.ProductCC}, nil
	case deliveryX2andX3:
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
