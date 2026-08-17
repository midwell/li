// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x1

import (
	"bytes"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"regexp"
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
	"targetXML":    targetXML,
	"responseBody": responseBody,
	"deliveryType": deliveryTypeOf,
}).Parse(`<?xml version="1.0" encoding="UTF-8"?>
<ns1:X1Response xmlns:ns1="http://uri.etsi.org/03221/X1/2017/10" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:ext="urn:3GPP:ns:li:3GPPX1Extensions:r18:v6" xmlns:c="http://uri.etsi.org/03280/common/2017/07">{{range .Messages}}
  <ns1:x1ResponseMessage xsi:type="ns1:{{.Type}}">
    <ns1:admfIdentifier>{{esc .AdmfIdentifier}}</ns1:admfIdentifier>
    <ns1:neIdentifier>{{esc .NeIdentifier}}</ns1:neIdentifier>
    <ns1:messageTimestamp>{{esc .MessageTimestamp}}</ns1:messageTimestamp>
    <ns1:version>{{esc .Version}}</ns1:version>
    <ns1:x1TransactionId>{{esc .X1TransactionID}}</ns1:x1TransactionId>
{{responseBody . -}}
  </ns1:x1ResponseMessage>{{end}}
</ns1:X1Response>`))

// x1TimestampLayout renders the ETSI TS 103 280 QualifiedMicrosecondDateTime that every
// X1 message carries. Its pattern demands *exactly* six fractional digits:
//
//	[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}(Z|[+-][0-9]{2}:[0-9]{2})
//
// The zeros in this layout are what keeps trailing zeros; Go's nines — as in
// time.RFC3339Nano, which every one of these call sites used to use — strip them. That made
// roughly one message in ten carry five digits or fewer and fail a peer's validation, in
// every direction: responses, the triggers a CC-TF sends, and the fault reports by which
// this element says something is wrong.
//
// The defect and the fix differ by one character, which is why there is one of these rather
// than five, and why a test pins it with a clock whose fraction ends in zeros.
const x1TimestampLayout = "2006-01-02T15:04:05.000000Z07:00"

// x1Timestamp renders t for an X1 message.
func x1Timestamp(t time.Time) string { return t.Format(x1TimestampLayout) }

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
	store  *store.Store
	neID   string
	admfID string // responsible ADMF; empty disables the "expected ADMF" check
	now    func() time.Time
	// onTaskChange is this element's one lifecycle callback. See OnTaskChange for
	// why one event carrying both sides beats two events under one XID.
	onTaskChange func(prev, next *types.InterceptTask)
	// onPurge names why tasking went, after it has gone. See OnPurge.
	onPurge func(types.InterceptTask, PurgeReason)
	// onAuthFailure is told the X1 error code when a peer fails clause 8.2.4
	// authentication. Nil leaves such failures unreported, which is the earlier
	// behaviour: refused and invisible.
	onAuthFailure func(code int)
	// canApply asks the POI whether it can actually carry out a task before it is
	// acknowledged. Nil accepts everything, which is right for a POI whose only
	// question about a task is answered by this package.
	canApply func(types.InterceptTask) error
	// faultProbes answer whether a fault condition holds *now*. They are consulted when the
	// element is asked for its status, never cached, so no answer can go stale — which is the
	// failure mode every retaining design shares. See WithFaultProbes.
	faultProbes []FaultProbe
	// deactivateAllDisabled and removeAllDestinationsEnabled carry the two bulk operations'
	// *different* defaults, which is the specification's asymmetry rather than ours.
	//
	// DeactivateAllTasks is enabled unless disabled: "By default (if there has been no
	// agreement in advance) then DeactivateAllTasks is enabled." It fails safe — interception
	// stops, which is the direction this whole capability fails in anyway.
	//
	// RemoveAllDestinations is disabled unless enabled: the specification states no default
	// beyond prior agreement, and it is not symmetric with the other. Removing every
	// destination strands an element that still has to deliver, and the specification's own
	// guard — refuse while any destination is referenced by a task — shows it was thought of
	// as dangerous.
	deactivateAllDisabled        bool
	removeAllDestinationsEnabled bool

	mu       sync.Mutex
	lastSeen time.Time // time of the last X1 message from the ADMF (keepalive watchdog)
	// requireDIDs refuses a CC task whose destinations are unknown, rather than
	// accepting it and delivering nothing.
	requireDIDs bool
	// destinations maps a DID provisioned with CreateDestination to the destination it
	// names. A task carries DIDs rather than addresses, so this is how an NE learns
	// where to deliver product.
	destinations map[string]heldDestination
	// configured holds DID→destination entries this element's own configuration
	// declares. They resolve exactly as provisioned ones do, and a provisioned entry
	// for the same DID takes precedence — see resolveLocked. Neither specification
	// requires that a task's destination identifier arrived over X1 rather than having
	// been agreed out of band, so this is a supported arrangement and not a fallback.
	configured map[string]heldDestination
}

// heldDestination is a delivery destination this element can resolve a DID to.
//
// The X1 delivery type is kept as the ADMF stated it rather than reduced to a single
// product type. Reducing it is what stopped an "X2andX3" destination from ever yielding
// an X2 endpoint: one destination serving both interfaces is one record here and two
// endpoints at the point of delivery.
type heldDestination struct {
	Address      string // "host:port", the form the X2/X3 senders dial
	DeliveryType string // X2Only | X3Only | X2andX3
	FriendlyName string // the ADMF's own name for it, where one was given
	// Configured marks an entry declared in this element's configuration rather than
	// provisioned over X1.
	Configured bool
}

// endpoints expands a destination into the delivery endpoints it serves.
//
// did is the identifier the destination was resolved by, and it is carried onto
// every endpoint. It used to be dropped here, which left the element unable to say
// *which* destination a delivery fault concerned — the identifier was discarded at
// the boundary between provisioning and delivery, so it was absent from the domain
// model every point of interception works in, not merely from the sites that
// notice a fault.
func (d heldDestination) endpoints(did string) []types.DeliveryEndpoint {
	switch d.DeliveryType {
	case deliveryX2Only:
		return []types.DeliveryEndpoint{{Type: types.DeliveryX2, Address: d.Address, DID: did}}
	case deliveryX3Only:
		return []types.DeliveryEndpoint{{Type: types.DeliveryX3, Address: d.Address, DID: did}}
	case deliveryX2andX3:
		return []types.DeliveryEndpoint{
			{Type: types.DeliveryX2, Address: d.Address, DID: did},
			{Type: types.DeliveryX3, Address: d.Address, DID: did},
		}
	default:
		// Unreachable: a destination is only stored once deliveryProducts has accepted
		// its type. Returning nothing rather than guessing keeps an unknown type from
		// becoming a delivery to the wrong interface.
		return nil
	}
}

// Option customises a Server.
type Option func(*Server)

// PurgeReason says why tasking was removed. It exists because the removals differ
// in what they mean to an operator, not in what they do to the element.
type PurgeReason int

const (
	// PurgeWithdrawal: an explicit DeactivateTask. The expected end of an
	// interception.
	PurgeWithdrawal PurgeReason = iota
	// PurgeBulkDeactivate: DeactivateAllTasks. Expected too — a provisioning
	// function clearing this element deliberately.
	PurgeBulkDeactivate
	// PurgeKeepaliveLapse: the fail-safe, because the controlling function stopped
	// answering. Nothing asked for this, and it is the only one of the three an
	// operator must investigate.
	PurgeKeepaliveLapse
)

// OnTaskChange registers the lifecycle callback: one event per transition of this
// element's tasking, carrying the task as it was and as it becomes.
//
//	(nil, task)  activation
//	(prev, next) modification, or an activation replacing an XID already held
//	(task, nil)  removal — deactivation, bulk deactivation, or fail-safe purge
//
// It supersedes OnActivate/OnDeactivate and is preferred when set. The pair could
// not express a modification: a ModifyTask keeps the XID, so "the old task" and
// "the new task" are the same key, and a POI receiving them as two events had to
// infer an ordering the provisioning interface never stated. Where the POI's
// response was to install state for the new task and remove state for the old,
// under that shared key, the removal could reclaim what the installation had just
// created.
//
// The POI decides what changed. This package no longer guesses from the target
// identifiers alone — a task's products can change with its targets untouched, and
// every guess of that kind is another field somebody forgot.
//
// An exact replay is not a transition and fires nothing: re-provisioning is how a
// provisioning function restores tasking after a restart, and it must not re-emit
// records that report the beginning of an interception that never stopped.
//
// The callback runs synchronously on the X1 request goroutine, so it must not
// block. Both pointers are to values owned by the caller for the duration of the
// call; a POI keeping either must copy it.
func OnTaskChange(fn func(prev, next *types.InterceptTask)) Option {
	return func(s *Server) { s.onTaskChange = fn }
}

// OnPurge registers a callback run after tasking has been removed, naming why.
//
// It carries no instruction — the removal itself travels on OnTaskChange, and has
// already happened by the time this runs. It exists so that an element reporting
// "my tasking was purged" can say whether anybody asked for it. An element that
// reports every withdrawal as a fail-safe purge teaches its operator to ignore the
// channel, and the report that matters then arrives into that habit.
func OnPurge(fn func(types.InterceptTask, PurgeReason)) Option {
	return func(s *Server) { s.onPurge = fn }
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

// FaultProbe reports whether one fault condition currently holds. It returns nil when the
// condition does not hold, and the fault to report when it does.
//
// A probe is asked at the moment a provisioning function asks for the element's status, so it
// describes the present rather than the past. Whoever holds the knowledge owns the probe: only
// the content shipper knows whether its mediation function is reachable, and only the datapath
// knows whether it is currently losing copies.
type FaultProbe func() *X1Error

// NEFault is the fault a probe reports for one of the conditions in report.go.
//
// The condition leads the description exactly as it does in a pushed report, so an ADMF
// reads the same token whichever mechanism carried it and a probe cannot invent a
// vocabulary of its own. detail says how much is wrong: it must name no target, warrant or
// destination, since the element's own status carries none of those and a probe written by
// whoever holds the knowledge is where that rule is easiest to break.
//
// The error code is the registry's generic one. TS 103 221-1's codes name failures of a
// *request*, and none of them names a condition of the element, so what an ADMF can act on
// here is the condition rather than a number picked to look specific.
func NEFault(condition, detail string) *X1Error {
	return &X1Error{
		ErrorCode:        errCodeGeneric,
		ErrorDescription: condition + ": " + detail,
	}
}

// MDFUnreachableProbe returns the probe every POI registers: whether the mediation functions
// this element delivers to can be reached right now.
//
// count answers how many destinations are currently unreachable and how many are in use at
// all — x2x3.Pool.Unreachable is that function, and a POI keeping its own clients supplies
// the equivalent. It is called on the X1 request goroutine, so it must not perform I/O
// (see FaultProbe).
//
// It takes counts rather than the destinations themselves so that the answer *cannot* name
// one. An element's own status says how much is wrong, never whose product is affected, and
// making that structural is cheaper than remembering it at three call sites.
func MDFUnreachableProbe(count func() (unreachable, inUse int)) FaultProbe {
	return func() *X1Error {
		unreachable, inUse := count()
		if unreachable == 0 {
			return nil
		}

		return NEFault(NEIssueMDFUnreachable, fmt.Sprintf(
			"%d of %d delivery destination(s) unreachable", unreachable, inUse))
	}
}

// WithFaultProbes registers conditions the element can observe about itself, for the status a
// provisioning function can ask for.
//
// Registering none is a legitimate configuration and not a silent one: the element then answers
// that no observable condition holds, which is true. What it does *not* mean is that nothing has
// ever gone wrong — faults are pushed as they happen over ReportNEIssue, and the ones that are
// events rather than states cannot be re-observed later. The two mechanisms answer different
// questions, "what just went wrong" and "what is wrong now", and neither replaces the other.
func WithFaultProbes(probes ...FaultProbe) Option {
	return func(s *Server) { s.faultProbes = append(s.faultProbes, probes...) }
}

// WithoutDeactivateAllTasks refuses bulk deactivation, which TS 103 221-1 otherwise requires
// an element to perform by default.
//
// Named for the non-default so that the default is visible by its absence: an element with no
// option set will stop every interception on one authenticated message, because the
// specification says it must.
func WithoutDeactivateAllTasks() Option {
	return func(s *Server) { s.deactivateAllDisabled = true }
}

// WithRemoveAllDestinations permits bulk destination removal, which is refused by default.
//
// The asymmetry with the option above is the specification's: bulk deactivation defaults to
// enabled and this does not. Deactivating everything stops interception, which is the safe
// direction; removing every destination leaves an element still tasked and with nowhere to
// deliver.
func WithRemoveAllDestinations() Option {
	return func(s *Server) { s.removeAllDestinationsEnabled = true }
}

// BulkOptions turns a deployment's expressed policy on the two bulk operations into the
// options that carry it, so a network function reads its configuration and passes the
// result rather than deciding for itself what an unset value means.
//
// A nil value is "no agreement in advance" — the specification's own phrase for the state
// its defaults are stated against — and yields no option, leaving the default this package
// holds. A non-nil value that already matches the default likewise yields no option, since
// the options express deviations.
//
// It exists because three network functions would otherwise each write the same pair of
// conditions, one of which is inverted with respect to the other. A single inverted
// condition in one of them changes what one element does about a destructive operation,
// which is the least likely difference to be noticed and the worst to have.
func BulkOptions(deactivateAllTasks, removeAllDestinations *bool) []Option {
	var opts []Option
	if deactivateAllTasks != nil && !*deactivateAllTasks {
		opts = append(opts, WithoutDeactivateAllTasks())
	}
	if removeAllDestinations != nil && *removeAllDestinations {
		opts = append(opts, WithRemoveAllDestinations())
	}
	return opts
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

// ConfiguredDestination is a DID→endpoint mapping declared in a network function's own
// configuration, for destinations an ADMF and an operator agreed out of band.
//
// DID must be the UUID the schema defines, DeliveryType one of X2Only, X3Only and
// X2andX3, and Address a "host:port" — the same three things CreateDestination carries,
// because the entry has to resolve identically to a provisioned one.
type ConfiguredDestination struct {
	DID          string
	DeliveryType string
	Address      string
}

// Valid reports whether this entry can be resolved, or why it cannot.
//
// Exported because a POI has somewhere to report a rejected entry and this package does
// not: an unusable mapping means a task naming that DID silently resolves to the
// configured default instead, which is the class of silence this whole change is about.
// The option below drops such an entry; the network function that supplied it tells the
// ADMF over X1.
func (d ConfiguredDestination) Valid() error {
	if err := validIdentifier("did", d.DID); err != nil {
		return err
	}
	if _, err := deliveryProducts(d.DeliveryType); err != nil {
		return err
	}
	if _, _, err := net.SplitHostPort(d.Address); err != nil {
		return fmt.Errorf("address is not host:port")
	}

	return nil
}

// WithConfiguredDestinations declares destinations this element can resolve without
// their having been provisioned over X1.
//
// TS 33.128 requires that a task *name* its delivery endpoints and that the element
// deliver to what it named; neither it nor TS 103 221-1 requires that the element
// learned the mapping over X1 rather than by agreement. So an ADMF referencing
// pre-shared destinations is conformant, and refusing it would be wrong.
//
// A destination provisioned over X1 under the same DID takes precedence, and the
// element says so in what it reports about its destinations — a configured entry
// silently superseded is the one outcome this must not have.
//
// A malformed entry is dropped rather than stored: it is operator configuration, not a
// peer's message, so there is nobody to refuse, and storing it would resolve a task's
// destination to an address nothing can dial. Dropping it is not the same as ignoring it —
// see ConfiguredDestination.Valid, which the caller uses to tell the ADMF.
func WithConfiguredDestinations(dests ...ConfiguredDestination) Option {
	return func(s *Server) {
		for _, d := range dests {
			if d.Valid() != nil {
				continue
			}
			s.configured[d.DID] = heldDestination{
				Address:      d.Address,
				DeliveryType: d.DeliveryType,
				Configured:   true,
			}
		}
	}
}

// NewServer returns an X1 Server backed by s, identifying itself as neID.
func NewServer(s *store.Store, neID string, opts ...Option) *Server {
	srv := &Server{
		store:        s,
		neID:         neID,
		now:          func() time.Time { return time.Now().UTC() },
		destinations: make(map[string]heldDestination),
		configured:   make(map[string]heldDestination),
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
		// TS 103 221-1 clause 6.1: "If the X1 Request could not be parsed, then the
		// response shall be constructed with an ADMF and NE Identifier …,
		// MessageTimestamp and Version, and a 'TopLevelError' flag but no other
		// information." The schema defines the element for it, so a conformant ADMF
		// has a structured answer to expect.
		//
		// Clause 7.2.2.2 settles the status code and it is the opposite of what stood
		// here: "HTTP error codes shall only be used to indicate HTTP-level errors, and
		// shall not be used to indicate errors with the X1 responses themselves." A
		// request that arrived intact and could not be parsed is an X1-level error, so
		// it is a 200 carrying the defined response — where this answered 400 with the
		// decoder's own message as the body, which is neither the defined answer nor a
		// thing an LI interface should be putting on the wire.
		w.Header().Set("Content-Type", "application/xml")
		//nolint:errcheck // a peer that hung up mid-response is not actionable, and must not be logged
		_, _ = w.Write(s.topLevelError(peer))

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

// topLevelErrorTemplate is the clause 6.1 answer to a request that could not be
// parsed. It is a different root element from X1Response — the schema declares
// X1TopLevelErrorResponse separately — and carries exactly four fields. Notably it
// has no x1TransactionId: table 6.1-1 makes that field conditional and says it
// "shall be omitted for 'TopLevelError' situations", which is consistent, since
// the identifier would have had to come from the request nobody could read.
var topLevelErrorTemplate = template.Must(template.New("x1tle").Funcs(template.FuncMap{
	"esc": escapeXML,
}).Parse(`<?xml version="1.0" encoding="UTF-8"?>
<ns1:X1TopLevelErrorResponse xmlns:ns1="http://uri.etsi.org/03221/X1/2017/10">
  <ns1:admfIdentifier>{{esc .AdmfID}}</ns1:admfIdentifier>
  <ns1:neIdentifier>{{esc .NeID}}</ns1:neIdentifier>
  <ns1:messageTimestamp>{{esc .Timestamp}}</ns1:messageTimestamp>
  <ns1:version>{{esc .Version}}</ns1:version>
</ns1:X1TopLevelErrorResponse>`))

// topLevelError renders the clause 6.1 response.
//
// The ADMF identifier cannot come from the request, so it comes from
// configuration — or, where this element has no configured ADMF, from the peer's
// certificate, which is what clause 6.1's "extracting the identifier of the
// Requester from the X.509 certificate if necessary" provides for. An empty value
// would not validate against the schema, and answering a peer we cannot name at
// all with a malformed message would compound the fault rather than report it.
func (s *Server) topLevelError(peer *x509.Certificate) []byte {
	admf := s.admfID
	if admf == "" {
		admf = certUID(peer)
	}

	var body bytes.Buffer
	if err := topLevelErrorTemplate.Execute(&body, struct {
		AdmfID, NeID, Timestamp, Version string
	}{
		AdmfID:    admf,
		NeID:      s.neID,
		Timestamp: x1Timestamp(s.now()),
		Version:   supportedVersion,
	}); err != nil {
		// Executing a template over four strings cannot fail; returning an empty body
		// is still better than panicking on the provisioning path.
		return nil
	}

	return body.Bytes()
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
			MessageTimestamp: x1Timestamp(s.now()),
			Version:          echoVersion(m.Version),
			X1TransactionID:  echoTransactionID(m.X1TransactionID),
			ErrorInformation: &X1Error{ErrorCode: code, ErrorDescription: desc},
			// The schema makes requestMessageType mandatory on an ErrorResponse. A refusal
			// that does not validate is a refusal a peer discards, so the type travels even
			// on the authentication path — where the request is refused before anything but
			// its type has been trusted.
			RequestType: localType(m.Type),
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
	s.purgeAllTasking(PurgeKeepaliveLapse)
}

// purgeAllTasking removes every task and runs the per-task teardown over what was there.
//
// The order matters, and is why this is one function rather than two callers each doing it: the
// store is cleared *first*, so a POI re-deriving against the task set during its own teardown
// sees an empty one. Clearing the store alone is not a purge — a CC-POI's duplication would keep
// running with its product going nowhere attributable — and running the hooks first would have
// each of them re-derive against tasks still present.
//
// Both the keepalive fail-safe and DeactivateAllTasks arrive here, which is what stops a bulk
// deactivation becoming a second, subtly different implementation of the same thing.
func (s *Server) purgeAllTasking(reason PurgeReason) {
	tasks := s.store.Snapshot()
	s.store.DeactivateAll()
	for _, t := range tasks {
		s.notifyRemoved(t, reason)
	}
}

// deactivateAll performs the bulk deactivation TS 103 221-1 requires every implementation to
// support: "If enabled, the DeactivateAllTasks command shall perform a 'DeactivateTask' command
// for all Tasks on the NE."
func (s *Server) deactivateAll() { s.purgeAllTasking(PurgeBulkDeactivate) }

// notifyChanged reports a successful activation or modification as the one
// transition it is.
//
// An exact replay fires nothing. An ADMF re-sending tasking it already sent — its
// restart-recovery path — must not make this element re-emit records that report
// the beginning of an interception, because none began, and must not tear down and
// rebuild state that was already correct.
//
// What changed is the POI's to work out. Deciding here, from the target
// identifiers alone, is what made a change of products invisible: adding CC never
// began content interception for a target's existing sessions, and removing it
// left that interception running after the authority for it was gone.
func (s *Server) notifyChanged(prevTask types.InterceptTask, hadPrev bool, task types.InterceptTask) {
	if s.onTaskChange == nil || (hadPrev && sameTask(prevTask, task)) {
		return
	}

	var prev *types.InterceptTask
	if hadPrev {
		prev = &prevTask
	}
	s.onTaskChange(prev, &task)
}

// sameTask reports whether two tasks are the same in every field a POI could act
// on. Used only to recognise a replay; anything else is a transition and is the
// POI's to interpret.
func sameTask(a, b types.InterceptTask) bool {
	return reflect.DeepEqual(a, b)
}

// notifyRemoved runs a removal's teardown and then names why it happened. The
// order is the contract: what is being reported is that interception stopped, so
// it must have stopped.
func (s *Server) notifyRemoved(task types.InterceptTask, reason PurgeReason) {
	if s.onTaskChange != nil {
		s.onTaskChange(&task, nil)
	}
	if s.onPurge != nil {
		s.onPurge(task, reason)
	}
}

// destinationsInUse counts the destinations some task still references.
//
// The specification refuses a bulk removal while any is referenced, and the reason is worth
// holding on to: a task whose destination has gone is a task producing product with nowhere to
// send it — the failure RequireResolvableDIDs exists to prevent, reached by removing the
// destination rather than by never providing it.
func (s *Server) destinationsInUse() int {
	referenced := make(map[string]struct{})
	for _, t := range s.store.Snapshot() {
		for _, did := range t.DIDs {
			referenced[did] = struct{}{}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	for did := range s.destinations {
		if _, ok := referenced[did]; ok {
			n++
		}
	}

	return n
}

// removeAllDestinations empties the provisioned destination store. Only reachable when
// the operation is enabled and nothing references a destination.
//
// Configured entries are untouched. They are the operator's, not the ADMF's: the
// specification's bulk removal is over "all Destinations on the NE" in the sense of
// those an ADMF created, and an X1 message that could delete an element's own
// configuration would be a different and much larger power.
func (s *Server) removeAllDestinations() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.destinations = make(map[string]heldDestination)
}

func (s *Server) apply(m X1RequestMessage) X1ResponseMessage {
	rm := X1ResponseMessage{
		AdmfIdentifier:   m.AdmfIdentifier,
		NeIdentifier:     s.neID,
		MessageTimestamp: x1Timestamp(s.now()),
		Version:          echoVersion(m.Version),
		X1TransactionID:  echoTransactionID(m.X1TransactionID),
	}

	var err error
	var code int // TS 103 221-1 error code; 0 means "pick the generic one"
	switch localType(m.Type) {
	case "ActivateTaskRequest", "ModifyTaskRequest":
		// An activation naming an XID this element already holds replaces it rather
		// than being refused, which is deliberate: re-provisioning is how an ADMF
		// restores tasking after an element restarts, and refusing it
		// would break the recovery path the fault reporting exists to trigger.
		// Modifying tasking that is *not* held has no such reading and is refused
		// below.
		//
		// The task already held is read for both, so that a replacement carries what
		// it replaces to the POI: an activation over a held XID changes this
		// element's tasking exactly as a modification does, and a POI told only
		// about the new task has no way to take down the state it applied for the
		// old one.
		isModify := localType(m.Type) == "ModifyTaskRequest"
		var prevTask types.InterceptTask
		var hadPrev bool
		if m.TaskDetails != nil {
			prevTask, hadPrev = s.store.Get(types.XID(m.TaskDetails.XID))
		}
		// Two questions answered before the switch, because each one picks a case, and
		// answered here rather than inside taskFromDetails because the code for a task
		// refusal differs between an activation and a modification.
		//
		// They are separate questions and stay separate: a value that violates the format
		// its schema defines is malformed, which is a general message error, while a field
		// this element cannot honour is a well-formed instruction it must refuse. The
		// registry orders them the same way, and so does the switch.
		var malformed, unhonourable error
		if m.TaskDetails != nil {
			malformed = malformedTaskIdentifiers(*m.TaskDetails)
			unhonourable = unhonourableTaskFields(*m.TaskDetails)
		}
		switch {
		case isModify && m.TaskDetails == nil:
			err = fmt.Errorf("missing taskDetails")
		case malformed != nil:
			// Before the "no such task" check below, deliberately. A ModifyTask naming a
			// malformed xId reached that check first and was refused with 2020, "XID does
			// not exist on NE" — true, but an accident of ordering, and it points the ADMF
			// at activating a task that would fail for the same reason. 1010 names the
			// actual fault, and "implementers shall use the most specific error code
			// available".
			err = malformed
			code = errorCode(err)
		case unhonourable != nil:
			err = unhonourable
			code = errorCode(err)
			if code == 0 {
				code = taskFailureCode(isModify)
			}
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
			// A refusal from the activate path may name its own code — a malformed
			// identifier is a schema error, not a generic failure — so it travels
			// rather than being flattened below.
			code = errorCode(err)
			if err != nil && code == 0 {
				// What is left is a refusal whose reason is in the description: a POI's
				// CanApply saying it cannot carry out this task, or a field of the task
				// details this element will not accept. 3000/3001 are the registry's own
				// "details of why the Task cannot be activated/modified", which is what
				// that is; 1000 says only that something went wrong, and an ADMF reads
				// the code before the text.
				code = taskFailureCode(isModify)
			}
			if err == nil {
				s.notifyChanged(prevTask, hadPrev, task)
			}
		}
		rm.Type = strings.Replace(localType(m.Type), "Request", "Response", 1)
	case "DeactivateTaskRequest":
		code, err = s.deactivate(m.XID)
		if err != nil && code == 0 {
			code = errorCode(err)
		}
		rm.Type = "DeactivateTaskResponse"
	case "DeactivateAllTasksRequest":
		if s.deactivateAllDisabled {
			// The specification's own text, verbatim, because an ADMF may match on it.
			err = fmt.Errorf("DeactivateAllTasks message is not enabled")
			code = errCodeDeactAllOff
		} else {
			s.deactivateAll()
		}
		rm.Type = "DeactivateAllTasksResponse"
	case "RemoveAllDestinationsRequest":
		if !s.removeAllDestinationsEnabled {
			// Verbatim again — and note the specification says "request" here where it says
			// "message" above. That asymmetry is its own, and is preserved rather than
			// tidied, because tidying it would break a peer matching the published string.
			err = fmt.Errorf("RemoveAllDestinations request is not enabled")
			code = errCodeRemoveAllOff
		} else if n := s.destinationsInUse(); n > 0 {
			// "Since a RemoveDestination request can only be issued against destinations that
			// are not in use, an NE shall respond with an error if the ADMF sends a
			// RemoveAllDestinations request while any of the Destinations are referenced by
			// Tasks."
			err = fmt.Errorf("%d destination(s) are referenced by tasks", n)
			code = errCodeDestinationsInUse
		} else {
			s.removeAllDestinations()
		}
		rm.Type = "RemoveAllDestinationsResponse"
	case "GetAllTaskDetailsRequest":
		// One of the interrogation set TS 103 221-1 clause 6.4.1 requires every
		// implementation to support. It projects the same task state GetAllDetails does,
		// through the same renderer, so the two answers cannot disagree about what this
		// element holds — an ADMF that got different answers could not tell which to trust.
		rm.Tasks = s.store.Snapshot()
		rm.Type = "GetAllTaskDetailsResponse"
	case "GetAllDestinationDetailsRequest":
		rm.Destinations = s.heldDestinations()
		rm.Type = "GetAllDestinationDetailsResponse"
	case "ListAllDetailsRequest":
		// Identifiers only. This is what an ADMF reaches for after being told an element has
		// lost its tasking: it needs the list before it can reconcile, and answering with an
		// empty one is a usable answer where an error is not.
		rm.Tasks = s.store.Snapshot()
		rm.Destinations = s.heldDestinations()
		rm.Type = "ListAllDetailsResponse"
	case "GetNEStatusRequest":
		rm.Faults = s.unresolvedFaults()
		rm.Type = "GetNEStatusResponse"
	case "GetDestinationDetailsRequest":
		if m.DID == "" {
			err = fmt.Errorf("missing dId")
		} else if d, found := s.destinationByDID(m.DID); found {
			rm.Destinations = []ReportedDestination{d}
		} else {
			// A destination the element does not hold is an error, not an empty answer: an
			// empty success would tell the ADMF the destination exists and is blank.
			err = fmt.Errorf("no such destination")
			code = errCodeNoSuchDID
		}
		rm.Type = "GetDestinationDetailsResponse"
	case "GetTaskDetailsRequest", "GetAllDetailsRequest":
		// A provisioning function has no other way to discover that this element has
		// lost the tasking it was given — a restart discards it, and nothing pushes
		// that fact anywhere. Answering these is what lets an ADMF audit and
		// re-provision instead of believing an interception is running that is not
		// — which TS 103 221-1 also requires.
		if localType(m.Type) == "GetAllDetailsRequest" {
			rm.Tasks = s.store.Snapshot()
			rm.Destinations = s.heldDestinations()
			rm.Faults = s.unresolvedFaults()
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
	case "GetAllGenericObjectDetailsRequest":
		// Answered rather than refused, because clause 6.4.1 lists it among the requests that
		// "shall be supported" with no qualifier — unlike DeleteAllObjects below, which is
		// required only "if the implementation supports Generic Objects".
		//
		// The answer omits listOfGenericObjectResponseDetails, which is what the specification
		// defines for an element in this position: "May be omitted if Generic Objects are not
		// supported by the NE". The same sentence governs the object lists inside GetAllDetails
		// and ListAllDetails, which this element already omits, so all three answers now say the
		// same thing about Generic Objects. An *empty* list would be a different and false
		// claim — that they are implemented and none is held.
		rm.Type = "GetAllGenericObjectDetailsResponse"
	case "CreateObjectRequest", "ModifyObjectRequest", "GetObjectRequest",
		"DeleteObjectRequest", "ListObjectsOfTypeRequest", "DeleteAllObjectsRequest":
		// The clause 6.8 object CRUD, which is conditional where the query above is not:
		// "The DeleteAllObjects request shall be supported if the implementation supports
		// Generic Objects", and an element that cannot store an object "shall reject the
		// CreateObjectRequest with an appropriate error response".
		//
		// Refused explicitly rather than by falling through to the unknown-type case, so that
		// the difference between this and the query above is stated where it is decided. An
		// acknowledgement would tell a provisioning function its object had been stored.
		err = fmt.Errorf("this NE does not support Generic Objects")
		code = errCodeUnsupportedRequest
	case "CreateDestinationRequest":
		code, err = s.createDestination(m.DestinationDetails)
		if err != nil && code == 0 {
			code = errorCode(err)
		}
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
		rm.RequestType = localType(m.Type)
		if code == 0 {
			code = errCodeGeneric
		}
		rm.ErrorInformation = &X1Error{ErrorCode: code, ErrorDescription: err.Error()}
	} else {
		rm.OK = ackOK
	}
	return rm
}

// deactivate removes one task, or reports why it cannot.
//
// TS 103 221-1 table 6.2.3-2 is explicit about the last case: "it is an error if the XID is
// not already present at the NE" — the mirror of the CreateDestination rule this element
// already answers with 2030, and the reason 2020 exists.
//
// It used to acknowledge unconditionally, which is the worst answer available. An ADMF
// withdrawing a warrant with a mistyped XID was told the withdrawal had completed while the
// interception went on running, and interception outliving its authority is the one
// direction this plane must never fail in. A malformed identifier was accepted on the same
// path for the same reason.
//
// The consequence of fixing it is worth stating, because it changes what a deployed element
// answers: an ADMF that re-sends a deactivation for tasking this element no longer holds —
// after a keepalive purge or a restart, say — now receives 2020 where it received an
// acknowledgement before. That is the point. It is the only way the ADMF can learn the
// element was not holding the warrant it thought it was withdrawing.
func (s *Server) deactivate(xid string) (int, error) {
	if xid == "" {
		return 0, fmt.Errorf("missing xId")
	}
	if err := validIdentifier("xId", xid); err != nil {
		return 0, err
	}

	// Read before removal so a POI can undo state it applied for the target (e.g. clear
	// mid-session CC on the SMF), and so "was it held" is answered from the same read.
	task, existed := s.store.Get(types.XID(xid))
	if !existed {
		return errCodeNoSuchTask, fmt.Errorf("no such task")
	}
	s.store.Deactivate(types.XID(xid))
	s.notifyRemoved(task, PurgeWithdrawal)

	return 0, nil
}

// createDestination records a delivery destination against its DID. Re-creating
// an existing DID is an error per TS 103 221-1 clause 6.3.1.1 ("it is an error if the
// DID is already present at the NE"), so a misconfiguration cannot silently redirect an
// agency's product elsewhere.
//
// It returns the TS 103 221-1 error code alongside the reason, since the registry names
// two of these refusals exactly and "implementers shall use the most specific error code
// available". A zero code leaves the caller to pick the generic one.
func (s *Server) createDestination(d *DestinationDetails) (int, error) {
	if d == nil {
		return 0, fmt.Errorf("missing destinationDetails")
	}
	if d.DID == "" {
		return 0, fmt.Errorf("missing dId")
	}
	if err := validIdentifier("dId", d.DID); err != nil {
		// The schema types a DId as a TS 103 280 UUID, so a value outside that format
		// is a schema error rather than a destination-creation failure — 1010 names
		// what is actually wrong where 6000 would name only where it happened.
		//
		// Refusing it matters beyond tidiness: an element that stores a malformed
		// identifier interoperates with a provisioning function no conformant one would
		// produce, and its own test material stops being a guide to what a real ADMF
		// sends. Ours said `pre-shared-did` for months.
		return 0, err
	}
	if _, err := deliveryProducts(d.DeliveryType); err != nil {
		return 0, err
	}
	if err := unhonourableExtensions(d.Extensions, "destination"); err != nil {
		// No destination extension is recognised, so every one reaches this. The rule
		// is the task's: an extension exists to change the meaning of the message that
		// carries it, and on a destination that means changing where product goes.
		return 0, err
	}
	dest, err := destinationFrom(*d)
	if err != nil {
		return 0, err
	}

	// Whether a task references the DID is answered from the task store, which has its
	// own lock, so it is asked before s.mu is taken.
	referenced := s.didReferenced(d.DID)

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.destinations[d.DID]; exists {
		// The wording is matched on by a peer that has to tell "already there" from
		// "something went wrong" — as an ADMF re-provisioning after a restart does —
		// so it stays as it is now that the code says the same thing.
		return errCodeDIDExists, fmt.Errorf("destination already present")
	}
	if _, declared := s.configured[d.DID]; declared && referenced {
		// A provisioned destination wins over a configured one (see resolveLocked), but
		// a task's endpoints are resolved once at activation and copied into the task.
		// Creating this would therefore change what the element *answers* about the DID
		// while every task activated before this moment kept delivering to the
		// configured address — so a provisioning function could read the new destination
		// back from an element still sending a live warrant's product to the old one.
		//
		// Refused only where both hold. Creating under a configured DID nothing
		// references is how an operator's static declaration gets replaced before use,
		// and that stays available.
		return errCodeCreateDestFailed, fmt.Errorf(
			"dId %s is declared in this element's configuration and referenced by an active task", d.DID)
	}
	s.destinations[d.DID] = dest
	return 0, nil
}

// didReferenced reports whether any task this element holds names the DID.
func (s *Server) didReferenced(did string) bool {
	for _, t := range s.store.Snapshot() {
		if slices.Contains(t.DIDs, did) {
			return true
		}
	}

	return false
}

// destinationFrom maps provisioned destination details onto the destination this element
// holds: where the X2/X3 senders dial, and what it may be dialled for.
func destinationFrom(d DestinationDetails) (heldDestination, error) {
	if d.Address.IPAddressAndPort == nil {
		// A URI, E.164 number or email address. 6020 is the registry's own entry for
		// it; the generic code said only that the destination could not be created.
		return heldDestination{}, codedError{errCodeBadAddressType, fmt.Errorf("unsupported deliveryAddress")}
	}
	ap := d.Address.IPAddressAndPort
	host := ap.Address.IPv4
	if host == "" {
		// An IPv6 literal needs brackets before it can be joined to a port.
		if ap.Address.IPv6 == "" {
			return heldDestination{}, fmt.Errorf("deliveryAddress carries no IP address")
		}
		host = "[" + ap.Address.IPv6 + "]"
	}
	port := ap.Port.Value()
	if port == 0 {
		return heldDestination{}, fmt.Errorf("deliveryAddress carries no port")
	}

	return heldDestination{
		Address:      host + ":" + strconv.FormatUint(uint64(port), 10),
		DeliveryType: d.DeliveryType,
		FriendlyName: d.FriendlyName,
	}, nil
}

// resolveLocked returns the destination a DID names, preferring one provisioned over X1
// to one declared in configuration. Caller holds s.mu.
func (s *Server) resolveLocked(did string) (heldDestination, bool) {
	if d, ok := s.destinations[did]; ok {
		return d, true
	}
	d, ok := s.configured[did]

	return d, ok
}

// resolveDIDs turns the DIDs a task references into delivery endpoints, skipping
// any this element cannot resolve.
//
// Skipping rather than rejecting is deliberate. A task naming an unresolvable DID
// is arguably malformed, but an ADMF is entitled to task an IRI-POI whose MDF2
// address comes from configuration — which is how this implementation has always
// worked, and what the sipgate simulator does — so failing the task here would
// stop interception working against every ADMF that does not call
// CreateDestination first. The strictness belongs at the point of delivery
// instead: a POI that has no destination for the product it was asked to produce
// must refuse to produce it, which is where an unresolvable destination becomes
// visible (as a reported fault) rather than silent.
//
// What is *not* skipped is a DID that resolves. Delivering to this element's own
// configured endpoint in preference to one the task named is the gap this change
// closes: two warrants provisioned to two agencies both arrived at whichever address
// configuration happened to name.
func (s *Server) resolveDIDs(dids []string) []types.DeliveryEndpoint {
	if len(dids) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	var out []types.DeliveryEndpoint
	for _, did := range dids {
		if dest, ok := s.resolveLocked(did); ok {
			out = append(out, dest.endpoints(did)...)
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
	// Answer with the task as this element now holds it, not as it was built. The
	// store stamps the task state, so a caller comparing this against what it held
	// before — which is how a replay is told from a change — must be comparing two
	// values of the same provenance.
	stored, _ := s.store.Get(task.XID)

	return stored, nil
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
		mapped, err := mapTarget(ti)
		if err != nil {
			return types.InterceptTask{}, err
		}
		targets = append(targets, mapped...)
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
		DIDs:          td.ListOfDIDs,
		Products:      products,
		ProductID:     types.XID(td.ProductID),
		CorrelationID: correlation,
		Deliveries:    deliveries,
		RecordScope:   recordScope(td),
	}, nil
}

// targetXML renders one target identifier as the contents of a
// <targetIdentifier> element, in the form the schemas define for it.
//
// It exists because an identifier cannot be reported as "element name plus value":
// the LI_T3 packet-detection criteria are not plain identifier elements but arms of
// a 3GPP extension, nested inside targetIdentifierExtension with an Owner. Rendering
// them as a plain element produced XML no ADMF could validate — and, worse, criteria
// with no mapping of their own were reported as `supiimsi`, telling an auditing ADMF
// that the element was tasked by a subscriber identity when it was tasked by a
// tunnel, a port or a direction. GetTaskDetails and GetAllDetails exist so an ADMF
// can discover what an element actually holds; answering them wrongly defeats the
// only mechanism it has.
//
// The output round-trips: what this emits, mapTarget parses back to the same
// identifier.
func targetXML(t types.TargetIdentifier) string {
	// The element names come from types, which is where they have to live now that
	// the X2 conditional attribute of TS 103 221-2 clause 5.3.18 renders the same
	// identifiers: one mapping, so the two interfaces cannot come to disagree about
	// what an identifier is called. The prefix is this document's, not the mapping's.
	if el, ok := t.Type.XMLElement(); ok {
		return "<ns1:" + el + ">" + escapeXML(t.Value) + "</ns1:" + el + ">"
	}

	arm, ok := extensionTargetArm(t)
	if !ok {
		// An identifier this package cannot render is reported as nothing rather than
		// as something else. An empty targetIdentifier is visibly wrong to an ADMF;
		// a plausible but incorrect one is not.
		return ""
	}

	return "<ns1:targetIdentifierExtension>" +
		"<ns1:Owner>" + ExtensionOwner3GPP + "</ns1:Owner>" +
		"<ext:UPFLIT3TargetIdentifierExtensions>" +
		"<ext:UPFLIT3TargetIdentifier>" + arm + "</ext:UPFLIT3TargetIdentifier>" +
		"</ext:UPFLIT3TargetIdentifierExtensions>" +
		"</ns1:targetIdentifierExtension>"
}

// extensionTargetArm renders the 3GPP LI_T3 arm for a packet-detection criterion.
func extensionTargetArm(t types.TargetIdentifier) (string, bool) {
	el := func(name, v string) string { return "<ext:" + name + ">" + escapeXML(v) + "</ext:" + name + ">" }

	switch t.Type {
	case types.TargetFSEID:
		return "<ext:FSEID>" + el("SEID", t.Value) + "</ext:FSEID>", true
	case types.TargetFTEID:
		// The value is "TEID" or "TEID@address"; the address, when present, is the
		// node that terminates the tunnel.
		teid, addr, hasAddr := strings.Cut(t.Value, "@")
		arm := "<ext:FTEID>" + el("TEID", teid)
		if hasAddr {
			// The same arm selection and the same rendering rule the triggering
			// path uses. This answer echoes a value a peer supplied, so a
			// conformant peer's value round-trips untouched; normalising it here
			// is what keeps a *non*-conformant one from making this element's own
			// details answer invalid, which is the answer an ADMF audits with.
			name, value := addressArm(addr)
			arm += el(name, value)
		}

		return arm + "</ext:FTEID>", true
	case types.TargetPDRID:
		return el("PDRID", t.Value), true
	case types.TargetQERID:
		return el("QERID", t.Value), true
	case types.TargetNetworkInstance:
		return el("NetworkInstance", t.Value), true
	case types.TargetGTPTunnelDirection:
		return el("GTPTunnelDirection", t.Value), true
	case types.TargetPDR:
		return el("PDR", t.Value), true
	default:
		return "", false
	}
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

// mapTarget maps one X1 target identifier onto the criteria it names. It returns
// a slice because one arm — the LI_T3 extension — is itself a list, and every
// member of that list is a criterion the task ordered.
func mapTarget(t TargetIdentifier) ([]types.TargetIdentifier, error) {
	switch {
	case t.SUPIIMSI != "":
		return one(types.TargetSUPI, t.SUPIIMSI), nil
	case t.IMSI != "":
		return one(types.TargetSUPI, t.IMSI), nil
	case t.SUPINAI != "":
		return one(types.TargetSUPI, t.SUPINAI), nil
	case t.PEIIMEI != "":
		return one(types.TargetPEI, t.PEIIMEI), nil
	case t.PEIIMEISV != "":
		return one(types.TargetPEI, t.PEIIMEISV), nil
	case t.GPSIMSISDN != "":
		return one(types.TargetGPSI, t.GPSIMSISDN), nil
	case t.E164Number != "":
		return one(types.TargetGPSI, t.E164Number), nil
	// The plain TS 103 221-1 criteria of table 6.2.3-7. These come after the
	// subscriber identifiers deliberately: a task carrying both is targeting a
	// subscriber, and the subscriber identifier is the one an IRI-POI can act on.
	//
	// That precedence governs a task's `targetIdentifiers` **list**, where a
	// subscriber identifier and a packet criterion are separate, legitimate entries
	// combined as alternatives. It does not govern the arms *within* one
	// targetIdentifier: the schema defines that as an xs:choice, so two populated
	// arms cannot occur, and malformedTaskIdentifiers refuses the message before
	// this is reached rather than letting the order below decide. The two rules are
	// about different levels of the structure — this switch is not what settles a
	// multi-arm message, and reading it as though it were is what left the
	// cardinality unchecked.
	case t.GTPUTunnelID != "":
		return one(types.TargetFTEID, t.GTPUTunnelID), nil
	case t.IPv4Address != "":
		return one(types.TargetUEIPv4, t.IPv4Address), nil
	case t.IPv6Address != "":
		return one(types.TargetUEIPv6, t.IPv6Address), nil
	case t.TCPPort != "":
		return one(types.TargetTCPPort, t.TCPPort), nil
	case t.UDPPort != "":
		return one(types.TargetUDPPort, t.UDPPort), nil
	case t.Extension != nil:
		return mapExtensionTarget(t.Extension)
	}

	return nil, fmt.Errorf("unsupported target identifier")
}

// one is the single-criterion result every plain arm produces.
func one(kind types.TargetIdentifierType, value string) []types.TargetIdentifier {
	return []types.TargetIdentifier{{Type: kind, Value: value}}
}

// mapExtensionTarget maps the 3GPP LI_T3 packet-detection criteria of TS 33.128
// table 6.2.3-7 onto target identifiers. Clause 6.2.3 requires a CC-POI to support
// "at least the identifier types given in table 6.2.3-7", so all of them are
// accepted here: the three plain TS 103 221-1 arms are handled in mapTarget, and
// the seven extension arms in mapUPFLIT3Identifier.
//
// **Every member of the list becomes a criterion.** UPFLIT3TargetIdentifier is a
// SEQUENCE OF CHOICE, so a list of several is exactly what the structure is for,
// and `A task carrying several criteria` already requires a CC-POI to intercept
// traffic matching any of them. This mapped `Identifiers[0]` and dropped the rest,
// which acknowledged a task while running an interception narrower than the one
// ordered — invisible to every party, since the triggering function was told the
// task was accepted and the mediation function receives well-formed product for
// the criterion that survived.
//
// A member that cannot be mapped refuses the **whole task**, which is the rule
// taskFromDetails already applies to the outer list, applied one level deeper
// where it was not. The OR semantics need nothing here: widening the output feeds
// the existing machinery more criteria and does not change how they combine, and
// the no-duplicate-delivery rule is enforced at the shipper.
//
// Accepting a criterion at this layer means it can be *provisioned*. Whether the
// CC-POI can then evaluate it against its own session state is a separate question
// answered further in — and a criterion it cannot evaluate is still refused there
// rather than accepted and ignored.
func mapExtensionTarget(ext *TargetIdentifierExtension) ([]types.TargetIdentifier, error) {
	if ext.UPFT3 == nil || len(ext.UPFT3.Identifiers) == 0 {
		return nil, fmt.Errorf("unsupported target identifier extension")
	}

	out := make([]types.TargetIdentifier, 0, len(ext.UPFT3.Identifiers))
	for i, id := range ext.UPFT3.Identifiers {
		target, err := mapUPFLIT3Identifier(id)
		if err != nil {
			return nil, fmt.Errorf("LI_T3 detection criterion %d of %d: %w", i+1, len(ext.UPFT3.Identifiers), err)
		}
		out = append(out, target)
	}

	return out, nil
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

// malformedTaskIdentifiers returns a refusal when a task's own identifiers do not conform
// to the format the schema defines for them, or nil when they do.
//
// The task's `xId` and the `productID` that replaces it in delivered PDU headers are both
// `etsi103280:UUID`. A malformed one is not cosmetic: `types.XID.Bytes()` maps an
// unparseable value to sixteen zero bytes, an MDF discards product it cannot attribute to
// a warrant, and nothing reports either — so the interception runs and every record is
// delivered under a label the mediation function throws away.
//
// An *absent* xId is left to taskFromDetails, which calls it missing. "Missing" and "not a
// UUID" are different things to be told, and the mandatory-field check already said the
// first one clearly.
func malformedTaskIdentifiers(td TaskDetails) error {
	if td.XID != "" {
		if err := validIdentifier("xId", td.XID); err != nil {
			return err
		}
	}
	if td.ProductID != "" {
		if err := validIdentifier("productID", td.ProductID); err != nil {
			return err
		}
	}
	// The same check the two identifiers above get, for the same reason. A dId the
	// schema cannot type is one no destination can be found under, so the task is
	// accepted and then delivers to nothing — the failure RequireResolvableDIDs
	// exists to prevent, arriving by the one route that skips it. It was this
	// element's own malformed dId that made the case for validating xId at all.
	for _, did := range td.ListOfDIDs {
		if err := validIdentifier("dId", did); err != nil {
			return err
		}
	}
	for _, ti := range td.TargetIdentifiers {
		if n := populatedArms(ti); n > 1 {
			// The schema defines TargetIdentifier as an xs:choice, so a message
			// populating two arms is invalid against it and no reading of it is
			// authoritative. Selecting one would mean the *element* deciding the scope
			// of an interception that the provisioning function ordered.
			//
			// Refused here rather than in unhonourableTaskFields, and the distinction is
			// the one the ordering at the call site already draws: this is a message that
			// violates its own format, not a well-formed task carrying something this
			// element cannot honour. Asking whether we could honour its contents presumes
			// something that has not been established.
			return refuse(errCodeSchemaError,
				"targetIdentifier populates %d arms of a choice; exactly one is valid", n)
		}
		// The same rule one level deeper. UPFLIT3TargetIdentifier is a *sequence of*
		// choices, so several members are valid and several arms of one member are
		// not — and the reason is unchanged: a member with two arms has no
		// authoritative reading, so selecting one narrows or widens an interception by
		// this element's decision rather than the provisioning function's. Checking
		// the outer choice and not this one would have left the same defect at the one
		// level where a CC-POI actually reads its detection criteria.
		if ti.Extension == nil || ti.Extension.UPFT3 == nil {
			continue
		}
		for i, id := range ti.Extension.UPFT3.Identifiers {
			if n := populatedLIT3Arms(id); n > 1 {
				return refuse(errCodeSchemaError,
					"LI_T3 detection criterion %d of %d populates %d arms of a choice; exactly one is valid",
					i+1, len(ti.Extension.UPFT3.Identifiers), n)
			}
		}
	}

	return nil
}

// populatedArms counts how many arms of the TargetIdentifier choice carry a value.
//
// It is deliberately a count over every arm rather than a check of the two that
// mapTarget happens to reach first: the defect being closed is that the switch's
// order decided the answer, so a guard sharing that order would inherit it. A new
// arm added to the struct and not added here would be silently exempt, which is
// the same class of omission — hence one place, listing all of them, beside the
// declaration they mirror.
func populatedArms(t TargetIdentifier) int {
	n := 0
	for _, v := range []string{
		t.IMSI, t.SUPIIMSI, t.SUPINAI,
		t.PEIIMEI, t.PEIIMEISV,
		t.GPSIMSISDN, t.E164Number,
		t.GTPUTunnelID, t.IPv4Address, t.IPv6Address,
		t.TCPPort, t.UDPPort,
	} {
		if v != "" {
			n++
		}
	}
	if t.Extension != nil {
		n++
	}

	return n
}

// populatedLIT3Arms is populatedArms for the inner choice: how many arms of one
// LI_T3 detection criterion carry a value. Listed in full, for the same reason —
// a criterion added to the struct and not added here would be silently exempt.
func populatedLIT3Arms(id UPFLIT3Identifier) int {
	n := 0
	for _, set := range []bool{
		id.FSEID != nil,
		id.PDRID != nil,
		id.QERID != nil,
		id.FTEID != nil,
		id.NetworkInstance != "",
		id.GTPTunnelDirection != "",
		id.PDR != "",
	} {
		if set {
			n++
		}
	}

	return n
}

// unhonourableTaskFields returns a refusal for the first field of td this element can
// neither act on nor safely disregard, or nil when there is none.
//
// The rule it applies, and the reason there is a rule rather than a list: a field the
// element discards silently produces an interception that differs from the one
// authorised, in a way nobody outside the element can discover. The provisioning
// function is acknowledged and has no channel through which the divergence could be
// reported. So the default is refusal, and a field is disregarded only where the
// specification addresses it to a function this element is not, or where disregarding
// it cannot change what is intercepted or where the product goes.
//
// What is deliberately *not* here: listOfMediationDetails and
// implicitDeactivationAllowed, both of which pass. See their declarations for the
// sentences that put them on the other side of the rule.
func unhonourableTaskFields(td TaskDetails) error {
	if len(td.ListOfServiceTypes) > 0 {
		// This element applies no service-type scoping, so honouring the task as sent
		// would intercept every service for the target when a narrower set was
		// authorised — more product than the warrant allows, and silently. TS 33.128
		// prescribes the remedy: an IRI-POI receiving a ServiceType it does not support
		// "shall reject the task with an appropriate error".
		//
		// The code was the generic "unsupported request" while the TS 103 221-1 error
		// registry — which is in that document's text, not its schema — had not been
		// read, with a note to substitute a better value once confirmed rather than
		// invent one. Table 6.7-3 has an entry for exactly this.
		return refuse(errCodeBadServiceType, "service-type scoping is not supported")
	}
	if len(td.ListOfTrafficPolicyReferences) > 0 {
		// "Ordered list  of TrafficPolicyReferences to be applied to the LITaskObject",
		// defined in TS 103 120 clause 8.2.13. It is an instruction about the task, and
		// this project implements no TS 103 120 traffic policies — so an accepted task
		// would run without the policy that was meant to shape it.
		return fmt.Errorf("listOfTrafficPolicyReferences is not supported")
	}
	if len(td.DSIDs) > 0 {
		// A dSId names a destination *set*, which annex E defines as a Generic Object:
		// the ADMF creates a DestinationSetDetails object and then references its
		// object id here. This element implements no Generic Objects — it refuses the
		// object CRUD outright — so a dSId can never name anything it holds.
		//
		// Refused whenever one is present, not only when the task names nothing else.
		// A task naming a dId *and* a dSId has still expressed an intent this element
		// would discard, and sets carry real semantics to discard: "Redundant" with a
		// preference order and failover, or "Duplicate", where "the NE will send copies
		// of intercepted traffic to all DIDs within the Destination Set".
		return fmt.Errorf("destination sets (dSId) are not supported")
	}
	if err := unhonourableExtensions(td.TaskDetailsExtensions, "task"); err != nil {
		return err
	}

	return nil
}

// unhonourableExtensions applies the same rule to an extension placeholder, on a task or
// on a destination.
//
// The instinct with an unknown extension is to ignore it. On this interface that is
// backwards: an extension exists in order to change the meaning of the message carrying
// it — the LI_T3 detection criteria arrive through exactly such a placeholder — so the
// test is on the owner and the content, not on presence.
func unhonourableExtensions(exts []MessageExtension, on string) error {
	for _, ext := range exts {
		if ext.Owner != ExtensionOwner3GPP {
			return fmt.Errorf("%s extension owned by %q is not supported", on, ext.Owner)
		}
		if ext.IdentifierAssociation == nil || len(ext.Content) > 0 {
			return fmt.Errorf("3GPP %s extension %s is not supported", on, extensionContentNames(ext))
		}
		// Only the AMF IRI-POI is given this extension, and only 33.128 table 6.2.2.1-1
		// defines it, but it is accepted at every element this package serves: an SMF
		// or UPF that refused it would refuse a task an ADMF may legitimately send to
		// several elements at once, and an element that produces no
		// identifier-association records loses nothing by being told which to produce.
		switch ext.IdentifierAssociation.EventsGenerated {
		case string(types.RecordScopeIdentifierAssociation), string(types.RecordScopeAll):
		default:
			// A closed enumeration. Defaulting would either withhold records the
			// warrant authorises or produce records it does not, and the element could
			// not tell which it had done.
			return fmt.Errorf("IdentifierAssociationEventsGenerated %q is not one of the enumerated values",
				ext.IdentifierAssociation.EventsGenerated)
		}
	}

	return nil
}

// extensionContentNames lists the element names an extension carried, so a refusal says
// what was sent. Empty content is named as such rather than as nothing, since an
// extension with an Owner and no content is its own kind of malformed.
func extensionContentNames(ext MessageExtension) string {
	if ext.IdentifierAssociation != nil {
		// A recognised element alongside unmodelled ones: name them all, since it is
		// the combination that is not supported.
		names := []string{"IdentifierAssociationExtensions"}
		for _, item := range ext.Content {
			names = append(names, item.XMLName.Local)
		}

		return strings.Join(names, ", ")
	}
	if len(ext.Content) == 0 {
		return "(no content)"
	}

	names := make([]string, 0, len(ext.Content))
	for _, item := range ext.Content {
		names = append(names, item.XMLName.Local)
	}

	return strings.Join(names, ", ")
}

// recordScope reads the per-task record scoping out of a task's extensions. A task
// carrying none is RecordScopeStandard, which is what TS 33.128 clause 6.2.2.2.1 means
// by the identifier-association records not being generated.
//
// It runs after unhonourableTaskFields has passed, so an extension present here is one
// with a 3GPP owner, recognised content and an enumerated value.
func recordScope(td TaskDetails) types.RecordScope {
	for _, ext := range td.TaskDetailsExtensions {
		if ext.IdentifierAssociation != nil {
			return types.RecordScope(ext.IdentifierAssociation.EventsGenerated)
		}
	}

	return types.RecordScopeStandard
}

// taskFailureCode is the registry's "generic ActivateTask/ModifyTask failure", whose
// suggested content is the reason the task cannot be applied. More specific than 1000,
// which says only that something went wrong.
func taskFailureCode(isModify bool) int {
	if isModify {
		return errCodeModifyFailed
	}

	return errCodeActivateFailed
}

// codedError pairs a refusal with the TS 103 221-1 error code that names it, so a code
// chosen where the reason is known reaches the response instead of being flattened to
// the generic one on the way out. Table 6.7-3 ends "Implementers shall use the most
// specific error code available", and an ADMF acts on the code before it reads the text.
type codedError struct {
	code int
	err  error
}

func (e codedError) Error() string { return e.err.Error() }

// errorCode returns the TS 103 221-1 code an error carries, or 0 when it carries none.
func errorCode(err error) int {
	var c codedError
	if errors.As(err, &c) {
		return c.code
	}

	return 0
}

// refuse builds a refusal carrying a specific code.
func refuse(code int, format string, args ...any) error {
	return codedError{code: code, err: fmt.Errorf(format, args...)}
}

// supportedVersion is the X1 interface version this element speaks, and the value it
// substitutes when a peer's is not one the schema admits.
const supportedVersion = "v1.6.1"

// versionPattern is the schema's Version restriction, `v1\.\d+\.\d+`.
var versionPattern = regexp.MustCompile(`^v1\.\d+\.\d+$`)

// echoVersion and echoTransactionID keep a peer from choosing header values that make
// *our own* answer invalid.
//
// Every response echoes the request's version and x1TransactionId, and the schema
// restricts both — a pattern and a UUID. So a malformed request produced a malformed
// reply, and the reply easiest to spoil is the one whose request has been trusted by
// nothing: the refusal telling a peer it may not task this element. A conformant ADMF
// validating replies discards an invalid one, which would make the most
// security-relevant message this interface sends unreportable, by sending a bad version
// string.
//
// The two fields are not the same trade. Substituting the version costs nothing: it is
// a statement about which interface *we* speak, and a peer that sent something outside
// the pattern has told us nothing to preserve.
func echoVersion(v string) string {
	if versionPattern.MatchString(v) {
		return v
	}

	return supportedVersion
}

// echoTransactionID substitutes a fresh UUID for a transaction identifier outside the
// schema's format.
//
// This one does cost something — an ADMF matches a response to its request by this value
// — so it is worth being explicit about who pays. Only a peer that sent a
// non-conformant identifier is affected, and it has no conformant correlation to lose;
// a conformant ADMF's value is echoed untouched. Set against that, echoing the malformed
// value invalidates the whole response, which loses the correlation *and* everything
// else the message says. A fresh value is chosen rather than a fixed one so that two
// refusals to the same peer stay distinguishable.
func echoTransactionID(id string) string {
	if uuidPattern.MatchString(id) {
		return id
	}

	return newUUID()
}

// uuidPattern is the TS 103 280 UUID: the format the schema restricts an XId, a DId and
// an x1TransactionId to. Lowercase hexadecimal only, and — as published — it does not
// pin the version or variant nibbles, so neither does this.
var uuidPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

// validIdentifier reports whether an identifier conforms to the UUID format the schema
// defines for it. field names the element, so an ADMF can tell which of a message's
// identifiers it got wrong.
//
// Three of them are `etsi103280:UUID`: a destination's `dId`, a task's `xId`, and the
// `productID` that replaces the XID in delivered PDU headers. Only the first was checked
// at first, which left the sharpest case open: `types.XID.Bytes()` maps an unparseable
// XID to sixteen zero bytes, an MDF discards product it cannot attribute to a warrant,
// and nothing reports either — so a task with a malformed `xId` was accepted,
// interception ran, and every record was delivered under a label the mediation function
// throws away. Refusing at the door is the only place that failure is visible.
func validIdentifier(field, value string) error {
	if !uuidPattern.MatchString(value) {
		// The value is the peer's, and this text travels back to it in the refusal, so
		// it is not echoed: an LI provisioning channel is the last place to start
		// reflecting attacker-chosen strings. The ADMF knows what it sent.
		return refuse(errCodeSchemaError,
			"%s is not a UUID as the schema requires", field)
	}

	return nil
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
