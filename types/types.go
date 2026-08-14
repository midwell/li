// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

// Package types defines the domain model shared across the Lawful Interception
// Points of Interception (POIs) and X-interfaces: the target identifiers a
// warrant may task, the interception task received over X1, and the delivery
// destinations for intercept product. These types are transport- and
// encoding-agnostic; the X1/X2/X3 wire formats live in their own packages.
package types

import (
	"encoding/hex"
	"slices"
	"strings"
)

// TargetIdentifierType enumerates the 5G identifiers a warrant may target.
type TargetIdentifierType string

const (
	// TargetSUPI is the Subscription Permanent Identifier (IMSI-derived). It is
	// known to the AMF only after primary authentication completes.
	TargetSUPI TargetIdentifierType = "SUPI"
	// TargetPEI is the Permanent Equipment Identifier (IMEI-derived).
	TargetPEI TargetIdentifierType = "PEI"
	// TargetGPSI is the Generic Public Subscription Identifier (e.g. MSISDN).
	TargetGPSI TargetIdentifierType = "GPSI"
	// TargetFSEID is a PFCP session (F-SEID), the packet-detection criterion a
	// CC Triggering Function gives a triggered CC-POI so it can isolate a
	// session's traffic without resolving subscriber identities (TS 33.128
	// table 6.2.3-7, "PFCP Session ID"). Value is the SEID in decimal. Unlike
	// the identifiers above this one names a session, not a subscriber, and is
	// only meaningful within the UPF that allocated it.
	TargetFSEID TargetIdentifierType = "FSEID"

	// The remaining packet-detection criteria of TS 33.128 table 6.2.3-7. Like
	// TargetFSEID these name traffic rather than a subscriber, and are only
	// meaningful within the UPF whose session state defines them. Clause 6.2.3
	// requires a CC-POI to support at least all of them.
	//
	// TargetFTEID is a GTP tunnel endpoint, carried in the ETSI gtpuTunnelId
	// identifier. That element is a plain integer in the schema, so the criterion
	// is the TEID alone with no address beside it: matching it against a session
	// therefore compares the TEID and cannot distinguish two tunnels that share
	// one. Value is the TEID in decimal.
	TargetFTEID TargetIdentifierType = "FTEID"
	// TargetUEIPv4 and TargetUEIPv6 are the subscriber's own address, so they
	// select that subscriber's session rather than a rule within it. Value is the
	// address in its textual form.
	TargetUEIPv4 TargetIdentifierType = "UEIPv4"
	TargetUEIPv6 TargetIdentifierType = "UEIPv6"
	// TargetTCPPort and TargetUDPPort narrow to a transport port. Value is the
	// port in decimal. These are finer than a PDU session, so whether they can be
	// applied by duplication alone depends on the rules the SMF installed.
	TargetTCPPort TargetIdentifierType = "TCPPort"
	TargetUDPPort TargetIdentifierType = "UDPPort"
	// TargetPDRID and TargetQERID name a rule inside a session by its identifier.
	// Value is the identifier in decimal. Both are scoped to a PFCP session, so a
	// criterion using one is only unambiguous alongside the session it belongs to.
	TargetPDRID TargetIdentifierType = "PDRID"
	TargetQERID TargetIdentifierType = "QERID"
	// TargetNetworkInstance selects every session on a network instance (a DNN, in
	// practice), so it is the one criterion broader than a session. The schema types
	// it as xs:hexBinary, so the value is those octets hex-encoded, not a name.
	TargetNetworkInstance TargetIdentifierType = "NetworkInstance"
	// TargetGTPTunnelDirection narrows to one direction. Value is the schema's
	// enumeration — "Outbound" or "Inbound", not the uplink/downlink vocabulary used
	// elsewhere in 3GPP — and is compared as given.
	TargetGTPTunnelDirection TargetIdentifierType = "GTPTunnelDirection"
	// TargetPDR carries a whole packet detection rule, encoded per TS 29.244
	// table 7.5.2.2-1 with the first four octets omitted. Value is that octet
	// string, hex-encoded; it is the only criterion whose comparison semantics
	// against a session's own rules are not yet settled.
	TargetPDR TargetIdentifierType = "PDR"
)

// IsPacketCriterion reports whether a target identifier names traffic rather than
// a subscriber. Only the traffic-naming ones may appear on LI_T3, and only they
// require session state to evaluate — the distinction the CC-POI's resolver and
// the IRI-POIs' target matching both depend on.
func (t TargetIdentifierType) IsPacketCriterion() bool {
	switch t {
	case TargetFSEID, TargetFTEID, TargetUEIPv4, TargetUEIPv6,
		TargetTCPPort, TargetUDPPort, TargetPDRID, TargetQERID,
		TargetNetworkInstance, TargetGTPTunnelDirection, TargetPDR:
		return true
	default:
		return false
	}
}

// TargetIdentifier identifies the subject of an interception task.
type TargetIdentifier struct {
	Type  TargetIdentifierType
	Value string
}

// XID is the X1 task identifier (warrant reference) assigned by the ADMF. It is
// carried in every xIRI/xCC record so the MDF can correlate product to a warrant.
type XID string

// Bytes converts the XID — a UUID string on X1 — to the 16-byte form carried in
// the X2/X3 PDU header (TS 103 221-2 clause 5.2.7). An unparseable value yields
// the zero XID, which is what an MDF treats as unattributable, so callers that
// must not deliver unattributable product check the result rather than assuming
// it.
func (x XID) Bytes() [16]byte {
	var out [16]byte

	b, err := hex.DecodeString(strings.ReplaceAll(string(x), "-", ""))
	if err == nil && len(b) == len(out) {
		copy(out[:], b)
	}

	return out
}

// IsZero reports whether the XID converts to the all-zero PDU header field, i.e.
// whether product labelled with it could be attributed to a warrant at all.
func (x XID) IsZero() bool {
	return x.Bytes() == [16]byte{}
}

// ProductType is the kind of intercept product a task requires.
type ProductType string

const (
	// ProductIRI is Intercept Related Information (signalling metadata) — delivered over X2.
	ProductIRI ProductType = "IRI"
	// ProductCC is Content of Communication (user-plane packets) — delivered over X3.
	ProductCC ProductType = "CC"
)

// DeliveryType distinguishes the X2 (IRI→MDF2) and X3 (CC→MDF3) destinations.
type DeliveryType string

const (
	DeliveryX2 DeliveryType = "X2"
	DeliveryX3 DeliveryType = "X3"
)

// DeliveryEndpoint is a destination an MDF exposes for intercept product.
type DeliveryEndpoint struct {
	Type    DeliveryType
	Address string // host:port of the MDF (X2 → MDF2, X3 → MDF3)
}

// TaskState is the lifecycle state of an interception task.
type TaskState string

const (
	TaskActive   TaskState = "active"
	TaskInactive TaskState = "inactive"
)

// InterceptTask is an interception task provisioned over X1 by the ADMF/LIPF.
// A network function evaluates events and traffic against its active tasks and
// produces the requested product to the matching delivery endpoints.
type InterceptTask struct {
	XID XID
	// Targets are the identifiers this task intercepts on, and they are
	// *alternatives*: traffic or signalling matching any one of them belongs to the
	// task. That is the ETSI list semantics — each entry in a task's
	// targetIdentifiers is another way to identify the same target — and it is why
	// this is a list rather than one identifier even though an ADMF tasking an
	// IRI-POI by subscriber identity supplies exactly one.
	//
	// A triggering function needing traffic that matches a *combination* of
	// properties cannot express it here; it must send a single criterion that
	// already carries the combination.
	Targets []TargetIdentifier
	// DIDs are the destination identifiers the task named, kept as given. They were
	// previously resolved to endpoints and then discarded, which lost two things the
	// interface needs: the identifiers a reported task has to carry back, and the ability to
	// answer whether a destination is still referenced — the guard the specification puts on
	// removing destinations in bulk.
	DIDs       []string
	Products   []ProductType      // IRI and/or CC
	Deliveries []DeliveryEndpoint // X2 and/or X3 destinations
	State      TaskState
	// ProductID, when set, replaces XID in the X2/X3 PDU header. It is how a
	// triggered POI labels its product with the *warrant* rather than with the
	// trigger task it was given: a Triggering Function allocates its own XID for
	// the trigger and passes the warrant XID here (TS 103 221-1 clause 6.2.1.2;
	// TS 33.128 table 6.2.3-6 makes it mandatory for LI_T3). Use DeliveryXID
	// rather than reading this directly.
	ProductID XID
	// CorrelationID is the value a triggered POI must place in the correlation
	// field of every PDU it delivers for this task, so the MDF can join content
	// to the signalling the triggering POI reported for the same session. Zero
	// means unset. Supplied by the Triggering Function, never derived locally —
	// deriving it independently on each side is how the two streams drift apart.
	CorrelationID uint64
	// RecordScope selects which xIRI record types this task's IRI-POI produces. It
	// comes from the 3GPP IdentifierAssociationExtensions the ADMF may put in the
	// task's TaskDetailsExtensions; the zero value is the scope of a task carrying
	// none. See RecordScope.
	RecordScope RecordScope
}

// RecordScope is the per-task scoping TS 33.128 clause 6.2.2.2.1 puts on the AMF
// IRI-POI's records: "The IRI-POI in the AMF shall only generate xIRI containing
// AMFIdentifierAssociation and AMFIdentifierDeassociation records when the
// IdentifierAssocationExtensions parameter has been received over LI_X1".
//
// It is a property of the task rather than of the element, because two warrants on one
// AMF may ask for different record sets.
type RecordScope string

const (
	// RecordScopeStandard is the scope of a task carrying no such extension: every
	// record type except the identifier-association pair, which per table 6.2.2.1-1
	// "shall not be generated" unless the extension asks for it.
	RecordScopeStandard RecordScope = ""
	// RecordScopeIdentifierAssociation is EventsGenerated "IdentifierAssociation":
	// "AMFIdentifierAssociation, AMFIdentifierDeassociation and AMFLocationUpdate
	// records shall be generated. No other record types shall be generated for that
	// target." It is the one scope that produces *less* than the default.
	RecordScopeIdentifierAssociation RecordScope = "IdentifierAssociation"
	// RecordScopeAll is EventsGenerated "All": "All AMF record types shall be
	// generated."
	RecordScopeAll RecordScope = "All"
)

// WantsIdentifierAssociation reports whether this task's IRI-POI is to produce
// AMFIdentifierAssociation and AMFIdentifierDeassociation records. Only a task that
// asked for them by extension gets them.
func (t InterceptTask) WantsIdentifierAssociation() bool {
	return t.RecordScope != RecordScopeStandard
}

// WantsGeneralRecords reports whether this task's IRI-POI is to produce the record
// types outside the identifier-association pair and AMFLocationUpdate — registration,
// deregistration, unsuccessful procedures, start of interception. A task scoped to
// IdentifierAssociation is the one case that wants none of them.
func (t InterceptTask) WantsGeneralRecords() bool {
	return t.RecordScope != RecordScopeIdentifierAssociation
}

// TargetsAny reports whether any of the task's identifiers is among ids — the
// identifiers of some entity the caller holds (a subscriber's identities, a
// session's criteria). It is the disjunction Targets documents, in one place so
// that each POI does not re-derive it.
func (t InterceptTask) TargetsAny(ids []TargetIdentifier) bool {
	for _, want := range t.Targets {
		for _, have := range ids {
			if want == have {
				return true
			}
		}
	}

	return false
}

// SplitTargets divides the identities a network function holds for one subject into
// the ones this task matched and the rest, which is the distinction ETSI
// TS 103 221-2 clauses 5.3.18 and 5.3.19 draw between the Matched and Other Target
// Identifier attributes an xIRI carries.
//
// It is TargetsAny's witness-returning sibling and lives beside it for the same
// reason: the rule belongs in one place rather than being re-derived by each POI.
// Every match is returned, not the first — where a task names both a SUPI and a PEI
// that the network function holds, both did match, and picking one to report as *the*
// match would be an arbitrary claim. Clause 5.3.18 permits multiple occurrences
// precisely so it need not be made.
//
// "Other" is the rest of this subject's identities, never another subscriber's: the
// literal reading of TS 33.128's "all other target identities present at the NF"
// would disclose unrelated subscribers to an agency holding a warrant for one.
func (t InterceptTask) SplitTargets(ids []TargetIdentifier) (matched, other []TargetIdentifier) {
	for _, have := range ids {
		if slices.Contains(t.Targets, have) {
			matched = append(matched, have)
		} else {
			other = append(other, have)
		}
	}

	return matched, other
}

// XMLFragments renders each identifier in the clause 5.3.18 form, dropping any this
// package cannot render rather than substituting something else — see XMLFragment.
func XMLFragments(ids []TargetIdentifier) []string {
	var out []string
	for _, id := range ids {
		if frag, ok := id.XMLFragment(); ok {
			out = append(out, frag)
		}
	}

	return out
}

// WantsProduct reports whether the task requires the given product type.
func (t InterceptTask) WantsProduct(p ProductType) bool {
	return slices.Contains(t.Products, p)
}

// DeliveryAddresses returns the addresses this task's product of type dt goes to: the
// destinations the task named and the element could resolve, in the order the task named
// them.
//
// Duplicates are removed. Two DIDs may name one endpoint — an X2andX3 destination
// referenced alongside an X2Only one at the same address, say — and an MDF receiving the
// same record twice under one warrant has no way to tell a duplicate from a repeat.
//
// An empty result is a task this element cannot deliver for from its own tasking alone.
// What a POI does then is the POI's decision: an IRI-POI may fall back to a configured
// endpoint, while a triggered CC-POI refuses the task instead.
func (t InterceptTask) DeliveryAddresses(dt DeliveryType) []string {
	var out []string
	for _, d := range t.Deliveries {
		if d.Type != dt || d.Address == "" || slices.Contains(out, d.Address) {
			continue
		}
		out = append(out, d.Address)
	}

	return out
}

// DeliveryXID returns the XID to put in the X2/X3 PDU header for this task: the
// ProductID when one was provisioned, otherwise the task's own XID (TS 103 221-1
// clause 6.2.1.2). Every X2/X3 sender must label product through this method —
// an MDF attributes a PDU to an intercept by its XID alone, so a POI that labels
// product with a trigger's XID, or with nothing, produces material the MDF
// cannot attribute and discards without complaint.
func (t InterceptTask) DeliveryXID() XID {
	if t.ProductID != "" {
		return t.ProductID
	}
	return t.XID
}
