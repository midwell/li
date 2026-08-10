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
)

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
	XID        XID
	Target     TargetIdentifier
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
}

// WantsProduct reports whether the task requires the given product type.
func (t InterceptTask) WantsProduct(p ProductType) bool {
	return slices.Contains(t.Products, p)
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
