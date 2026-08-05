// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

// Package x1 implements the network-element (POI) side of the ETSI TS 103 221-1
// X1 interface: it receives task-provisioning requests from an ADMF/LIPF over
// HTTP (XML bodies) and applies them to the interception-task store. The NF is
// the X1 server; the ADMF is the client. Transport security (mutual TLS, X0
// credential pre-provisioning) is layered on separately.
package x1

import "encoding/xml"

// Namespace is the ETSI TS 103 221-1 X1 XML namespace. The message-type
// discriminator rides on the xsi:type attribute (XML-Schema-instance namespace).
const Namespace = "http://uri.etsi.org/03221/X1/2017/10"

// X1Request is the top-level X1 request envelope. It may carry one or more
// messages (TS 103 221-1 allows a batch); the common case is a single message.
type X1Request struct {
	XMLName  xml.Name           `xml:"http://uri.etsi.org/03221/X1/2017/10 X1Request"`
	Messages []X1RequestMessage `xml:"x1RequestMessage"`
}

// X1RequestMessage is one request. The xsi:type attribute selects the action
// (ActivateTaskRequest, ModifyTaskRequest, DeactivateTaskRequest, …); the
// action-specific payload is carried in TaskDetails (activate/modify) or XID
// (deactivate). The header fields are common to every message type.
type X1RequestMessage struct {
	Type             string       `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
	AdmfIdentifier   string       `xml:"admfIdentifier"`
	NeIdentifier     string       `xml:"neIdentifier"`
	MessageTimestamp string       `xml:"messageTimestamp"`
	Version          string       `xml:"version"`
	X1TransactionID  string       `xml:"x1TransactionId"`
	TaskDetails      *TaskDetails `xml:"taskDetails,omitempty"` // ActivateTask / ModifyTask
	XID              string       `xml:"xId,omitempty"`         // DeactivateTask
}

// TaskDetails describes the interception task being (de)provisioned. Field order
// follows the TS_103_221_01.xsd xs:sequence, which is normative for the wire
// form; CorrelationID and ProductID sit where the schema puts them (after
// listOfDIDs, either side of implicitDeactivationAllowed). Note the schema spells
// these two "correlationID"/"productID", not the "xId"/"dId" pattern used by its
// other fields.
type TaskDetails struct {
	XID               string             `xml:"xId"`
	TargetIdentifiers []TargetIdentifier `xml:"targetIdentifiers>targetIdentifier"`
	DeliveryType      string             `xml:"deliveryType"` // X2Only | X3Only | X2andX3
	ListOfDIDs        []string           `xml:"listOfDIDs>dId"`
	CorrelationID     string             `xml:"correlationID,omitempty"` // xs:nonNegativeInteger
	ProductID         string             `xml:"productID,omitempty"`     // UUIDv4; overrides XID in X2/X3 headers
}

// TargetIdentifier is a CHOICE of target-identifier kinds. Only the subset the
// 5G POIs match on is modeled; the rest of the TS 103 221-1 set is unmodeled
// (an unknown identifier yields an empty match and is rejected).
type TargetIdentifier struct {
	IMSI       string `xml:"imsi,omitempty"`
	SUPIIMSI   string `xml:"supiimsi,omitempty"`
	SUPINAI    string `xml:"supinai,omitempty"`
	PEIIMEI    string `xml:"peiImei,omitempty"`
	PEIIMEISV  string `xml:"peiImeisv,omitempty"`
	GPSIMSISDN string `xml:"gpsiMsisdn,omitempty"`
	E164Number string `xml:"e164Number,omitempty"`
	// Extension carries identifier types defined outside TS 103 221-1. The only
	// one modeled is the 3GPP LI_T3 packet-detection criteria a CC Triggering
	// Function sends a triggered CC-POI.
	Extension *TargetIdentifierExtension `xml:"targetIdentifierExtension,omitempty"`
}

// ExtensionOwner3GPP is the Extension/Owner value for identifier types 3GPP
// defines (TS 103 221-1 annex B; TS 33.128 table 6.2.3-7 "Owner" column).
const ExtensionOwner3GPP = "3GPP"

// NamespaceX1Ext3GPP is the namespace of the 3GPP X1 extension schema
// (urn_3GPP_ns_li_3GPPX1Extensions.xsd, shipped with TS 33.128). It is
// elementFormDefault="qualified", so its child elements are namespace-qualified
// on the wire — unlike the ETSI X1 body around them.
const NamespaceX1Ext3GPP = "urn:3GPP:ns:li:3GPPX1Extensions:r18:v6"

// TargetIdentifierExtension is the TS 103 221-1 Extension placeholder: an Owner
// naming the specification that defines the content, then that content.
type TargetIdentifierExtension struct {
	Owner string             `xml:"Owner"`
	UPFT3 *UPFLIT3Extensions `xml:"urn:3GPP:ns:li:3GPPX1Extensions:r18:v6 UPFLIT3TargetIdentifierExtensions,omitempty"`
}

// UPFLIT3Extensions holds the LI_T3 packet-detection criteria for a triggered
// CC-POI in a UPF. The schema allows several; we send and match on one.
type UPFLIT3Extensions struct {
	Identifiers []UPFLIT3Identifier `xml:"urn:3GPP:ns:li:3GPPX1Extensions:r18:v6 UPFLIT3TargetIdentifier"`
}

// UPFLIT3Identifier is a CHOICE over the criteria of TS 33.128 table 6.2.3-7.
// Only FSEID is modeled: it is the criterion the BESS datapath already tags onto
// duplicated packets, so it is the one the CC-POI can actually match. The others
// (PDRID, QERID, NetworkInstance, GTPTunnelDirection, FTEID, PDR) are defined by
// the schema and deliberately unimplemented — a trigger carrying one is rejected
// rather than silently treated as a match-all.
type UPFLIT3Identifier struct {
	FSEID *FSEID `xml:"urn:3GPP:ns:li:3GPPX1Extensions:r18:v6 FSEID,omitempty"`
}

// FSEID is a PFCP session identifier: the SEID plus the address of the node that
// allocated it. Within one UPF the SEID alone is unambiguous, so the addresses
// are informational for matching purposes.
type FSEID struct {
	SEID        uint64 `xml:"urn:3GPP:ns:li:3GPPX1Extensions:r18:v6 SEID"`
	IPv4Address string `xml:"urn:3GPP:ns:li:3GPPX1Extensions:r18:v6 IPv4Address,omitempty"`
	IPv6Address string `xml:"urn:3GPP:ns:li:3GPPX1Extensions:r18:v6 IPv6Address,omitempty"`
}

// X1Response is the top-level X1 response envelope.
type X1Response struct {
	XMLName  xml.Name            `xml:"http://uri.etsi.org/03221/X1/2017/10 X1Response"`
	Messages []X1ResponseMessage `xml:"x1ResponseMessage"`
}

// X1ResponseMessage acknowledges one request message.
type X1ResponseMessage struct {
	Type             string   `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
	AdmfIdentifier   string   `xml:"admfIdentifier"`
	NeIdentifier     string   `xml:"neIdentifier"`
	MessageTimestamp string   `xml:"messageTimestamp"`
	Version          string   `xml:"version"`
	X1TransactionID  string   `xml:"x1TransactionId"`
	OK               string   `xml:"oK,omitempty"`
	ErrorInformation *X1Error `xml:"errorInformation,omitempty"`
}

// X1Error carries an error response (subset).
type X1Error struct {
	ErrorCode        int    `xml:"errorCode"`
	ErrorDescription string `xml:"errorDescription"`
}
