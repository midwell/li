// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

// Package x1 implements the network-element (POI) side of the ETSI TS 103 221-1
// X1 interface: it receives task-provisioning requests from an ADMF/LIPF over
// HTTP (XML bodies) and applies them to the interception-task store. The NF is
// the X1 server; the ADMF is the client. Transport security (mutual TLS, X0
// credential pre-provisioning) is layered on separately.
package x1

import (
	"encoding/xml"

	"github.com/omec-project/li/types"
)

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
	// DestinationDetails carries a delivery destination being provisioned
	// (CreateDestination). A task references destinations by DID, so they must be
	// installed before the first task that names them.
	DestinationDetails *DestinationDetails `xml:"destinationDetails,omitempty"`
	// DID is a bare destination identifier, as GetDestinationDetails and
	// RemoveDestination carry it — distinct from the DID inside DestinationDetails,
	// which is part of a destination being provisioned.
	DID string `xml:"dId,omitempty"`
}

// DestinationDetails is a delivery destination (TS 103 221-1 clause 6.3.1.2).
// Field order follows its xs:sequence.
type DestinationDetails struct {
	DID          string          `xml:"dId"`
	FriendlyName string          `xml:"friendlyName,omitempty"`
	DeliveryType string          `xml:"deliveryType"`
	Address      DeliveryAddress `xml:"deliveryAddress"`
}

// DeliveryAddress is a CHOICE of address forms. Only ipAddressAndPort is
// modeled — the X2/X3 senders deliver to a host and port — so a destination
// given as a URI, E.164 number or email address is rejected rather than
// silently accepted and never delivered to.
type DeliveryAddress struct {
	IPAddressAndPort *IPAddressPort `xml:"ipAddressAndPort,omitempty"`
}

// IPAddressPort is the TS 103 280 address-and-port structure. Its namespace is
// elementFormDefault="qualified", hence the qualified child names.
type IPAddressPort struct {
	Address IPAddress `xml:"http://uri.etsi.org/03280/common/2017/07 address"`
	Port    uint16    `xml:"http://uri.etsi.org/03280/common/2017/07 port"`
}

// IPAddress is a CHOICE of IPv4 and IPv6 literal.
type IPAddress struct {
	IPv4 string `xml:"http://uri.etsi.org/03280/common/2017/07 IPv4Address,omitempty"`
	IPv6 string `xml:"http://uri.etsi.org/03280/common/2017/07 IPv6Address,omitempty"`
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
	// ListOfServiceTypes narrows a task to particular CSP service types. Bound so
	// that it can be *refused*: encoding/xml drops elements a struct does not
	// declare, so leaving it out meant an instruction to intercept less was
	// silently discarded and everything delivered instead. Element names per
	// TS_103_221_01.xsd (listOfServiceTypes containing serviceType).
	ListOfServiceTypes []string `xml:"listOfServiceTypes>serviceType,omitempty"`
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
	// The plain TS 103 221-1 arms that TS 33.128 table 6.2.3-7 lists as LI_T3
	// packet-detection criteria. Element names are the schema's, which are
	// lowercase-initial — the table names the *types* (IPv4Address, TCPPort), not
	// these elements, so they are not interchangeable.
	//
	// GTPUTunnelID is an integer in the schema (GtpTunnelId is an xs:integer, not a
	// structure), so it carries a TEID with no address alongside it.
	GTPUTunnelID string `xml:"gtpuTunnelId,omitempty"`
	IPv4Address  string `xml:"ipv4Address,omitempty"`
	IPv6Address  string `xml:"ipv6Address,omitempty"`
	TCPPort      string `xml:"tcpPort,omitempty"`
	UDPPort      string `xml:"udpPort,omitempty"`
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

// UPFLIT3Identifier is a CHOICE over the extension criteria of TS 33.128 table
// 6.2.3-7. All seven arms the schema defines are modeled. Note that NetworkInstance
// and PDR are xs:hexBinary rather than strings, and that FTEID here may carry an
// address beside the TEID — unlike the plain gtpuTunnelId identifier, which the
// schema types as a bare integer.
type UPFLIT3Identifier struct {
	FSEID              *FSEID  `xml:"urn:3GPP:ns:li:3GPPX1Extensions:r18:v6 FSEID,omitempty"`
	PDRID              *uint32 `xml:"urn:3GPP:ns:li:3GPPX1Extensions:r18:v6 PDRID,omitempty"`
	QERID              *uint32 `xml:"urn:3GPP:ns:li:3GPPX1Extensions:r18:v6 QERID,omitempty"`
	NetworkInstance    string  `xml:"urn:3GPP:ns:li:3GPPX1Extensions:r18:v6 NetworkInstance,omitempty"`
	GTPTunnelDirection string  `xml:"urn:3GPP:ns:li:3GPPX1Extensions:r18:v6 GTPTunnelDirection,omitempty"`
	FTEID              *FTEID  `xml:"urn:3GPP:ns:li:3GPPX1Extensions:r18:v6 FTEID,omitempty"`
	PDR                string  `xml:"urn:3GPP:ns:li:3GPPX1Extensions:r18:v6 PDR,omitempty"`
}

// FTEID is a GTP tunnel endpoint: the TEID, optionally with the address of the node
// that terminates it. The addresses are optional in the schema, so a criterion may
// name a TEID alone — which cannot distinguish two tunnels that share one.
type FTEID struct {
	TEID        uint32 `xml:"urn:3GPP:ns:li:3GPPX1Extensions:r18:v6 TEID"`
	IPv4Address string `xml:"urn:3GPP:ns:li:3GPPX1Extensions:r18:v6 IPv4Address,omitempty"`
	IPv6Address string `xml:"urn:3GPP:ns:li:3GPPX1Extensions:r18:v6 IPv6Address,omitempty"`
}

// GTP tunnel direction is a closed enumeration in the schema — "Outbound" or
// "Inbound", not the uplink/downlink vocabulary used elsewhere in 3GPP. A value
// outside it is refused rather than passed through: an unrecognised direction that
// matched nothing would silently intercept nothing, and one that matched everything
// would collect both directions when one was authorised.
const (
	GTPDirectionOutbound = "Outbound"
	GTPDirectionInbound  = "Inbound"
)

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
	// Tasks carries the answer to a details query on the way *out*: the server
	// renders one taskResponseDetails per task, so a requester can see what this
	// element actually holds rather than what it believes it provisioned.
	Tasks []types.InterceptTask `xml:"-"`
	// TaskResponses is the same information on the way *in*, parsed by a requester
	// reading a reply. The two directions are separate fields because the outgoing
	// form is built from the domain model and the incoming form is whatever the peer
	// sent, which may include tasks this requester knows nothing about — the point
	// of asking.
	TaskResponses []TaskResponseDetails `xml:"taskResponseDetails"`
	// AllTaskResponses is the same, nested, as GetAllDetailsResponse defines it. The two
	// answers put a task in different places — GetTaskDetails directly, GetAllDetails inside
	// listOfTaskResponseDetails — and encoding/xml matches one tag per field, so a requester
	// that bound only the direct form read *zero* tasks from a GetAllDetails reply. Use
	// ReportedTasks rather than either field.
	AllTaskResponses []TaskResponseDetails `xml:"listOfTaskResponseDetails>taskResponseDetails"`
	// RequestType is the type of the request being answered. It is only rendered on an
	// ErrorResponse, where the schema makes requestMessageType mandatory — omitting it made
	// every refusal this element sent invalid.
	RequestType string `xml:"-"`
	// Destinations are the destinations this element holds, for the answers that report
	// them. Carried separately from Tasks for the same reason: the outgoing form is built
	// from what the element holds, not parsed from a peer.
	Destinations []ReportedDestination `xml:"-"`
	// Faults are the element's own unresolved faults, for neStatusDetails. Empty until the
	// element retains what it reports to the ADMF.
	Faults []X1Error `xml:"-"`
}

// ReportedTasks returns the tasks a peer reported, whichever answer carried them.
func (m X1ResponseMessage) ReportedTasks() []TaskResponseDetails {
	if len(m.AllTaskResponses) > 0 {
		return m.AllTaskResponses
	}

	return m.TaskResponses
}

// ReportedDestination is one destination as an element reports it: the identifier the ADMF
// provisioned it under, and where it points.
type ReportedDestination struct {
	DID      string
	Endpoint types.DeliveryEndpoint
}

// TaskResponseDetails is one task as reported by an element (TS 103 221-1
// clause 6.2.5).
type TaskResponseDetails struct {
	TaskDetails TaskDetails `xml:"taskDetails"`
	TaskStatus  string      `xml:"taskStatus"`
}

// X1Error carries an error response (subset).
type X1Error struct {
	ErrorCode        int    `xml:"errorCode"`
	ErrorDescription string `xml:"errorDescription"`
}
