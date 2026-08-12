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
	// Extensions is the destination's own extension placeholder. Bound for the same
	// reason ListOfServiceTypes is: an extension exists to change the meaning of the
	// message carrying it, and encoding/xml discards what a struct does not declare.
	Extensions []MessageExtension `xml:"destinationDetailsExtensions,omitempty"`
}

// MessageExtension is the TS 103 221-1 Extension placeholder as it appears on a task
// or a destination: an Owner naming the specification that defines the content, then
// that content as elements from another namespace.
//
// Content is captured rather than modelled. Nothing here acts on an extension; the
// point of binding it is to be able to *refuse* one, and a refusal needs the owner and
// the names of what was sent, not their meaning.
type MessageExtension struct {
	Owner string `xml:"Owner"`
	// IdentifierAssociation is the one task extension this element acts on. TS 33.128
	// table 6.2.2.1-1 makes it conditional on the AMF IRI-POI's ActivateTask and gives
	// it real force: absent, the identifier-association records "shall not be
	// generated". Refusing every extension would therefore refuse a conformant 3GPP
	// ADMF, which is why the test is on the owner and content rather than on presence.
	IdentifierAssociation *IdentifierAssociationExtension `xml:"urn:3GPP:ns:li:3GPPX1Extensions:r18:v6 IdentifierAssociationExtensions,omitempty"`
	// Content is every other element the extension carries, kept for its name alone:
	// nothing acts on it, and a refusal needs to say what was sent, not what it meant.
	Content []ExtensionItem `xml:",any"`
}

// IdentifierAssociationExtension carries the record scoping of TS 33.128
// clause 6.2.2.2.1. EventsGenerated is a closed enumeration — "IdentifierAssociation"
// or "All" — and a value outside it is refused rather than defaulted: guessing would
// either withhold records a warrant authorises or produce records it does not.
type IdentifierAssociationExtension struct {
	EventsGenerated string `xml:"urn:3GPP:ns:li:3GPPX1Extensions:r18:v6 IdentifierAssociationEventsGenerated"`
}

// ExtensionItem is one element inside an extension, kept for its name alone.
type ExtensionItem struct {
	XMLName xml.Name
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
	Port    Port      `xml:"http://uri.etsi.org/03280/common/2017/07 port"`
}

// Port is the TS 103 280 Port CHOICE: a TCPPort or a UDPPort *child element*, never a
// number in the element's own text.
//
// It was bound as a bare uint16 until a schema validator was pointed at this path, and
// the mistake was two-way — we rendered a destination no peer could validate, and a
// conformant peer's port parsed as zero, so the element would have stored a destination
// pointing nowhere and delivered nothing to it. It went unnoticed because the only peer
// this code has ever spoken to is another copy of itself, sending the same wrong shape.
type Port struct {
	TCPPort *uint16 `xml:"http://uri.etsi.org/03280/common/2017/07 TCPPort,omitempty"`
	UDPPort *uint16 `xml:"http://uri.etsi.org/03280/common/2017/07 UDPPort,omitempty"`
}

// Value returns the port number whichever arm carries it, or 0 when neither does.
// The transport is not distinguished: X2 and X3 are carried over TCP (TS 103 221-2),
// so a UDPPort names the same endpoint this element would dial anyway.
func (p Port) Value() uint16 {
	switch {
	case p.TCPPort != nil:
		return *p.TCPPort
	case p.UDPPort != nil:
		return *p.UDPPort
	default:
		return 0
	}
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
	// DSIDs are destination *set* identifiers, the other arm of listOfDIDs. A set is a
	// Generic Object (annex E: the ADMF creates a DestinationSetDetails object, then
	// names its object id here), and this element implements no Generic Objects — so a
	// dSId can never name anything it holds. Bound in order to refuse a task whose
	// destinations are named only this way; see the refusal in taskFromDetails.
	DSIDs         []string `xml:"listOfDIDs>dSId,omitempty"`
	CorrelationID string   `xml:"correlationID,omitempty"` // xs:nonNegativeInteger
	ProductID     string   `xml:"productID,omitempty"`     // UUIDv4; overrides XID in X2/X3 headers
	// ListOfServiceTypes narrows a task to particular CSP service types. Bound so
	// that it can be *refused*: encoding/xml drops elements a struct does not
	// declare, so leaving it out meant an instruction to intercept less was
	// silently discarded and everything delivered instead. Element names per
	// TS_103_221_01.xsd (listOfServiceTypes containing serviceType).
	ListOfServiceTypes []string `xml:"listOfServiceTypes>serviceType,omitempty"`
	// ListOfMediationDetails is accepted and disregarded, which is what TS 103 221-1
	// asks of a POI. The field is "for use by an NE that is performing mediation (i.e.
	// a mediation and delivery function). This shall be included between the ADMF and
	// the MDF." The AMF, SMF and UPF host POIs, not an MDF, so the details are not
	// addressed to them — and refusing them would refuse a conformant task.
	//
	// Bound all the same, so the disregard is a decision recorded here rather than an
	// element encoding/xml happened to drop.
	ListOfMediationDetails []MediationDetails `xml:"listOfMediationDetails>mediationDetails,omitempty"`
	// ImplicitDeactivationAllowed is likewise accepted and disregarded: "Indication
	// that a Task may implicitly deactivate itself once the NE has determined that it
	// has completed." This element never concludes that a task has completed, so it
	// never self-deactivates and the permission is unused either way. An ADMF setting
	// it will not receive the ReportTaskIssue the field implies — a missing feature,
	// not a divergence in what is intercepted.
	//
	// A pointer so that "absent" and "present and false" stay distinguishable, which
	// the drift audit needs even though the behaviour does not.
	ImplicitDeactivationAllowed *bool `xml:"implicitDeactivationAllowed,omitempty"`
	// TaskDetailsExtensions is refused unless recognised. An extension exists in order
	// to change the meaning of the message that carries it — the LI_T3 detection
	// criteria arrive through exactly such a placeholder — so ignoring an unknown one
	// is the opposite of safe.
	TaskDetailsExtensions []MessageExtension `xml:"taskDetailsExtensions,omitempty"`
	// ListOfTrafficPolicyReferences is refused. It is an "Ordered list  of
	// TrafficPolicyReferences to be applied to the LITaskObject", defined in
	// TS 103 120 clause 8.2.13, which this project does not implement. A policy that
	// is meant to shape what a task collects, silently unapplied, is the
	// listOfServiceTypes defect a second time.
	ListOfTrafficPolicyReferences []string `xml:"listOfTrafficPolicyReferences>trafficPolicyReference,omitempty"`
}

// MediationDetails is one entry of listOfMediationDetails. Only enough of its
// xs:sequence is bound to show that the element was seen and disregarded on purpose:
// nothing here reads these values, because the structure is addressed to a mediation
// function and this element is not one.
type MediationDetails struct {
	LIID         string `xml:"LIID"`
	DeliveryType string `xml:"deliveryType"`
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
	// Faults are the element's own unresolved faults, for neStatusDetails: the conditions a
	// registered probe says hold at the moment the status was asked for, never a history.
	Faults []X1Error `xml:"-"`
}

// ReportedTasks returns the tasks a peer reported, whichever answer carried them.
func (m X1ResponseMessage) ReportedTasks() []TaskResponseDetails {
	if len(m.AllTaskResponses) > 0 {
		return m.AllTaskResponses
	}

	return m.TaskResponses
}

// ReportedDestination is one destination as an element reports it: the identifier it is
// held under, where it points, and how this element came to know it.
type ReportedDestination struct {
	DID string
	// DeliveryType is the X1 value the destination was declared with — X2Only, X3Only
	// or X2andX3. It is kept rather than derived from an endpoint type, because one
	// destination serving both interfaces is one record and two endpoints.
	DeliveryType string
	Address      string // "host:port"
	FriendlyName string // the ADMF's own name for it, where one was given
	// Configured marks an entry this element's configuration declares rather than one
	// provisioned with CreateDestination.
	Configured bool
	// ShadowsConfigured marks a provisioned entry that supersedes a configured one for
	// the same DID. Provisioned wins, which is the right precedence and the wrong kind
	// of silence: an operator whose configured entry is not the one in force has to be
	// able to see that from what the element reports.
	ShadowsConfigured bool
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
