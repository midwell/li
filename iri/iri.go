// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

// Package iri builds and encodes 3GPP TS 33.128 xIRI records — the Intercept
// Related Information payload carried in an X2 PDU (payload format 3GPP-33.128).
//
// The records are defined in the TS33128Payloads ASN.1 module
// (DEFINITIONS IMPLICIT TAGS), encoded with BER/DER. We hand-write only the
// subset of records the AMF/SMF POIs actually emit and encode them with the
// bundled li/asn1 codec (BER + CHOICE; vendored from PromonLogicalis), mirroring SD-Core's house pattern of
// typed structs + a reflective tag codec (cf. omec ngapType + aper, which are
// PER and therefore not reusable for 33.128's BER).
//
// This is the first vertical slice: the XIRIPayload wrapper and the
// AMFRegistration event (mandatory fields plus the PEI/GPSI target-identifier
// optionals). Remaining records and optional fields follow the same patterns.
package iri

import (
	"fmt"
	"net"
	"reflect"

	"github.com/omec-project/li/asn1"
)

// xIRIPayloadOID is the fixed RELATIVE-OID identifying an xIRI payload for
// TS 33.128 r18 v15: {threeGPP(4) ts33128(19) r18(18) version15(15) xIRI(1)}.
// All arcs are < 128, so the RELATIVE-OID content is one byte per arc. It is
// carried in the [1] IMPLICIT field of XIRIPayload, where the implicit context
// tag replaces the universal RELATIVE-OID tag, so the bytes on the wire are
// exactly this content.
var xIRIPayloadOID = []byte{0x04, 0x13, 0x12, 0x0F, 0x01}

// Target-identifier leaf types. They are distinct Go types (not bare strings)
// so the CHOICE codec can tell the alternatives apart by reflect.Type.
type (
	IMSI   string // NumericString(6..15)
	NAI    string // UTF8String
	IMEI   string // NumericString(14)
	IMEISV string // NumericString(16)
	MSISDN string // NumericString(1..15)
)

// AMFRegistrationType ::= ENUMERATED, see clause 6.2.2.2.2.
type AMFRegistrationType int

const (
	RegTypeInitial          AMFRegistrationType = 1
	RegTypeMobility         AMFRegistrationType = 2
	RegTypePeriodic         AMFRegistrationType = 3
	RegTypeEmergency        AMFRegistrationType = 4
	RegTypeSNPNOnboarding   AMFRegistrationType = 5
	RegTypeDisasterMobility AMFRegistrationType = 6
	RegTypeDisasterInitial  AMFRegistrationType = 7
)

// AMFRegistrationResult ::= ENUMERATED.
type AMFRegistrationResult int

const (
	RegResult3GPPAccess     AMFRegistrationResult = 1
	RegResultNon3GPPAccess  AMFRegistrationResult = 2
	RegResult3GPPAndNon3GPP AMFRegistrationResult = 3
)

// AMFDirection ::= ENUMERATED — who initiated the procedure.
type AMFDirection int

const (
	DirNetworkInitiated AMFDirection = 1
	DirUEInitiated      AMFDirection = 2
)

// AccessType ::= ENUMERATED.
type AccessType int

const (
	AccessThreeGPP    AccessType = 1
	AccessNonThreeGPP AccessType = 2
	AccessBoth        AccessType = 3
)

// --- SMF PDU-session types ---

// PDUSessionID ::= INTEGER (0..255).
type PDUSessionID int

// PDUSessionType ::= ENUMERATED.
type PDUSessionType int

const (
	PDUSessionTypeIPv4         PDUSessionType = 1
	PDUSessionTypeIPv6         PDUSessionType = 2
	PDUSessionTypeIPv4v6       PDUSessionType = 3
	PDUSessionTypeUnstructured PDUSessionType = 4
	PDUSessionTypeEthernet     PDUSessionType = 5
)

// DNN ::= UTF8String — Data Network Name.
type DNN string

// FiveGSMRequestType ::= ENUMERATED.
type FiveGSMRequestType int

const (
	SMRequestInitial           FiveGSMRequestType = 1
	SMRequestExisting          FiveGSMRequestType = 2
	SMRequestInitialEmergency  FiveGSMRequestType = 3
	SMRequestExistingEmergency FiveGSMRequestType = 4
	SMRequestModification      FiveGSMRequestType = 5
	SMRequestReserved          FiveGSMRequestType = 6
	SMRequestMAPDU             FiveGSMRequestType = 7
)

// SNSSAI ::= SEQUENCE — the slice identifier (SST + optional SD).
type SNSSAI struct {
	SliceServiceType    int    `asn1:"tag:1"`          // SST (0..255)
	SliceDifferentiator []byte `asn1:"tag:2,optional"` // SD, OCTET STRING(3)
	MappedHPLMNSST      int    `asn1:"tag:3,optional"`
	MappedHPLMNSD       []byte `asn1:"tag:4,optional"`
}

// FTEID ::= SEQUENCE — a GTP-U F-TEID (tunnel id + endpoint IP).
type FTEID struct {
	TEID        int64  `asn1:"tag:1"`          // 0..4294967295
	IPv4Address []byte `asn1:"tag:2,optional"` // OCTET STRING(4)
	IPv6Address []byte `asn1:"tag:3,optional"` // OCTET STRING(16)
}

// FiveGSGTPTunnels ::= SEQUENCE — the 5GS user plane tunnels of a PDU session
// (TS 33.128 table 6.2.3-1C). Only uLNGUUPTunnelInformation is modelled: it is
// the F-TEID of the UPF endpoint of the NG-U transport bearer, which is the
// value a POI here can supply. additionalULNGUUPTunnelInformation (multiple NG-U
// bearers) and dLRANTunnelInformation (downlink RAN tunnel and QoS flows) are
// not modelled — the SMF holds neither for the single default path it manages.
type FiveGSGTPTunnels struct {
	ULNGUUPTunnelInformation FTEID `asn1:"tag:1,optional"`
}

// GTPTunnelInfo ::= SEQUENCE — the user plane GTP tunnels of a session
// (TS 33.128 table 6.2.3-1B). The payload tables mark this field **M** in
// SMFPDUSessionEstablishment, SMFPDUSessionModification and
// SMFStartOfInterceptionWithEstablishedPDUSession, while the published ASN.1
// module marks it OPTIONAL — so a record omitting it decodes cleanly and is
// still non-conformant. It was absent here for exactly that reason; see
// CONFORMANCE.md.
//
// ePSGTPTunnels [2] is not modelled: it reports PDN connection events at an
// SGW/PGW, which this project does not implement.
type GTPTunnelInfo struct {
	FiveGSGTPTunnels FiveGSGTPTunnels `asn1:"tag:1,optional"`
}

// Location ::= SEQUENCE — minimal model. All six members are OPTIONAL; we model
// only locationInfo [1] (and within it only currentLocation), so a Location may
// be empty. The deeper detail (userLocation → EUTRA/NR/N3GA/..., positioningInfo,
// the 4G variants, iMSLocation) is deferred to a later increment.
type Location struct {
	LocationInfo LocationInfo `asn1:"tag:1,optional"`
}

// LocationInfo ::= SEQUENCE — minimal: currentLocation only; the rest (userLocation,
// geoInfo, rATType, timeZone, additionalCellIDs) is deferred.
type LocationInfo struct {
	CurrentLocation bool `asn1:"tag:2,optional"`
}

// AMFFailedProcedureType ::= ENUMERATED.
type AMFFailedProcedureType int

const (
	FailedRegistration            AMFFailedProcedureType = 1
	FailedSMS                     AMFFailedProcedureType = 2
	FailedPDUSessionEstablishment AMFFailedProcedureType = 3
)

// FiveGMMCause / FiveGSMCause ::= INTEGER (0..255) — the two AMFFailureCause
// CHOICE arms. Distinct Go types so the codec can tell them apart.
type (
	FiveGMMCause int
	FiveGSMCause int
)

// SMFFailedProcedureType ::= ENUMERATED — which SM procedure failed, not why.
// The cause travels separately in FiveGSMCause.
type SMFFailedProcedureType int

const (
	SMFFailedPDUSessionEstablishment SMFFailedProcedureType = 1
	SMFFailedPDUSessionModification  SMFFailedProcedureType = 2
	SMFFailedPDUSessionRelease       SMFFailedProcedureType = 3
)

// Initiator ::= ENUMERATED — who is initiating the rejection or indicating the
// failure, per the field's description in TS 33.128 table 6.2.3-5.
type Initiator int

const (
	InitiatorUE      Initiator = 1
	InitiatorNetwork Initiator = 2
	InitiatorUnknown Initiator = 3
)

// --- UserIdentifiers, the identity list the newer AMF records carry ---
//
// TS 33.128:
//
//	UserIdentifiers     ::= SEQUENCE { fiveGSSubscriberIDs [1] FiveGSSubscriberIDs OPTIONAL,
//	                                   ePSSubscriberIDs    [2] EPSSubscriberIDs OPTIONAL }
//	FiveGSSubscriberIDs ::= SEQUENCE { fiveGSSubscriberID [1] SEQUENCE SIZE(1..MAX) OF FiveGSSubscriberID }
//	FiveGSSubscriberID  ::= CHOICE { sUPI [1] SUPI, sUCI [2] SUCI, pEI [3] PEI, gPSI [4] GPSI }
//
// The inner arms are themselves CHOICEs, and a context tag on a CHOICE is
// automatically explicit — so each arm is a one-field Go struct. The struct
// encodes as a constructed SEQUENCE whose tag the outer CHOICE registration then
// rewrites to its context tag, which is exactly the [n] EXPLICIT wrapper the
// module asks for. Registering the leaves flat would emit [1] IMSI where the
// module wants [1] { [1] IMSI }.
//
// ePSSubscriberIDs is not modelled: it carries IMSI/IMEI/MSISDN in their EPS
// forms for a UE with an EPS presence, which SD-Core's AMF never has.
type (
	// SubscriberSUPI is the sUPI [1] arm; Value holds an IMSI or NAI.
	SubscriberSUPI struct {
		Value any `asn1:"choice:supi"`
	}
	// SubscriberPEI is the pEI [3] arm; Value holds an IMEI or IMEISV.
	SubscriberPEI struct {
		Value any `asn1:"choice:pei"`
	}
	// SubscriberGPSI is the gPSI [4] arm; Value holds an MSISDN or NAI.
	SubscriberGPSI struct {
		Value any `asn1:"choice:gpsi"`
	}
)

// FiveGSSubscriberIDs wraps the SEQUENCE SIZE(1..MAX) OF the CHOICE above. The
// list is declared []any with the choice on the field, which is what makes the
// codec resolve the CHOICE per element rather than against the slice.
type FiveGSSubscriberIDs struct {
	IDs []any `asn1:"tag:1,choice:fiveGSSubscriberID"`
}

// UserIdentifiers is mandatory in the records that carry it, but both its members
// are OPTIONAL, so the empty form is schema-valid. Build it with Identifiers.
type UserIdentifiers struct {
	FiveGS FiveGSSubscriberIDs `asn1:"tag:1,optional"`
}

// Identifiers builds a UserIdentifiers from whichever of the three identity
// leaves are known, skipping absent ones. Order follows the CHOICE's tag order so
// two records for the same subscriber compare equal.
//
// The list is SIZE(1..MAX), so a UserIdentifiers with no identity at all omits
// fiveGSSubscriberIDs entirely rather than carrying an empty list — present and
// empty would be schema-invalid, unlike the empty UserIdentifiers itself.
func Identifiers(supi, pei, gpsi any) UserIdentifiers {
	var ids []any
	if supi != nil {
		ids = append(ids, SubscriberSUPI{Value: supi})
	}
	if pei != nil {
		ids = append(ids, SubscriberPEI{Value: pei})
	}
	if gpsi != nil {
		ids = append(ids, SubscriberGPSI{Value: gpsi})
	}
	if len(ids) == 0 {
		return UserIdentifiers{}
	}
	return UserIdentifiers{FiveGS: FiveGSSubscriberIDs{IDs: ids}}
}

// --- NGAP-facing leaf types, for the handover records ---

// AMFUENGAPID ::= INTEGER (0..1099511627775), RANUENGAPID ::= INTEGER (0..4294967295).
type (
	AMFUENGAPID int64
	RANUENGAPID int64
)

// HandoverType ::= ENUMERATED, mirroring TS 38.413's HandoverType.
type HandoverType int

const (
	HandoverIntra5GS     HandoverType = 1
	HandoverFiveGSToEPS  HandoverType = 2
	HandoverEPSTo5GS     HandoverType = 3
	HandoverFiveGSToUTRA HandoverType = 4
)

// The five HandoverCause arms. Each is an ENUMERATED whose values follow the
// corresponding NGAP Cause group in TS 38.413 clause 9.3.1.2, numbered from 1 in
// the order the module lists them. Distinct Go types so the CHOICE codec can tell
// the groups apart; the NGAP-to-LI value mapping is done where the record is
// built, not here.
type (
	CauseRadioNetwork int
	CauseTransport    int
	CauseNas          int
	CauseProtocol     int
	CauseMisc         int
)

// RANTargetToSourceContainer / RANSourceToTargetContainer ::= OCTET STRING — the
// opaque RRC containers. Copied, never parsed (design D6).
type (
	RANTargetToSourceContainer []byte
	RANSourceToTargetContainer []byte
)

// PDUSessionResourceInformation ::= SEQUENCE — which session moved with the target.
type PDUSessionResourceInformation struct {
	PDUSessionID PDUSessionID `asn1:"tag:1"`
}

// --- Service-accept and transfer leaf types ---

// ServiceMessageIdentity ::= CHOICE { serviceRequest [1] OCTET STRING,
// serviceAccept [2] OCTET STRING } — the message-type octet, per TS 24.501
// clause 9.7, not the whole PDU.
type (
	ServiceRequestIdentity []byte
	ServiceAcceptIdentity  []byte
)

// UEPolicy ::= OCTET STRING (SIZE(16..65540)) and lcsCorrelationId ::= UTF8String
// (SIZE(1..255)). The policy is an opaque payload: copied, never parsed.
type (
	UEPolicy         []byte
	LCSCorrelationID string
)

// FiveGGUTI ::= SEQUENCE. All members are IMPLICIT context-tagged.
type FiveGGUTI struct {
	MCC         string `asn1:"tag:1"` // NumericString(3)
	MNC         string `asn1:"tag:2"` // NumericString(2..3)
	AMFRegionID int    `asn1:"tag:3"` // INTEGER(0..255)
	AMFSetID    int    `asn1:"tag:4"` // INTEGER(0..1023)
	AMFPointer  int    `asn1:"tag:5"` // INTEGER(0..63)
	FiveGTMSI   int64  `asn1:"tag:6"` // INTEGER(0..4294967295)
}

// AMFRegistration is a slice of TS 33.128 AMFRegistration: the four mandatory
// members (registrationType, registrationResult, sUPI, gUTI) plus the PEI/GPSI
// target-identifier optionals. The CHOICE-typed members (sUPI/pEI/gPSI) are
// EXPLICIT-tagged because a context tag on a CHOICE is automatically explicit.
type AMFRegistration struct {
	RegistrationType   AMFRegistrationType   `asn1:"tag:1"`
	RegistrationResult AMFRegistrationResult `asn1:"tag:2"`
	SUPI               any                   `asn1:"tag:4,explicit,choice:supi"`
	PEI                any                   `asn1:"tag:6,explicit,choice:pei,optional"`
	GPSI               any                   `asn1:"tag:7,explicit,choice:gpsi,optional"`
	GUTI               FiveGGUTI             `asn1:"tag:8"`
}

// AMFDeregistration is a slice of TS 33.128 AMFDeregistration: the mandatory
// deregistrationDirection + accessType, plus the target-identifier optionals.
// (sUPI/sUCI/pEI/gPSI/gUTI are all OPTIONAL in this record.)
type AMFDeregistration struct {
	DeregistrationDirection AMFDirection `asn1:"tag:1"`
	AccessType              AccessType   `asn1:"tag:2"`
	SUPI                    any          `asn1:"tag:3,explicit,choice:supi,optional"`
	PEI                     any          `asn1:"tag:5,explicit,choice:pei,optional"`
	GPSI                    any          `asn1:"tag:6,explicit,choice:gpsi,optional"`
	GUTI                    FiveGGUTI    `asn1:"tag:7,optional"` // value+optional: zero-value omitted (lib has no pointer support)
}

// AMFStartOfInterceptionWithRegisteredUE is a slice of the same-named record,
// generated when interception is activated for an already-registered UE.
// Mandatory: registrationResult, sUPI, gUTI. registrationType is OPTIONAL here.
type AMFStartOfInterceptionWithRegisteredUE struct {
	RegistrationResult AMFRegistrationResult `asn1:"tag:1"`
	RegistrationType   AMFRegistrationType   `asn1:"tag:2,optional"`
	SUPI               any                   `asn1:"tag:4,explicit,choice:supi"`
	PEI                any                   `asn1:"tag:6,explicit,choice:pei,optional"`
	GPSI               any                   `asn1:"tag:7,explicit,choice:gpsi,optional"`
	GUTI               FiveGGUTI             `asn1:"tag:8"`
}

// SMFPDUSessionEstablishment is a slice of the same-named TS 33.128 record.
// Mandatory: pDUSessionID, gTPTunnelID, pDUSessionType, dNN, requestType.
// uEEndpoint [9] is OPTIONAL here and carries the address assigned to the UE —
// distinct from gTPTunnelID, which is the serving UPF's tunnel endpoint.
// Deferred optionals (deeper subtrees): location [11] and the long tail.
type SMFPDUSessionEstablishment struct {
	SUPI           any                `asn1:"tag:1,explicit,choice:supi,optional"`
	PEI            any                `asn1:"tag:3,explicit,choice:pei,optional"`
	GPSI           any                `asn1:"tag:4,explicit,choice:gpsi,optional"`
	PDUSessionID   PDUSessionID       `asn1:"tag:5"`
	GTPTunnelID    FTEID              `asn1:"tag:6"`
	PDUSessionType PDUSessionType     `asn1:"tag:7"`
	SNSSAI         SNSSAI             `asn1:"tag:8,optional"`
	UEEndpoint     []any              `asn1:"tag:9,choice:ueEndpointAddress,optional"`
	DNN            DNN                `asn1:"tag:12"`
	RequestType    FiveGSMRequestType `asn1:"tag:15"`
	AccessType     AccessType         `asn1:"tag:16,optional"`
	GTPTunnelInfo  GTPTunnelInfo      `asn1:"tag:25,optional"`
}

// SMFPDUSessionModification is a slice of the same-named record. Only
// requestType is mandatory.
type SMFPDUSessionModification struct {
	SUPI          any                `asn1:"tag:1,explicit,choice:supi,optional"`
	PEI           any                `asn1:"tag:3,explicit,choice:pei,optional"`
	GPSI          any                `asn1:"tag:4,explicit,choice:gpsi,optional"`
	SNSSAI        SNSSAI             `asn1:"tag:5,optional"`
	RequestType   FiveGSMRequestType `asn1:"tag:8"`
	AccessType    AccessType         `asn1:"tag:9,optional"`
	PDUSessionID  PDUSessionID       `asn1:"tag:11,optional"` // note: value 0 indistinguishable from absent
	GTPTunnelInfo GTPTunnelInfo      `asn1:"tag:16,optional"`
}

// SMFPDUSessionRelease is a slice of the same-named record. Mandatory: sUPI,
// pDUSessionID. Deferred optionals: timeOfFirst/LastPacket [5][6] (GeneralizedTime),
// location [9], and the cause tail.
type SMFPDUSessionRelease struct {
	SUPI           any          `asn1:"tag:1,explicit,choice:supi"`
	PEI            any          `asn1:"tag:2,explicit,choice:pei,optional"`
	GPSI           any          `asn1:"tag:3,explicit,choice:gpsi,optional"`
	PDUSessionID   PDUSessionID `asn1:"tag:4"`
	UplinkVolume   int64        `asn1:"tag:7,optional"`
	DownlinkVolume int64        `asn1:"tag:8,optional"`
}

// AMFLocationUpdate is a slice of the same-named record. Mandatory: sUPI,
// location (a minimal Location for now — see Location).
type AMFLocationUpdate struct {
	SUPI     any       `asn1:"tag:1,explicit,choice:supi"`
	PEI      any       `asn1:"tag:3,explicit,choice:pei,optional"`
	GPSI     any       `asn1:"tag:4,explicit,choice:gpsi,optional"`
	GUTI     FiveGGUTI `asn1:"tag:5,optional"`
	Location Location  `asn1:"tag:6"`
}

// AMFUnsuccessfulProcedure is a slice of the same-named record. Mandatory:
// failedProcedureType and failureCause (a CHOICE of 5GMM/5GSM cause).
type AMFUnsuccessfulProcedure struct {
	FailedProcedureType AMFFailedProcedureType `asn1:"tag:1"`
	FailureCause        any                    `asn1:"tag:2,explicit,choice:amfFailureCause"`
	SUPI                any                    `asn1:"tag:4,explicit,choice:supi,optional"`
	PEI                 any                    `asn1:"tag:6,explicit,choice:pei,optional"`
	GPSI                any                    `asn1:"tag:7,explicit,choice:gpsi,optional"`
	GUTI                FiveGGUTI              `asn1:"tag:8,optional"`
	Location            Location               `asn1:"tag:9,optional"`
}

// AMFIdentifierAssociation is a slice of the same-named TS 33.128 record,
// generated when the AMF binds a target's SUPI to a (newly assigned) 5G-GUTI.
// Mandatory: sUPI [1], gUTI [5]; the pEI/gPSI target-identifier optionals are
// also carried. Deferred optionals (deeper types): sUCI [2], oldGUTI [6]
// (EPS5GGUTI), additionalUserIdentifiers [7], relatedAMFUENGAPID [8].
type AMFIdentifierAssociation struct {
	SUPI any       `asn1:"tag:1,explicit,choice:supi"`
	PEI  any       `asn1:"tag:3,explicit,choice:pei,optional"`
	GPSI any       `asn1:"tag:4,explicit,choice:gpsi,optional"`
	GUTI FiveGGUTI `asn1:"tag:5"`
	// location [6] is MANDATORY in this record, unlike the other records that
	// carry a Location, where deferring the deep subtree was harmless. Omitting it
	// made every association record fail schema validation. The minimal Location
	// the other records use satisfies the requirement; filling in the detail
	// remains the deferred increment.
	Location Location `asn1:"tag:6"`
}

// AMFIdentifierDeassociation is a slice of the same-named TS 33.128 record,
// generated when the AMF releases a target's SUPI↔5G-GUTI binding. Mandatory:
// sUPI [1] and gUTI [5]. location [6] is optional here — unlike in
// AMFIdentifierAssociation — so the deep subtree stays deferred.
//
// The GUTI was previously emitted as [2] and optional, which is where sUCI lives:
// a conformant receiver read the 5G-GUTI as a SUCI and separately reported the
// mandatory gUTI missing.
type AMFIdentifierDeassociation struct {
	SUPI any       `asn1:"tag:1,explicit,choice:supi"`
	GUTI FiveGGUTI `asn1:"tag:5"`
}

// UEEndpointAddress alternatives. TS 33.128:
//
//	UEEndpointAddress ::= CHOICE {
//	    iPv4Address     [1] IPv4Address,      -- OCTET STRING (SIZE(4))
//	    iPv6Address     [2] IPv6Address,      -- OCTET STRING (SIZE(16))
//	    ethernetAddress [3] MACAddress        -- OCTET STRING (SIZE(6))
//	}
//
// Distinct Go types, like the IMSI/NAI target-identifier leaves, so the CHOICE
// codec can tell the alternatives apart by reflect.Type. They are named byte
// slices, which the codec handles as of local patch 8 — the guards admitted the
// shape before that but the bodies panicked on it.
//
// A ueEndpoint field is a SEQUENCE OF this CHOICE, so it is declared as []any and
// tagged with the choice; see local patch 7 for why the declared type is what
// makes that mean "per element".
type (
	IPv4Address []byte // SIZE(4)
	IPv6Address []byte // SIZE(16)
	MACAddress  []byte // SIZE(6)
)

// UEEndpoint builds the ueEndpoint list for a single UE address, discriminating
// v4 from v6 the way the rest of the project does — To4 first, because a
// 4-in-6-mapped address answers To16 as well and would otherwise be reported as
// IPv6. Returns nil for an absent or unusable address, so a caller that has no
// address emits no list rather than an empty one: an empty ueEndpoint is a
// positive claim that the session has no endpoint address, which is never true
// of an established session.
func UEEndpoint(ip net.IP) []any {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return []any{IPv4Address(append([]byte(nil), v4...))}
	}
	if v16 := ip.To16(); v16 != nil {
		return []any{IPv6Address(append([]byte(nil), v16...))}
	}
	return nil
}

// SMFStartOfInterceptionWithEstablishedPDUSession is a slice of the same-named
// TS 33.128 record (XIRIEvent [9]), generated when interception is activated for
// a UE that already has an active PDU session. Mandatory: pDUSessionID,
// gTPTunnelID, pDUSessionType, uEEndpoint, dNN, requestType. Deep optionals
// (location, the EPS-combo tail, serving network, etc.) are deferred, as for
// SMFPDUSessionEstablishment.
//
// uEEndpoint is mandatory here and must not be emitted as an empty SEQUENCE: an
// empty list asserts that an established session has no endpoint address. Build
// it with UEEndpoint.
type SMFStartOfInterceptionWithEstablishedPDUSession struct {
	SUPI           any                `asn1:"tag:1,explicit,choice:supi,optional"`
	PEI            any                `asn1:"tag:3,explicit,choice:pei,optional"`
	GPSI           any                `asn1:"tag:4,explicit,choice:gpsi,optional"`
	PDUSessionID   PDUSessionID       `asn1:"tag:5"`
	GTPTunnelID    FTEID              `asn1:"tag:6"`
	PDUSessionType PDUSessionType     `asn1:"tag:7"`
	SNSSAI         SNSSAI             `asn1:"tag:8,optional"`
	UEEndpoint     []any              `asn1:"tag:9,choice:ueEndpointAddress"`
	DNN            DNN                `asn1:"tag:12"`
	RequestType    FiveGSMRequestType `asn1:"tag:15"`
	AccessType     AccessType         `asn1:"tag:16,optional"`
	GTPTunnelInfo  GTPTunnelInfo      `asn1:"tag:23,optional"`
}

// SMFUnsuccessfulProcedure is a slice of the same-named record (XIRIEvent [10]),
// generated wherever the SMF refuses or fails a session procedure for a target.
// Mandatory: failedProcedureType, failureCause, initiator — all three knowable at
// every rejection site. The target-identifier optionals and pDUSessionID are
// carried because a record an agency cannot attribute to a subscriber and a
// session is of little use. Deferred optionals: the EPS tail, requestedSlice,
// location, and the long list beyond.
type SMFUnsuccessfulProcedure struct {
	FailedProcedureType SMFFailedProcedureType `asn1:"tag:1"`
	FailureCause        FiveGSMCause           `asn1:"tag:2"`
	Initiator           Initiator              `asn1:"tag:3"`
	SUPI                any                    `asn1:"tag:5,explicit,choice:supi,optional"`
	PEI                 any                    `asn1:"tag:7,explicit,choice:pei,optional"`
	GPSI                any                    `asn1:"tag:8,explicit,choice:gpsi,optional"`
	PDUSessionID        PDUSessionID           `asn1:"tag:9,optional"` // value 0 indistinguishable from absent
	UEEndpoint          []any                  `asn1:"tag:10,choice:ueEndpointAddress,optional"`
	DNN                 DNN                    `asn1:"tag:12,optional"`
	RequestType         FiveGSMRequestType     `asn1:"tag:15,optional"`
	AccessType          AccessType             `asn1:"tag:16,optional"`
}

// AMFUEServiceAccept is a slice of the same-named record (XIRIEvent [147]),
// generated when the AMF sends a SERVICE ACCEPT to the target. Mandatory:
// userIdentifiers, serviceMessageIdentity.
type AMFUEServiceAccept struct {
	UserIdentifiers        UserIdentifiers `asn1:"tag:1"`
	ServiceMessageIdentity any             `asn1:"tag:2,explicit,choice:serviceMessageIdentity"`
	ServiceType            []byte          `asn1:"tag:3,optional"` // OCTET STRING (SIZE(1))
	FiveGTMSI              int64           `asn1:"tag:4,optional"`
}

// AMFUEPolicyTransfer is a slice of the same-named record (XIRIEvent [146]),
// generated when the AMF passes a UE policy container to or from the PCF.
// Mandatory: sUPI, uEPolicy. The policy is copied opaquely (design D6).
type AMFUEPolicyTransfer struct {
	SUPI     any       `asn1:"tag:1,explicit,choice:supi"`
	PEI      any       `asn1:"tag:3,explicit,choice:pei,optional"`
	GPSI     any       `asn1:"tag:4,explicit,choice:gpsi,optional"`
	GUTI     FiveGGUTI `asn1:"tag:5,optional"`
	UEPolicy UEPolicy  `asn1:"tag:6"`
}

// AMFPositioningInfoTransfer is a slice of the same-named record
// (XIRIEvent [111]), generated when the AMF relays an NRPPa or LPP message for a
// target. Mandatory: sUPI, lcsCorrelationId. Both payloads are copied opaquely.
type AMFPositioningInfoTransfer struct {
	SUPI             any              `asn1:"tag:1,explicit,choice:supi"`
	PEI              any              `asn1:"tag:3,explicit,choice:pei,optional"`
	GPSI             any              `asn1:"tag:4,explicit,choice:gpsi,optional"`
	GUTI             FiveGGUTI        `asn1:"tag:5,optional"`
	NRPPaMessage     []byte           `asn1:"tag:6,optional"`
	LPPMessage       []byte           `asn1:"tag:7,optional"`
	LCSCorrelationID LCSCorrelationID `asn1:"tag:8"`
}

// AMFRANHandoverCommand is a slice of the same-named record (XIRIEvent [113]),
// generated when the AMF sends a HANDOVER COMMAND to the source RAN node. All
// five members are mandatory, and all five are available where the command is
// sent (design D2).
type AMFRANHandoverCommand struct {
	UserIdentifiers         UserIdentifiers            `asn1:"tag:1"`
	AMFUENGAPID             AMFUENGAPID                `asn1:"tag:2"`
	RANUENGAPID             RANUENGAPID                `asn1:"tag:3"`
	HandoverType            HandoverType               `asn1:"tag:4"`
	TargetToSourceContainer RANTargetToSourceContainer `asn1:"tag:5"`
}

// AMFRANHandoverRequest is a slice of the same-named record (XIRIEvent [114]).
// Despite the name it is generated on the HANDOVER REQUEST **ACKNOWLEDGE** from
// the target RAN node, per TS 33.128 clause 6.2.2.2.9.3 — see design D2. Eight
// mandatory members; handoverCause and sourceToTargetContainer originate in the
// earlier HANDOVER REQUIRED and have to be carried forward.
type AMFRANHandoverRequest struct {
	UserIdentifiers               UserIdentifiers               `asn1:"tag:1"`
	AMFUENGAPID                   AMFUENGAPID                   `asn1:"tag:2"`
	RANUENGAPID                   RANUENGAPID                   `asn1:"tag:3"`
	HandoverType                  HandoverType                  `asn1:"tag:4"`
	HandoverCause                 any                           `asn1:"tag:5,explicit,choice:handoverCause"`
	PDUSessionResourceInformation PDUSessionResourceInformation `asn1:"tag:6"`
	TargetToSourceContainer       RANTargetToSourceContainer    `asn1:"tag:9"`
	SourceToTargetContainer       RANSourceToTargetContainer    `asn1:"tag:11"`
}

// XIRIPayload ::= SEQUENCE { xIRIPayloadOID [1] RELATIVE-OID, event [2] XIRIEvent }.
// event is a CHOICE, hence EXPLICIT-tagged.
type XIRIPayload struct {
	OID   []byte `asn1:"tag:1"`
	Event any    `asn1:"tag:2,explicit,choice:xiriEvent"`
}

// NewContext returns an asn1 context with the TS 33.128 CHOICE registrations
// this package needs. Each AddChoice maps Go types to the IMPLICIT context tags
// used by the corresponding ASN.1 CHOICE alternative.
func NewContext() *asn1.Context {
	ctx := asn1.NewContext()
	//nolint:errcheck // static registration; a malformed entry is caught by this package's tests
	_ = ctx.AddChoice("supi", []asn1.Choice{
		{Type: reflect.TypeOf(IMSI("")), Options: "tag:1"},
		{Type: reflect.TypeOf(NAI("")), Options: "tag:2"},
	})
	//nolint:errcheck // static registration; a malformed entry is caught by this package's tests
	_ = ctx.AddChoice("pei", []asn1.Choice{
		{Type: reflect.TypeOf(IMEI("")), Options: "tag:1"},
		{Type: reflect.TypeOf(IMEISV("")), Options: "tag:2"},
	})
	//nolint:errcheck // static registration; a malformed entry is caught by this package's tests
	_ = ctx.AddChoice("gpsi", []asn1.Choice{
		{Type: reflect.TypeOf(MSISDN("")), Options: "tag:1"},
		{Type: reflect.TypeOf(NAI("")), Options: "tag:2"},
	})
	//nolint:errcheck // static registration; a malformed entry is caught by this package's tests
	_ = ctx.AddChoice("ueEndpointAddress", []asn1.Choice{
		{Type: reflect.TypeOf(IPv4Address(nil)), Options: "tag:1"},
		{Type: reflect.TypeOf(IPv6Address(nil)), Options: "tag:2"},
		{Type: reflect.TypeOf(MACAddress(nil)), Options: "tag:3"},
	})
	//nolint:errcheck // static registration; a malformed entry is caught by this package's tests
	_ = ctx.AddChoice("amfFailureCause", []asn1.Choice{
		{Type: reflect.TypeOf(FiveGMMCause(0)), Options: "tag:1"},
		{Type: reflect.TypeOf(FiveGSMCause(0)), Options: "tag:2"},
	})
	// The arms are one-field structs, not the leaf types: each is a CHOICE, and a
	// context tag on a CHOICE is explicit — see SubscriberSUPI.
	//nolint:errcheck // static registration; a malformed entry is caught by this package's tests
	_ = ctx.AddChoice("fiveGSSubscriberID", []asn1.Choice{
		{Type: reflect.TypeOf(SubscriberSUPI{}), Options: "tag:1"},
		{Type: reflect.TypeOf(SubscriberPEI{}), Options: "tag:3"},
		{Type: reflect.TypeOf(SubscriberGPSI{}), Options: "tag:4"},
	})
	//nolint:errcheck // static registration; a malformed entry is caught by this package's tests
	_ = ctx.AddChoice("serviceMessageIdentity", []asn1.Choice{
		{Type: reflect.TypeOf(ServiceRequestIdentity(nil)), Options: "tag:1"},
		{Type: reflect.TypeOf(ServiceAcceptIdentity(nil)), Options: "tag:2"},
	})
	//nolint:errcheck // static registration; a malformed entry is caught by this package's tests
	_ = ctx.AddChoice("handoverCause", []asn1.Choice{
		{Type: reflect.TypeOf(CauseRadioNetwork(0)), Options: "tag:1"},
		{Type: reflect.TypeOf(CauseTransport(0)), Options: "tag:2"},
		{Type: reflect.TypeOf(CauseNas(0)), Options: "tag:3"},
		{Type: reflect.TypeOf(CauseProtocol(0)), Options: "tag:4"},
		{Type: reflect.TypeOf(CauseMisc(0)), Options: "tag:5"},
	})
	//nolint:errcheck // static registration; a malformed entry is caught by this package's tests
	_ = ctx.AddChoice("xiriEvent", []asn1.Choice{
		{Type: reflect.TypeOf(AMFRegistration{}), Options: "tag:1"},
		{Type: reflect.TypeOf(AMFDeregistration{}), Options: "tag:2"},
		{Type: reflect.TypeOf(AMFLocationUpdate{}), Options: "tag:3"},
		{Type: reflect.TypeOf(AMFStartOfInterceptionWithRegisteredUE{}), Options: "tag:4"},
		{Type: reflect.TypeOf(AMFUnsuccessfulProcedure{}), Options: "tag:5"},
		{Type: reflect.TypeOf(SMFPDUSessionEstablishment{}), Options: "tag:6"},
		{Type: reflect.TypeOf(SMFPDUSessionModification{}), Options: "tag:7"},
		{Type: reflect.TypeOf(SMFPDUSessionRelease{}), Options: "tag:8"},
		{Type: reflect.TypeOf(SMFStartOfInterceptionWithEstablishedPDUSession{}), Options: "tag:9"},
		{Type: reflect.TypeOf(SMFUnsuccessfulProcedure{}), Options: "tag:10"},
		// Identifier (de)association carry their real TS 33.128 XIRIEvent tags,
		// which are > 30 and therefore encode in ASN.1 high-tag-number (long) form.
		{Type: reflect.TypeOf(AMFIdentifierAssociation{}), Options: "tag:62"},
		{Type: reflect.TypeOf(AMFPositioningInfoTransfer{}), Options: "tag:111"},
		{Type: reflect.TypeOf(AMFRANHandoverCommand{}), Options: "tag:113"},
		{Type: reflect.TypeOf(AMFRANHandoverRequest{}), Options: "tag:114"},
		{Type: reflect.TypeOf(AMFUEPolicyTransfer{}), Options: "tag:146"},
		{Type: reflect.TypeOf(AMFUEServiceAccept{}), Options: "tag:147"},
		{Type: reflect.TypeOf(AMFIdentifierDeassociation{}), Options: "tag:186"},
	})
	return ctx
}

// EncodeXIRI wraps an xIRI event (e.g. AMFRegistration) in an XIRIPayload and
// returns its DER encoding, suitable as the payload of an X2 PDU with payload
// format 3GPP-33.128.
func EncodeXIRI(ctx *asn1.Context, event any) ([]byte, error) {
	if err := validateEvent(event); err != nil {
		return nil, err
	}
	// **Every constrained leaf, on the one path every record crosses.** validateEvent above
	// checks two endpoint-list cases; this checks the restrictions the type definitions
	// themselves carry, which nothing checked at all. A record violating its own definition
	// encoded cleanly and went out: this element believes it delivered, a conformant mediation
	// function discards what it cannot validate, and because delivery succeeded no fault is
	// raised on either side. See constraints.go.
	if err := validateConstraints(event); err != nil {
		return nil, err
	}

	return ctx.Encode(XIRIPayload{OID: xIRIPayloadOID, Event: event})
}

// validateEvent refuses records whose encoding would be schema-valid but false.
//
// The codec cannot catch these: an empty SEQUENCE OF encodes cleanly, and
// ueEndpoint carries no SIZE constraint, so nothing downstream rejects it. What
// it asserts, though, is that an established PDU session has no endpoint
// address, which is never true — and an agency cannot tell that claim apart from
// one we actually meant. Refusing here rather than in each caller keeps the rule
// on the single path both the SMF's record builders take.
// Both records that carry ueEndpoint are checked, because the difference between
// them is only which shape counts as wrong. In the start-of-interception record
// the field is mandatory, so absent and empty are both wrong. In the
// establishment record it is OPTIONAL, so absent is correct and only
// present-and-empty is wrong — a nil slice is omitted, a non-nil empty one is
// emitted as a present empty SEQUENCE.
func validateEvent(event any) error {
	switch rec := event.(type) {
	case SMFStartOfInterceptionWithEstablishedPDUSession:
		if len(rec.UEEndpoint) == 0 {
			return fmt.Errorf(
				"iri: SMFStartOfInterceptionWithEstablishedPDUSession has an empty uEEndpoint; " +
					"the field is mandatory and an empty list asserts the session has no endpoint address")
		}
	case SMFPDUSessionEstablishment:
		if rec.UEEndpoint != nil && len(rec.UEEndpoint) == 0 {
			return fmt.Errorf(
				"iri: SMFPDUSessionEstablishment has a present but empty uEEndpoint; " +
					"the field is optional, so leave it nil to omit it — an empty list " +
					"asserts the session has no endpoint address")
		}
	}
	return nil
}
