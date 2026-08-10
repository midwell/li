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
// Deferred optionals (deeper subtrees): uEEndpoint [9] (SEQUENCE OF the
// UEEndpointAddress CHOICE), location [11], and the long tail.
type SMFPDUSessionEstablishment struct {
	SUPI           any                `asn1:"tag:1,explicit,choice:supi,optional"`
	PEI            any                `asn1:"tag:3,explicit,choice:pei,optional"`
	GPSI           any                `asn1:"tag:4,explicit,choice:gpsi,optional"`
	PDUSessionID   PDUSessionID       `asn1:"tag:5"`
	GTPTunnelID    FTEID              `asn1:"tag:6"`
	PDUSessionType PDUSessionType     `asn1:"tag:7"`
	SNSSAI         SNSSAI             `asn1:"tag:8,optional"`
	DNN            DNN                `asn1:"tag:12"`
	RequestType    FiveGSMRequestType `asn1:"tag:15"`
	AccessType     AccessType         `asn1:"tag:16,optional"`
}

// SMFPDUSessionModification is a slice of the same-named record. Only
// requestType is mandatory.
type SMFPDUSessionModification struct {
	SUPI         any                `asn1:"tag:1,explicit,choice:supi,optional"`
	PEI          any                `asn1:"tag:3,explicit,choice:pei,optional"`
	GPSI         any                `asn1:"tag:4,explicit,choice:gpsi,optional"`
	SNSSAI       SNSSAI             `asn1:"tag:5,optional"`
	RequestType  FiveGSMRequestType `asn1:"tag:8"`
	AccessType   AccessType         `asn1:"tag:9,optional"`
	PDUSessionID PDUSessionID       `asn1:"tag:11,optional"` // note: value 0 indistinguishable from absent
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

// UEEndpointAddress models TS 33.128's ueEndpoint element, which is a CHOICE.
// The bundled codec cannot encode a SEQUENCE OF CHOICE (verified), so
// SMFStartOfInterceptionWithEstablishedPDUSession currently emits uEEndpoint as
// an empty SEQUENCE (present, zero entries — schema-valid). Populating it needs
// SEQUENCE-OF-CHOICE codec support, deferred as it is for the establishment record.
type UEEndpointAddress struct{}

// SMFStartOfInterceptionWithEstablishedPDUSession is a slice of the same-named
// TS 33.128 record (XIRIEvent [9]), generated when interception is activated for
// a UE that already has an active PDU session. Mandatory: pDUSessionID,
// gTPTunnelID, pDUSessionType, uEEndpoint, dNN, requestType (uEEndpoint emitted
// empty — see UEEndpointAddress). Deep optionals (location, the EPS-combo tail,
// serving network, etc.) are deferred, as for SMFPDUSessionEstablishment.
type SMFStartOfInterceptionWithEstablishedPDUSession struct {
	SUPI           any                 `asn1:"tag:1,explicit,choice:supi,optional"`
	PEI            any                 `asn1:"tag:3,explicit,choice:pei,optional"`
	GPSI           any                 `asn1:"tag:4,explicit,choice:gpsi,optional"`
	PDUSessionID   PDUSessionID        `asn1:"tag:5"`
	GTPTunnelID    FTEID               `asn1:"tag:6"`
	PDUSessionType PDUSessionType      `asn1:"tag:7"`
	SNSSAI         SNSSAI              `asn1:"tag:8,optional"`
	UEEndpoint     []UEEndpointAddress `asn1:"tag:9"` // mandatory SEQUENCE OF; emitted empty
	DNN            DNN                 `asn1:"tag:12"`
	RequestType    FiveGSMRequestType  `asn1:"tag:15"`
	AccessType     AccessType          `asn1:"tag:16,optional"`
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
	_ = ctx.AddChoice("amfFailureCause", []asn1.Choice{
		{Type: reflect.TypeOf(FiveGMMCause(0)), Options: "tag:1"},
		{Type: reflect.TypeOf(FiveGSMCause(0)), Options: "tag:2"},
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
		// Identifier (de)association carry their real TS 33.128 XIRIEvent tags,
		// which are > 30 and therefore encode in ASN.1 high-tag-number (long) form.
		{Type: reflect.TypeOf(AMFIdentifierAssociation{}), Options: "tag:62"},
		{Type: reflect.TypeOf(AMFIdentifierDeassociation{}), Options: "tag:186"},
	})
	return ctx
}

// EncodeXIRI wraps an xIRI event (e.g. AMFRegistration) in an XIRIPayload and
// returns its DER encoding, suitable as the payload of an X2 PDU with payload
// format 3GPP-33.128.
func EncodeXIRI(ctx *asn1.Context, event any) ([]byte, error) {
	return ctx.Encode(XIRIPayload{OID: xIRIPayloadOID, Event: event})
}
