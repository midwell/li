// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

// Package iri builds and encodes 3GPP TS 33.128 xIRI records — the Intercept
// Related Information payload carried in an X2 PDU (payload format 3GPP-33.128).
//
// The records are defined in the TS33128Payloads ASN.1 module
// (DEFINITIONS IMPLICIT TAGS), encoded with BER/DER. We hand-write only the
// subset of records the AMF/SMF POIs actually emit and encode them with the
// PromonLogicalis/asn1 library (BER + CHOICE), mirroring SD-Core's house pattern of
// typed structs + a reflective tag codec (cf. omec ngapType + aper, which are
// PER and therefore not reusable for 33.128's BER).
//
// This is the first vertical slice: the XIRIPayload wrapper and the
// AMFRegistration event (mandatory fields plus the PEI/GPSI target-identifier
// optionals). Remaining records and optional fields follow the same patterns.
package iri

import (
	"reflect"

	"github.com/PromonLogicalis/asn1"
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
	_ = ctx.AddChoice("supi", []asn1.Choice{
		{Type: reflect.TypeOf(IMSI("")), Options: "tag:1"},
		{Type: reflect.TypeOf(NAI("")), Options: "tag:2"},
	})
	_ = ctx.AddChoice("pei", []asn1.Choice{
		{Type: reflect.TypeOf(IMEI("")), Options: "tag:1"},
		{Type: reflect.TypeOf(IMEISV("")), Options: "tag:2"},
	})
	_ = ctx.AddChoice("gpsi", []asn1.Choice{
		{Type: reflect.TypeOf(MSISDN("")), Options: "tag:1"},
		{Type: reflect.TypeOf(NAI("")), Options: "tag:2"},
	})
	_ = ctx.AddChoice("xiriEvent", []asn1.Choice{
		{Type: reflect.TypeOf(AMFRegistration{}), Options: "tag:1"},
	})
	return ctx
}

// EncodeXIRI wraps an xIRI event (e.g. AMFRegistration) in an XIRIPayload and
// returns its DER encoding, suitable as the payload of an X2 PDU with payload
// format 3GPP-33.128.
func EncodeXIRI(ctx *asn1.Context, event any) ([]byte, error) {
	return ctx.Encode(XIRIPayload{OID: xIRIPayloadOID, Event: event})
}
