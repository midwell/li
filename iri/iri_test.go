// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package iri

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func sampleRegistration() AMFRegistration {
	return AMFRegistration{
		RegistrationType:   RegTypeInitial,
		RegistrationResult: RegResult3GPPAccess,
		SUPI:               IMSI("262019876543210"),
		PEI:                IMEI("35342500000001"),
		GPSI:               MSISDN("4915123456789"),
		GUTI: FiveGGUTI{
			MCC:         "262",
			MNC:         "01",
			AMFRegionID: 200,
			AMFSetID:    1,
			AMFPointer:  0,
			FiveGTMSI:   3735928559, // 0xDEADBEEF, exercises the int64 range
		},
	}
}

func TestEncodeDecodeXIRI(t *testing.T) {
	ctx := NewContext()

	der, err := EncodeXIRI(ctx, sampleRegistration())
	if err != nil {
		t.Fatalf("EncodeXIRI: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("empty encoding")
	}

	// Round-trip: decode back into an XIRIPayload and check the event.
	var got XIRIPayload
	if _, err := ctx.Decode(der, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(got.OID, xIRIPayloadOID) {
		t.Errorf("OID = % x, want % x", got.OID, xIRIPayloadOID)
	}
	reg, ok := got.Event.(AMFRegistration)
	if !ok {
		t.Fatalf("event decoded as %T, want AMFRegistration", got.Event)
	}
	if reg.RegistrationType != RegTypeInitial || reg.RegistrationResult != RegResult3GPPAccess {
		t.Errorf("enums: type=%d result=%d", reg.RegistrationType, reg.RegistrationResult)
	}
	if supi, ok := reg.SUPI.(IMSI); !ok || supi != IMSI("262019876543210") {
		t.Errorf("SUPI = %#v, want IMSI 262019876543210", reg.SUPI)
	}
	if pei, ok := reg.PEI.(IMEI); !ok || pei != IMEI("35342500000001") {
		t.Errorf("PEI = %#v, want IMEI 35342500000001", reg.PEI)
	}
	if gpsi, ok := reg.GPSI.(MSISDN); !ok || gpsi != MSISDN("4915123456789") {
		t.Errorf("GPSI = %#v, want MSISDN 4915123456789", reg.GPSI)
	}
	if reg.GUTI != (FiveGGUTI{MCC: "262", MNC: "01", AMFRegionID: 200, AMFSetID: 1, AMFPointer: 0, FiveGTMSI: 3735928559}) {
		t.Errorf("GUTI mismatch: %+v", reg.GUTI)
	}

	// Dump the DER for an independent structural check (openssl asn1parse).
	out := filepath.Join(os.TempDir(), "li_xiri_amfreg.der")
	if err := os.WriteFile(out, der, 0o600); err != nil {
		t.Fatalf("write der: %v", err)
	}
	t.Logf("wrote %d bytes of DER to %s", len(der), out)
}

// TestAbsentOptionalChoice verifies that absent (nil) optional CHOICE fields are
// omitted, not encoded — exercising the bundled li/asn1 nil-safety patch.
func TestAbsentOptionalChoice(t *testing.T) {
	ctx := NewContext()
	reg := sampleRegistration()
	reg.PEI = nil  // optional, absent
	reg.GPSI = nil // optional, absent

	der, err := EncodeXIRI(ctx, reg)
	if err != nil {
		t.Fatalf("EncodeXIRI with absent optionals: %v", err)
	}
	// Absent optionals must shrink the encoding versus the all-present sample.
	full, _ := EncodeXIRI(ctx, sampleRegistration())
	if len(der) >= len(full) {
		t.Errorf("absent-optional encoding (%d) not smaller than full (%d)", len(der), len(full))
	}

	var got XIRIPayload
	if _, err := ctx.Decode(der, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	r, ok := got.Event.(AMFRegistration)
	if !ok {
		t.Fatalf("event decoded as %T", got.Event)
	}
	if r.PEI != nil || r.GPSI != nil {
		t.Errorf("omitted optionals decoded non-nil: PEI=%#v GPSI=%#v", r.PEI, r.GPSI)
	}
	// Mandatory fields must still be present and correct.
	if supi, ok := r.SUPI.(IMSI); !ok || supi != IMSI("262019876543210") {
		t.Errorf("SUPI = %#v, want IMSI", r.SUPI)
	}
}

func TestDeregistrationRoundTrip(t *testing.T) {
	ctx := NewContext()
	dereg := AMFDeregistration{
		DeregistrationDirection: DirUEInitiated,
		AccessType:              AccessThreeGPP,
		SUPI:                    IMSI("262019876543210"),
		GUTI:                    FiveGGUTI{MCC: "262", MNC: "01", AMFRegionID: 200, AMFSetID: 1, FiveGTMSI: 42},
	}
	der, err := EncodeXIRI(ctx, dereg)
	if err != nil {
		t.Fatalf("EncodeXIRI: %v", err)
	}
	var got XIRIPayload
	if _, err := ctx.Decode(der, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	r, ok := got.Event.(AMFDeregistration)
	if !ok {
		t.Fatalf("event decoded as %T, want AMFDeregistration", got.Event)
	}
	if r.DeregistrationDirection != DirUEInitiated || r.AccessType != AccessThreeGPP {
		t.Errorf("enums: dir=%d access=%d", r.DeregistrationDirection, r.AccessType)
	}
	if supi, ok := r.SUPI.(IMSI); !ok || supi != IMSI("262019876543210") {
		t.Errorf("SUPI = %#v", r.SUPI)
	}
	if r.GUTI.MCC != "262" {
		t.Errorf("GUTI not round-tripped: %+v", r.GUTI)
	}
}

func TestStartOfInterceptionRoundTrip(t *testing.T) {
	ctx := NewContext()
	soi := AMFStartOfInterceptionWithRegisteredUE{
		RegistrationResult: RegResult3GPPAccess,
		RegistrationType:   RegTypeInitial,
		SUPI:               IMSI("262019876543210"),
		GUTI:               FiveGGUTI{MCC: "262", MNC: "01", AMFRegionID: 1, AMFSetID: 1, FiveGTMSI: 7},
	}
	der, err := EncodeXIRI(ctx, soi)
	if err != nil {
		t.Fatalf("EncodeXIRI: %v", err)
	}
	var got XIRIPayload
	if _, err := ctx.Decode(der, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	r, ok := got.Event.(AMFStartOfInterceptionWithRegisteredUE)
	if !ok {
		t.Fatalf("event decoded as %T, want AMFStartOfInterceptionWithRegisteredUE", got.Event)
	}
	if r.RegistrationResult != RegResult3GPPAccess || r.RegistrationType != RegTypeInitial {
		t.Errorf("enums: result=%d type=%d", r.RegistrationResult, r.RegistrationType)
	}
}

// TestEventDiscrimination confirms each event decodes back to its own Go type
// via the XIRIEvent CHOICE (no cross-talk between record kinds).
func TestEventDiscrimination(t *testing.T) {
	ctx := NewContext()
	cases := []struct {
		name  string
		event any
		check func(any) bool
	}{
		{"registration", sampleRegistration(), func(e any) bool { _, ok := e.(AMFRegistration); return ok }},
		{"deregistration", AMFDeregistration{DeregistrationDirection: DirNetworkInitiated, AccessType: AccessBoth}, func(e any) bool { _, ok := e.(AMFDeregistration); return ok }},
		{"startOfInterception", AMFStartOfInterceptionWithRegisteredUE{RegistrationResult: RegResult3GPPAccess, SUPI: IMSI("1"), GUTI: FiveGGUTI{MCC: "262", MNC: "01"}}, func(e any) bool { _, ok := e.(AMFStartOfInterceptionWithRegisteredUE); return ok }},
		{"smfStartOfInterception", SMFStartOfInterceptionWithEstablishedPDUSession{SUPI: IMSI("1"), PDUSessionID: 5, PDUSessionType: PDUSessionTypeIPv4, DNN: "internet", RequestType: SMRequestExisting}, func(e any) bool { _, ok := e.(SMFStartOfInterceptionWithEstablishedPDUSession); return ok }},
		{"identifierAssociation", AMFIdentifierAssociation{SUPI: IMSI("1"), GUTI: FiveGGUTI{MCC: "262", MNC: "01"}}, func(e any) bool { _, ok := e.(AMFIdentifierAssociation); return ok }},
		{"identifierDeassociation", AMFIdentifierDeassociation{SUPI: IMSI("1"), GUTI: FiveGGUTI{MCC: "262", MNC: "01"}}, func(e any) bool { _, ok := e.(AMFIdentifierDeassociation); return ok }},
	}
	for _, tc := range cases {
		der, err := EncodeXIRI(ctx, tc.event)
		if err != nil {
			t.Fatalf("%s: encode: %v", tc.name, err)
		}
		var got XIRIPayload
		if _, err := ctx.Decode(der, &got); err != nil {
			t.Fatalf("%s: decode: %v", tc.name, err)
		}
		if !tc.check(got.Event) {
			t.Errorf("%s: decoded as %T", tc.name, got.Event)
		}
	}
}

// TestIdentifierAssociationRoundTrip round-trips both identifier-association
// records. Their XIRIEvent tags (62 and 186) exceed 30, so this is also the
// codec's high-tag-number (long-form) coverage: the identifier octet is
// context+constructed+0x1f = 0xBF, followed by the base-128 tag continuation.
func TestIdentifierAssociationRoundTrip(t *testing.T) {
	ctx := NewContext()
	guti := FiveGGUTI{MCC: "262", MNC: "01", AMFRegionID: 1, AMFSetID: 1, FiveGTMSI: 42}

	assoc := AMFIdentifierAssociation{
		SUPI: IMSI("262019876543210"),
		PEI:  IMEI("35342500000001"),
		GPSI: MSISDN("4915123456789"),
		GUTI: guti,
	}
	der, err := EncodeXIRI(ctx, assoc)
	if err != nil {
		t.Fatalf("association encode: %v", err)
	}
	// The [62] alternative must appear on the wire in high-tag-number long form:
	// 0xBF (context|constructed|0x1f) followed by 0x3E (=62 in one octet).
	if !bytes.Contains(der, []byte{0xBF, 0x3E}) {
		t.Errorf("association DER missing high-tag-number form for [62]: % x", der)
	}
	var g1 XIRIPayload
	if _, err := ctx.Decode(der, &g1); err != nil {
		t.Fatalf("association decode: %v", err)
	}
	a, ok := g1.Event.(AMFIdentifierAssociation)
	if !ok {
		t.Fatalf("event decoded as %T, want AMFIdentifierAssociation", g1.Event)
	}
	if supi, ok := a.SUPI.(IMSI); !ok || supi != "262019876543210" {
		t.Errorf("association SUPI = %#v", a.SUPI)
	}
	if a.GUTI != guti {
		t.Errorf("association GUTI = %+v, want %+v", a.GUTI, guti)
	}

	// Deassociation: tag 186 = 1×128 + 58, so two continuation octets 0x81 0x3A
	// after the 0xBF introducer.
	deassoc := AMFIdentifierDeassociation{SUPI: IMSI("262019876543210"), GUTI: guti}
	der, err = EncodeXIRI(ctx, deassoc)
	if err != nil {
		t.Fatalf("deassociation encode: %v", err)
	}
	if !bytes.Contains(der, []byte{0xBF, 0x81, 0x3A}) {
		t.Errorf("deassociation DER missing high-tag-number form for [186]: % x", der)
	}
	var g2 XIRIPayload
	if _, err := ctx.Decode(der, &g2); err != nil {
		t.Fatalf("deassociation decode: %v", err)
	}
	d, ok := g2.Event.(AMFIdentifierDeassociation)
	if !ok {
		t.Fatalf("event decoded as %T, want AMFIdentifierDeassociation", g2.Event)
	}
	if supi, ok := d.SUPI.(IMSI); !ok || supi != "262019876543210" || d.GUTI != guti {
		t.Errorf("deassociation = %#v guti %+v", d.SUPI, d.GUTI)
	}
}

func sampleEstablishment() SMFPDUSessionEstablishment {
	return SMFPDUSessionEstablishment{
		SUPI:           IMSI("262019876543210"),
		PDUSessionID:   5,
		GTPTunnelID:    FTEID{TEID: 3735928559, IPv4Address: []byte{10, 0, 0, 1}},
		PDUSessionType: PDUSessionTypeIPv4,
		SNSSAI:         SNSSAI{SliceServiceType: 1, SliceDifferentiator: []byte{0x00, 0x00, 0x7b}},
		DNN:            "internet",
		RequestType:    SMRequestInitial,
		AccessType:     AccessThreeGPP,
	}
}

func TestSMFEstablishmentRoundTrip(t *testing.T) {
	ctx := NewContext()
	der, err := EncodeXIRI(ctx, sampleEstablishment())
	if err != nil {
		t.Fatalf("EncodeXIRI: %v", err)
	}
	var got XIRIPayload
	if _, err := ctx.Decode(der, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	r, ok := got.Event.(SMFPDUSessionEstablishment)
	if !ok {
		t.Fatalf("event decoded as %T, want SMFPDUSessionEstablishment", got.Event)
	}
	if r.PDUSessionID != 5 || r.PDUSessionType != PDUSessionTypeIPv4 || r.DNN != "internet" || r.RequestType != SMRequestInitial {
		t.Errorf("scalars: id=%d type=%d dnn=%q req=%d", r.PDUSessionID, r.PDUSessionType, r.DNN, r.RequestType)
	}
	if r.GTPTunnelID.TEID != 3735928559 || !bytes.Equal(r.GTPTunnelID.IPv4Address, []byte{10, 0, 0, 1}) {
		t.Errorf("FTEID: %+v", r.GTPTunnelID)
	}
	if r.SNSSAI.SliceServiceType != 1 || !bytes.Equal(r.SNSSAI.SliceDifferentiator, []byte{0x00, 0x00, 0x7b}) {
		t.Errorf("SNSSAI: %+v", r.SNSSAI)
	}
	if supi, ok := r.SUPI.(IMSI); !ok || supi != IMSI("262019876543210") {
		t.Errorf("SUPI: %#v", r.SUPI)
	}
}

func TestSMFModificationAndReleaseRoundTrip(t *testing.T) {
	ctx := NewContext()

	mod := SMFPDUSessionModification{SUPI: IMSI("262019876543210"), RequestType: SMRequestModification, PDUSessionID: 5}
	der, err := EncodeXIRI(ctx, mod)
	if err != nil {
		t.Fatalf("modification encode: %v", err)
	}
	var g1 XIRIPayload
	if _, err := ctx.Decode(der, &g1); err != nil {
		t.Fatalf("modification decode: %v", err)
	}
	if m, ok := g1.Event.(SMFPDUSessionModification); !ok || m.RequestType != SMRequestModification || m.PDUSessionID != 5 {
		t.Errorf("modification: %#v", g1.Event)
	}

	rel := SMFPDUSessionRelease{SUPI: IMSI("262019876543210"), PDUSessionID: 5, UplinkVolume: 1024, DownlinkVolume: 8192}
	der, err = EncodeXIRI(ctx, rel)
	if err != nil {
		t.Fatalf("release encode: %v", err)
	}
	var g2 XIRIPayload
	if _, err := ctx.Decode(der, &g2); err != nil {
		t.Fatalf("release decode: %v", err)
	}
	r, ok := g2.Event.(SMFPDUSessionRelease)
	if !ok || r.PDUSessionID != 5 || r.UplinkVolume != 1024 || r.DownlinkVolume != 8192 {
		t.Errorf("release: %#v", g2.Event)
	}
}

func TestLocationUpdateRoundTrip(t *testing.T) {
	ctx := NewContext()
	lu := AMFLocationUpdate{
		SUPI: IMSI("262019876543210"),
		GUTI: FiveGGUTI{MCC: "262", MNC: "01", AMFRegionID: 1, AMFSetID: 1, FiveGTMSI: 9},
	}
	der, err := EncodeXIRI(ctx, lu)
	if err != nil {
		t.Fatalf("EncodeXIRI: %v", err)
	}
	var got XIRIPayload
	if _, err := ctx.Decode(der, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	r, ok := got.Event.(AMFLocationUpdate)
	if !ok {
		t.Fatalf("event decoded as %T, want AMFLocationUpdate", got.Event)
	}
	if supi, ok := r.SUPI.(IMSI); !ok || supi != IMSI("262019876543210") {
		t.Errorf("SUPI = %#v", r.SUPI)
	}
	if r.GUTI.MCC != "262" {
		t.Errorf("GUTI not round-tripped: %+v", r.GUTI)
	}
}

func TestUnsuccessfulProcedureRoundTrip(t *testing.T) {
	ctx := NewContext()
	up := AMFUnsuccessfulProcedure{
		FailedProcedureType: FailedRegistration,
		FailureCause:        FiveGMMCause(7),
		SUPI:                IMSI("262019876543210"),
	}
	der, err := EncodeXIRI(ctx, up)
	if err != nil {
		t.Fatalf("EncodeXIRI: %v", err)
	}
	var got XIRIPayload
	if _, err := ctx.Decode(der, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	r, ok := got.Event.(AMFUnsuccessfulProcedure)
	if !ok {
		t.Fatalf("event decoded as %T, want AMFUnsuccessfulProcedure", got.Event)
	}
	if r.FailedProcedureType != FailedRegistration {
		t.Errorf("failedProcedureType = %d", r.FailedProcedureType)
	}
	if c, ok := r.FailureCause.(FiveGMMCause); !ok || c != 7 {
		t.Errorf("failureCause = %#v, want FiveGMMCause(7)", r.FailureCause)
	}
}

// TestMissingMandatoryErrors verifies that a nil MANDATORY field is a loud error,
// not a silently truncated record (the li/asn1 patch returns an error rather
// than omitting or panicking).
func TestMissingMandatoryErrors(t *testing.T) {
	ctx := NewContext()
	reg := sampleRegistration()
	reg.SUPI = nil // mandatory — must not be silently dropped

	if _, err := EncodeXIRI(ctx, reg); err == nil {
		t.Fatal("expected an error encoding a record with a nil mandatory SUPI, got nil")
	}
}
