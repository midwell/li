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
