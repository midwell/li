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

// TestAbsentOptionalChoice documents a known limitation of the Logicalis/asn1
// library: a nil interface{} field is unwrapped with reflect.Value.Elem()
// before the optional check, yielding an invalid Value that panics isEmpty.
// So an ABSENT optional CHOICE field cannot currently be represented as nil.
// Fix options (follow-up): a one-line guard upstream (treat an invalid Value as
// empty in encode/isEmpty), vendor a patched copy, or assemble absent optional
// choice fields via raw values. Mandatory choices and present optionals work.
func TestAbsentOptionalChoice(t *testing.T) {
	t.Skip("known Logicalis nil-interface limitation for absent optional CHOICE fields; tracked as follow-up")
}
