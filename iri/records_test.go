// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package iri

import (
	"bytes"
	"testing"
)

func sampleIdentifiers() UserIdentifiers {
	return Identifiers(IMSI("262019876543210"), IMEISV("3534250000000151"), MSISDN("4915123456789"))
}

// supiOf digs the SUPI back out of a decoded UserIdentifiers. It exists to prove
// the nested CHOICE survives a round trip with its concrete types intact — a
// decode that returned the right bytes under the wrong Go types would still be
// wrong at every call site that reads them.
func supiOf(t *testing.T, u UserIdentifiers) IMSI {
	t.Helper()
	for _, id := range u.FiveGS.IDs {
		arm, ok := id.(SubscriberSUPI)
		if !ok {
			continue
		}
		imsi, ok := arm.Value.(IMSI)
		if !ok {
			t.Fatalf("sUPI arm holds %T, want IMSI", arm.Value)
		}
		return imsi
	}
	t.Fatalf("no sUPI arm in %#v", u.FiveGS.IDs)
	return ""
}

// TestUserIdentifiersNesting is the assertion the whole UserIdentifiers modelling
// turns on. TS 33.128 nests three levels — UserIdentifiers -> FiveGSSubscriberIDs
// -> SEQUENCE OF a CHOICE whose arms are themselves CHOICEs — and a context tag on
// a CHOICE is explicit, so each arm must encode as [n] { inner }. Registering the
// leaves flat would emit one level too few, produce bytes that decode against a
// laxer reader, and be rejected by the published module.
func TestUserIdentifiersNesting(t *testing.T) {
	ctx := NewContext()
	rec := AMFUEServiceAccept{
		UserIdentifiers:        sampleIdentifiers(),
		ServiceMessageIdentity: ServiceAcceptIdentity{0x4E},
	}
	der, err := EncodeXIRI(ctx, rec)
	if err != nil {
		t.Fatalf("EncodeXIRI: %v", err)
	}

	var got XIRIPayload
	if _, err := ctx.Decode(der, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	out, ok := got.Event.(AMFUEServiceAccept)
	if !ok {
		t.Fatalf("decoded as %T, want AMFUEServiceAccept", got.Event)
	}
	if n := len(out.UserIdentifiers.FiveGS.IDs); n != 3 {
		t.Fatalf("decoded %d identifiers, want 3: %#v", n, out.UserIdentifiers.FiveGS.IDs)
	}
	if supi := supiOf(t, out.UserIdentifiers); supi != IMSI("262019876543210") {
		t.Errorf("SUPI = %q, want 262019876543210", supi)
	}
	// Order follows the CHOICE's tag order, so two records for the same subscriber
	// are byte-comparable.
	if _, ok := out.UserIdentifiers.FiveGS.IDs[1].(SubscriberPEI); !ok {
		t.Errorf("identifier 1 is %T, want SubscriberPEI", out.UserIdentifiers.FiveGS.IDs[1])
	}
	if _, ok := out.UserIdentifiers.FiveGS.IDs[2].(SubscriberGPSI); !ok {
		t.Errorf("identifier 2 is %T, want SubscriberGPSI", out.UserIdentifiers.FiveGS.IDs[2])
	}
}

// TestIdentifiersSkipsAbsentLeaves: a subscriber with no PEI or GPSI yields a
// one-entry list, not a three-entry list with empty arms.
func TestIdentifiersSkipsAbsentLeaves(t *testing.T) {
	u := Identifiers(IMSI("262019876543210"), nil, nil)
	if n := len(u.FiveGS.IDs); n != 1 {
		t.Fatalf("got %d identifiers, want 1: %#v", n, u.FiveGS.IDs)
	}
	// And no identity at all omits the inner list rather than carrying it empty:
	// fiveGSSubscriberID is SIZE(1..MAX), so present-and-empty is schema-invalid.
	if ids := Identifiers(nil, nil, nil).FiveGS.IDs; ids != nil {
		t.Errorf("empty Identifiers carries %#v, want nil", ids)
	}
}

func TestSMFUnsuccessfulProcedureRoundTrip(t *testing.T) {
	ctx := NewContext()
	rec := SMFUnsuccessfulProcedure{
		FailedProcedureType: SMFFailedPDUSessionEstablishment,
		FailureCause:        FiveGSMCause(0x1a), // insufficient resources
		Initiator:           InitiatorNetwork,
		SUPI:                IMSI("262019876543210"),
		PEI:                 IMEISV("3534250000000151"),
		GPSI:                MSISDN("4915123456789"),
		PDUSessionID:        5,
		DNN:                 DNN("internet"),
		RequestType:         SMRequestInitial,
		AccessType:          AccessThreeGPP,
	}
	der, err := EncodeXIRI(ctx, rec)
	if err != nil {
		t.Fatalf("EncodeXIRI: %v", err)
	}
	var got XIRIPayload
	if _, err := ctx.Decode(der, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	out, ok := got.Event.(SMFUnsuccessfulProcedure)
	if !ok {
		t.Fatalf("decoded as %T", got.Event)
	}
	if out.FailedProcedureType != SMFFailedPDUSessionEstablishment {
		t.Errorf("failedProcedureType = %d", out.FailedProcedureType)
	}
	if out.FailureCause != FiveGSMCause(0x1a) {
		t.Errorf("failureCause = %d, want 26", out.FailureCause)
	}
	if out.Initiator != InitiatorNetwork {
		t.Errorf("initiator = %d, want network(2)", out.Initiator)
	}
	if supi, ok := out.SUPI.(IMSI); !ok || supi != "262019876543210" {
		t.Errorf("SUPI = %#v", out.SUPI)
	}
}

// TestSMFUnsuccessfulProcedureMandatoryOnly: the three mandatory members alone
// must encode, since that is all some rejection sites know.
func TestSMFUnsuccessfulProcedureMandatoryOnly(t *testing.T) {
	ctx := NewContext()
	rec := SMFUnsuccessfulProcedure{
		FailedProcedureType: SMFFailedPDUSessionRelease,
		FailureCause:        FiveGSMCause(0x2b),
		Initiator:           InitiatorNetwork,
	}
	der, err := EncodeXIRI(ctx, rec)
	if err != nil {
		t.Fatalf("EncodeXIRI with mandatory members only: %v", err)
	}
	var got XIRIPayload
	if _, err := ctx.Decode(der, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	out := got.Event.(SMFUnsuccessfulProcedure) //nolint:errcheck // asserted by construction
	if out.FailedProcedureType != SMFFailedPDUSessionRelease || out.SUPI != nil {
		t.Errorf("round trip = %+v", out)
	}
}

func TestAMFUEServiceAcceptRoundTrip(t *testing.T) {
	ctx := NewContext()
	rec := AMFUEServiceAccept{
		UserIdentifiers:        sampleIdentifiers(),
		ServiceMessageIdentity: ServiceAcceptIdentity{0x4E},
		ServiceType:            []byte{0x01},
	}
	der, err := EncodeXIRI(ctx, rec)
	if err != nil {
		t.Fatalf("EncodeXIRI: %v", err)
	}
	var got XIRIPayload
	if _, err := ctx.Decode(der, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	out := got.Event.(AMFUEServiceAccept) //nolint:errcheck // asserted by construction
	id, ok := out.ServiceMessageIdentity.(ServiceAcceptIdentity)
	if !ok {
		t.Fatalf("serviceMessageIdentity = %T, want ServiceAcceptIdentity", out.ServiceMessageIdentity)
	}
	if !bytes.Equal(id, []byte{0x4E}) {
		t.Errorf("serviceMessageIdentity = % x, want 4e", id)
	}
}

// TestOpaquePayloadsAreCopiedVerbatim covers design D6 and task 2.2: the AMF
// passes these through without parsing, so a byte the AMF saw must be the byte the
// MDF sees. A codec that helpfully normalised one would change evidence.
func TestOpaquePayloadsAreCopiedVerbatim(t *testing.T) {
	ctx := NewContext()
	// Deliberately awkward: leading and trailing zero bytes, and a 0x00 run that a
	// string-oriented codec might truncate.
	//
	// Sixteen octets, because `UEPolicy ::= OCTET STRING (SIZE(16..65540))` and the encoder
	// now checks that. The previous value was seven, which is the evidence this test suite
	// carried that nothing checked: a record violating its own definition encoded cleanly, and
	// a conformant mediation function would have discarded it while this element believed it
	// had delivered. Fixed by making the value conformant rather than by relaxing the
	// constraint — the shortest permitted length is also the sharpest boundary to encode.
	policy := UEPolicy{
		0x00, 0xFF, 0x00, 0x00, 0x7F, 0x80, 0x00, 0x00,
		0x01, 0x02, 0x03, 0x04, 0xFE, 0xFF, 0x00, 0x7F,
	}
	nrppa := []byte{0x00, 0x01, 0x02, 0xFF, 0x00}
	lpp := []byte{0xAB, 0x00, 0xCD}
	target := RANTargetToSourceContainer{0x00, 0xDE, 0xAD, 0x00}
	source := RANSourceToTargetContainer{0xBE, 0xEF, 0x00, 0x00}

	t.Run("uEPolicy", func(t *testing.T) {
		der, err := EncodeXIRI(ctx, AMFUEPolicyTransfer{SUPI: IMSI("262019876543210"), UEPolicy: policy})
		if err != nil {
			t.Fatalf("EncodeXIRI: %v", err)
		}
		var got XIRIPayload
		if _, err := ctx.Decode(der, &got); err != nil {
			t.Fatalf("Decode: %v", err)
		}
		out := got.Event.(AMFUEPolicyTransfer) //nolint:errcheck // asserted by construction
		if !bytes.Equal(out.UEPolicy, policy) {
			t.Errorf("uEPolicy = % x, want % x", out.UEPolicy, policy)
		}
	})

	t.Run("positioning payloads", func(t *testing.T) {
		der, err := EncodeXIRI(ctx, AMFPositioningInfoTransfer{
			SUPI:             IMSI("262019876543210"),
			NRPPaMessage:     nrppa,
			LPPMessage:       lpp,
			LCSCorrelationID: LCSCorrelationID("corr-1"),
		})
		if err != nil {
			t.Fatalf("EncodeXIRI: %v", err)
		}
		var got XIRIPayload
		if _, err := ctx.Decode(der, &got); err != nil {
			t.Fatalf("Decode: %v", err)
		}
		out := got.Event.(AMFPositioningInfoTransfer) //nolint:errcheck // asserted by construction
		if !bytes.Equal(out.NRPPaMessage, nrppa) {
			t.Errorf("nRPPaMessage = % x, want % x", out.NRPPaMessage, nrppa)
		}
		if !bytes.Equal(out.LPPMessage, lpp) {
			t.Errorf("lPPMessage = % x, want % x", out.LPPMessage, lpp)
		}
		if out.LCSCorrelationID != "corr-1" {
			t.Errorf("lcsCorrelationId = %q", out.LCSCorrelationID)
		}
	})

	t.Run("handover containers", func(t *testing.T) {
		der, err := EncodeXIRI(ctx, AMFRANHandoverRequest{
			UserIdentifiers:               sampleIdentifiers(),
			AMFUENGAPID:                   1,
			RANUENGAPID:                   2,
			HandoverType:                  HandoverIntra5GS,
			HandoverCause:                 CauseRadioNetwork(17),
			PDUSessionResourceInformation: PDUSessionResourceInformation{PDUSessionID: 5},
			TargetToSourceContainer:       target,
			SourceToTargetContainer:       source,
		})
		if err != nil {
			t.Fatalf("EncodeXIRI: %v", err)
		}
		var got XIRIPayload
		if _, err := ctx.Decode(der, &got); err != nil {
			t.Fatalf("Decode: %v", err)
		}
		out := got.Event.(AMFRANHandoverRequest) //nolint:errcheck // asserted by construction
		if !bytes.Equal(out.TargetToSourceContainer, target) {
			t.Errorf("targetToSourceContainer = % x, want % x", out.TargetToSourceContainer, target)
		}
		if !bytes.Equal(out.SourceToTargetContainer, source) {
			t.Errorf("sourceToTargetContainer = % x, want % x", out.SourceToTargetContainer, source)
		}
		if cause, ok := out.HandoverCause.(CauseRadioNetwork); !ok || cause != 17 {
			t.Errorf("handoverCause = %#v, want CauseRadioNetwork(17)", out.HandoverCause)
		}
	})
}

func TestAMFRANHandoverCommandRoundTrip(t *testing.T) {
	ctx := NewContext()
	rec := AMFRANHandoverCommand{
		UserIdentifiers:         sampleIdentifiers(),
		AMFUENGAPID:             1099511627775, // the top of the range
		RANUENGAPID:             4294967295,
		HandoverType:            HandoverIntra5GS,
		TargetToSourceContainer: RANTargetToSourceContainer{0x01, 0x02},
	}
	der, err := EncodeXIRI(ctx, rec)
	if err != nil {
		t.Fatalf("EncodeXIRI: %v", err)
	}
	var got XIRIPayload
	if _, err := ctx.Decode(der, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	out := got.Event.(AMFRANHandoverCommand) //nolint:errcheck // asserted by construction
	if out.AMFUENGAPID != 1099511627775 || out.RANUENGAPID != 4294967295 {
		t.Errorf("NGAP ids did not survive: amf=%d ran=%d", out.AMFUENGAPID, out.RANUENGAPID)
	}
	if out.HandoverType != HandoverIntra5GS {
		t.Errorf("handoverType = %d", out.HandoverType)
	}
}

// TestHandoverCauseArms: every cause group must be distinguishable after decode,
// since the group is half the meaning — "radio network: handover desirable" and
// "misc: hardware failure" describe very different events.
func TestHandoverCauseArms(t *testing.T) {
	ctx := NewContext()
	arms := []any{
		CauseRadioNetwork(1), CauseTransport(2), CauseNas(3), CauseProtocol(4), CauseMisc(5),
	}
	for _, arm := range arms {
		rec := AMFRANHandoverRequest{
			UserIdentifiers:               sampleIdentifiers(),
			AMFUENGAPID:                   1,
			RANUENGAPID:                   2,
			HandoverType:                  HandoverIntra5GS,
			HandoverCause:                 arm,
			PDUSessionResourceInformation: PDUSessionResourceInformation{PDUSessionID: 5},
			TargetToSourceContainer:       RANTargetToSourceContainer{0x01},
			SourceToTargetContainer:       RANSourceToTargetContainer{0x02},
		}
		der, err := EncodeXIRI(ctx, rec)
		if err != nil {
			t.Fatalf("EncodeXIRI(%T): %v", arm, err)
		}
		var got XIRIPayload
		if _, err := ctx.Decode(der, &got); err != nil {
			t.Fatalf("Decode(%T): %v", arm, err)
		}
		out := got.Event.(AMFRANHandoverRequest) //nolint:errcheck // asserted by construction
		if gotArm, wantArm := out.HandoverCause, arm; gotArm != wantArm {
			t.Errorf("cause arm %T decoded as %T (%v)", wantArm, gotArm, gotArm)
		}
	}
}

// TestNewRecordsDiscriminate: each new record must decode back to its own Go type
// through the XIRIEvent CHOICE. Their tags are 10, 111, 113, 114, 146 and 147 —
// all but the first use high-tag-number form, which is where a tag typo hides.
func TestNewRecordsDiscriminate(t *testing.T) {
	ctx := NewContext()
	cases := []struct {
		name  string
		event any
		check func(any) bool
	}{
		{"unsuccessfulSMProcedure", SMFUnsuccessfulProcedure{
			FailedProcedureType: SMFFailedPDUSessionEstablishment, FailureCause: 1, Initiator: InitiatorNetwork,
		}, func(e any) bool { _, ok := e.(SMFUnsuccessfulProcedure); return ok }},
		{"positioningInfoTransfer", AMFPositioningInfoTransfer{
			SUPI: IMSI("1"), LCSCorrelationID: "c",
		}, func(e any) bool { _, ok := e.(AMFPositioningInfoTransfer); return ok }},
		{"handoverCommand", AMFRANHandoverCommand{
			UserIdentifiers: sampleIdentifiers(), AMFUENGAPID: 1, RANUENGAPID: 2,
			HandoverType: HandoverIntra5GS, TargetToSourceContainer: RANTargetToSourceContainer{0x01},
		}, func(e any) bool { _, ok := e.(AMFRANHandoverCommand); return ok }},
		{"handoverRequest", AMFRANHandoverRequest{
			UserIdentifiers: sampleIdentifiers(), AMFUENGAPID: 1, RANUENGAPID: 2,
			HandoverType: HandoverIntra5GS, HandoverCause: CauseRadioNetwork(1),
			PDUSessionResourceInformation: PDUSessionResourceInformation{PDUSessionID: 5},
			TargetToSourceContainer:       RANTargetToSourceContainer{0x01},
			SourceToTargetContainer:       RANSourceToTargetContainer{0x02},
		}, func(e any) bool { _, ok := e.(AMFRANHandoverRequest); return ok }},
		{"uePolicyTransfer", AMFUEPolicyTransfer{
			// Sixteen octets: SIZE(16..65540), which the encoder checks.
			SUPI: IMSI("1"), UEPolicy: make(UEPolicy, 16),
		}, func(e any) bool { _, ok := e.(AMFUEPolicyTransfer); return ok }},
		{"ueServiceAccept", AMFUEServiceAccept{
			UserIdentifiers: sampleIdentifiers(), ServiceMessageIdentity: ServiceAcceptIdentity{0x4E},
		}, func(e any) bool { _, ok := e.(AMFUEServiceAccept); return ok }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			der, err := EncodeXIRI(ctx, tc.event)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			var got XIRIPayload
			if _, err := ctx.Decode(der, &got); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !tc.check(got.Event) {
				t.Errorf("decoded as %T", got.Event)
			}
		})
	}
}
