// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package iri

import (
	"encoding/hex"
	"testing"
)

func sampleIdentifiers() UserIdentifiers {
	return Identifiers(IMSI("262019876543210"), IMEISV("3534250000000151"), MSISDN("4915123456789"))
}

// TestUserIdentifiersNesting is the assertion the whole UserIdentifiers modelling
// turns on. TS 33.128 nests three levels — UserIdentifiers -> FiveGSSubscriberIDs
// -> SEQUENCE OF a CHOICE whose arms are themselves CHOICEs — and a context tag on
// a CHOICE is explicit, so each arm must encode as [n] { inner }. Registering the
// leaves flat would emit one level too few, produce bytes that decode against a
// laxer reader, and be rejected by the published module.
func TestUserIdentifiersNesting(t *testing.T) {
	der := assertEncodes(t, AMFUEServiceAccept{
		UserIdentifiers:        sampleIdentifiers(),
		ServiceMessageIdentity: ServiceAcceptIdentity{0x4E},
	}, "305081050413120f01a247bf811343a13ca13aa138a111810f323632303139383736353433323130a312821033353334323530303030303030313531a40f810d34393135313233343536373839a20382014e")

	// userIdentifiers [1] { fiveGSSubscriberIDs [1] { fiveGSSubscriberID [1] {
	//   sUPI [1] { iMSI [1] }, pEI [3] { iMEISV [2] }, gPSI [4] { mSISDN [1] } } } },
	// in the CHOICE's tag order, so two records for the same subscriber are
	// byte-comparable.
	want := "a13c" + "a13a" + "a138" +
		"a111" + "810f" + hex.EncodeToString([]byte("262019876543210")) +
		"a312" + "8210" + hex.EncodeToString([]byte("3534250000000151")) +
		"a40f" + "810d" + hex.EncodeToString([]byte("4915123456789"))
	if !containsTLV(der, want, nil) {
		t.Errorf("userIdentifiers is not nested three levels deep in tag order: % x", der)
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

func TestSMFUnsuccessfulProcedureEncoding(t *testing.T) {
	der := assertEncodes(t, SMFUnsuccessfulProcedure{
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
	}, "305f81050413120f01a256aa5481010182011a830102a511810f323632303139383736353433323130a712821033353334323530303030303030313531a80f810d343931353132333435363738398901058c08696e7465726e65748f0101900101")
	// failedProcedureType [1] 1, failureCause [2] 26, initiator [3] network(2).
	if !containsTLV(der, "810101"+"82011a"+"830102", nil) {
		t.Errorf("mandatory members are not [1] 1, [2] 26, [3] 2 in order: % x", der)
	}
}

// TestSMFUnsuccessfulProcedureMandatoryOnly: the three mandatory members alone
// must encode, since that is all some rejection sites know.
func TestSMFUnsuccessfulProcedureMandatoryOnly(t *testing.T) {
	assertEncodes(t, SMFUnsuccessfulProcedure{
		FailedProcedureType: SMFFailedPDUSessionRelease,
		FailureCause:        FiveGSMCause(0x2b),
		Initiator:           InitiatorNetwork,
	}, "301481050413120f01a20baa0981010382012b830102")
}

func TestAMFUEServiceAcceptEncoding(t *testing.T) {
	der := assertEncodes(t, AMFUEServiceAccept{
		UserIdentifiers:        sampleIdentifiers(),
		ServiceMessageIdentity: ServiceAcceptIdentity{0x4E},
		ServiceType:            []byte{0x01},
	}, "305381050413120f01a24abf811346a13ca13aa138a111810f323632303139383736353433323130a312821033353334323530303030303030313531a40f810d34393135313233343536373839a20382014e830101")
	// serviceMessageIdentity [2] EXPLICIT around serviceAccept [2] 0x4E.
	if !containsTLV(der, "a20382014e", nil) {
		t.Errorf("serviceMessageIdentity is not [2] { [2] 4e }: % x", der)
	}
}

// TestOpaquePayloadsAreCopiedVerbatim covers design D6 and task 2.2: the AMF
// passes these through without parsing, so a byte the AMF saw must be the byte the
// MDF sees. A codec that helpfully normalised one would change evidence.
func TestOpaquePayloadsAreCopiedVerbatim(t *testing.T) {
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

	// Each payload must appear on the wire as its own member's tag and length followed
	// by exactly the bytes given — nothing normalised, trimmed or re-encoded.
	t.Run("uEPolicy", func(t *testing.T) {
		der := assertEncodes(t, AMFUEPolicyTransfer{SUPI: IMSI("262019876543210"), UEPolicy: policy}, "303281050413120f01a229bf811225a111810f323632303139383736353433323130861000ff00007f80000001020304feff007f")
		if !containsTLV(der, "8610", policy) {
			t.Errorf("uEPolicy [6] is not carried verbatim: % x", der)
		}
	})

	t.Run("positioning payloads", func(t *testing.T) {
		der := assertEncodes(t, AMFPositioningInfoTransfer{
			SUPI:             IMSI("262019876543210"),
			NRPPaMessage:     nrppa,
			LPPMessage:       lpp,
			LCSCorrelationID: LCSCorrelationID("corr-1"),
		}, "303381050413120f01a22abf6f27a111810f3236323031393837363534333231308605000102ff008703ab00cd8806636f72722d31")
		if !containsTLV(der, "8605", nrppa) {
			t.Errorf("nRPPaMessage [6] is not carried verbatim: % x", der)
		}
		if !containsTLV(der, "8703", lpp) {
			t.Errorf("lPPMessage [7] is not carried verbatim: % x", der)
		}
		if !containsTLV(der, "8806", []byte("corr-1")) {
			t.Errorf("lcsCorrelationId [8] is not carried verbatim: % x", der)
		}
	})

	t.Run("handover containers", func(t *testing.T) {
		der := assertEncodes(t, AMFRANHandoverRequest{
			UserIdentifiers:               sampleIdentifiers(),
			AMFUENGAPID:                   1,
			RANUENGAPID:                   2,
			HandoverType:                  HandoverIntra5GS,
			HandoverCause:                 CauseRadioNetwork(17),
			PDUSessionResourceInformation: PDUSessionResourceInformation{PDUSessionID: 5},
			TargetToSourceContainer:       target,
			SourceToTargetContainer:       source,
		}, "306981050413120f01a260bf725da13ca13aa138a111810f323632303139383736353433323130a312821033353334323530303030303030313531a40f810d34393135313233343536373839820101830102840101a503810111a603810105890400dead008b04beef0000")
		if !containsTLV(der, "8904", target) {
			t.Errorf("targetToSourceContainer [9] is not carried verbatim: % x", der)
		}
		if !containsTLV(der, "8b04", source) {
			t.Errorf("sourceToTargetContainer [11] is not carried verbatim: % x", der)
		}
		if !containsTLV(der, "a503810111", nil) {
			t.Errorf("handoverCause is not [5] { radioNetwork [1] 17 }: % x", der)
		}
	})
}

func TestAMFRANHandoverCommandEncoding(t *testing.T) {
	der := assertEncodes(t, AMFRANHandoverCommand{
		UserIdentifiers:         sampleIdentifiers(),
		AMFUENGAPID:             1099511627775, // the top of the range
		RANUENGAPID:             4294967295,
		HandoverType:            HandoverIntra5GS,
		TargetToSourceContainer: RANTargetToSourceContainer{0x01, 0x02},
	}, "306081050413120f01a257bf7154a13ca13aa138a111810f323632303139383736353433323130a312821033353334323530303030303030313531a40f810d34393135313233343536373839820600ffffffffff830500ffffffff84010185020102")
	// The tops of both ranges need a leading zero octet to stay positive:
	// aMFUENGAPID [2] 00 ff ff ff ff ff, rANUENGAPID [3] 00 ff ff ff ff.
	if !containsTLV(der, "820600ffffffffff"+"830500ffffffff", nil) {
		t.Errorf("NGAP ids at the top of their ranges are not encoded as expected: % x", der)
	}
}

// TestHandoverCauseArms: every cause group must be distinguishable on the wire, since
// the group is half the meaning — "radio network: handover desirable" and "misc:
// hardware failure" describe very different events.
func TestHandoverCauseArms(t *testing.T) {
	for _, tc := range []struct {
		arm  any
		want string // handoverCause [5] EXPLICIT around the arm's own tag
	}{
		{CauseRadioNetwork(1), "a503810101"},
		{CauseTransport(2), "a503820102"},
		{CauseNas(3), "a503830103"},
		{CauseProtocol(4), "a503840104"},
		{CauseMisc(5), "a503850105"},
	} {
		der, err := EncodeXIRI(NewContext(), AMFRANHandoverRequest{
			UserIdentifiers:               sampleIdentifiers(),
			AMFUENGAPID:                   1,
			RANUENGAPID:                   2,
			HandoverType:                  HandoverIntra5GS,
			HandoverCause:                 tc.arm,
			PDUSessionResourceInformation: PDUSessionResourceInformation{PDUSessionID: 5},
			TargetToSourceContainer:       RANTargetToSourceContainer{0x01},
			SourceToTargetContainer:       RANSourceToTargetContainer{0x02},
		})
		if err != nil {
			t.Fatalf("EncodeXIRI(%T): %v", tc.arm, err)
		}
		if !containsTLV(der, tc.want, nil) {
			t.Errorf("cause arm %T is not carried as %s: % x", tc.arm, tc.want, der)
		}
	}
}

// TestNewRecordsDiscriminate: each new record must be carried under its own
// XIRIEvent alternative. Their tags are 10, 111, 113, 114, 146 and 147 — all but the
// first use high-tag-number form, which is where a tag typo hides.
func TestNewRecordsDiscriminate(t *testing.T) {
	cases := []struct {
		name  string
		event any
		want  string
	}{
		{"unsuccessfulSMProcedure", SMFUnsuccessfulProcedure{
			FailedProcedureType: SMFFailedPDUSessionEstablishment, FailureCause: 1, Initiator: InitiatorNetwork,
		}, "301481050413120f01a20baa09810101820101830102"},
		{"positioningInfoTransfer", AMFPositioningInfoTransfer{
			SUPI: IMSI("1"), LCSCorrelationID: "c",
		}, "301481050413120f01a20bbf6f08a103810131880163"},
		{"handoverCommand", AMFRANHandoverCommand{
			UserIdentifiers: sampleIdentifiers(), AMFUENGAPID: 1, RANUENGAPID: 2,
			HandoverType: HandoverIntra5GS, TargetToSourceContainer: RANTargetToSourceContainer{0x01},
		}, "305681050413120f01a24dbf714aa13ca13aa138a111810f323632303139383736353433323130a312821033353334323530303030303030313531a40f810d34393135313233343536373839820101830102840101850101"},
		{"handoverRequest", AMFRANHandoverRequest{
			UserIdentifiers: sampleIdentifiers(), AMFUENGAPID: 1, RANUENGAPID: 2,
			HandoverType: HandoverIntra5GS, HandoverCause: CauseRadioNetwork(1),
			PDUSessionResourceInformation: PDUSessionResourceInformation{PDUSessionID: 5},
			TargetToSourceContainer:       RANTargetToSourceContainer{0x01},
			SourceToTargetContainer:       RANSourceToTargetContainer{0x02},
		}, "306381050413120f01a25abf7257a13ca13aa138a111810f323632303139383736353433323130a312821033353334323530303030303030313531a40f810d34393135313233343536373839820101830102840101a503810101a6038101058901018b0102"},
		{"uePolicyTransfer", AMFUEPolicyTransfer{
			// Sixteen octets: SIZE(16..65540), which the encoder checks.
			SUPI: IMSI("1"), UEPolicy: make(UEPolicy, 16),
		}, "302481050413120f01a21bbf811217a103810131861000000000000000000000000000000000"},
		{"ueServiceAccept", AMFUEServiceAccept{
			UserIdentifiers: sampleIdentifiers(), ServiceMessageIdentity: ServiceAcceptIdentity{0x4E},
		}, "305081050413120f01a247bf811343a13ca13aa138a111810f323632303139383736353433323130a312821033353334323530303030303030313531a40f810d34393135313233343536373839a20382014e"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertEncodes(t, tc.event, tc.want)
		})
	}
}
