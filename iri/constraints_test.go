// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package iri

import (
	"strings"
	"testing"
)

// TestARecordViolatingItsOwnDefinitionIsRefused is the encoder validating what it emits.
//
// The record definitions carry their restrictions in comments — `OCTET STRING (SIZE(16..65540))`,
// `INTEGER (0..255)` — and nothing checked them: `EncodeXIRI` validated two endpoint-list cases
// and no constraint at all. So a record whose values violate its own definition encoded cleanly
// and went out.
//
// **That failure is invisible on both sides.** This element believes it delivered; a conformant
// mediation function discards what it cannot validate; and because the delivery succeeded, no
// fault is raised anywhere. It is the unattributable-record failure arriving through the payload
// instead of the header — and the evidence that nothing would catch it was in this package's own
// test suite, which encoded a seven-byte `UEPolicy` against `SIZE(16..65540)`.
//
// One case per kind of restriction: a size, a range, and a length-bounded string.
func TestARecordViolatingItsOwnDefinitionIsRefused(t *testing.T) {
	ctx := NewContext()

	conformantPolicy := make(UEPolicy, 16)

	for _, tc := range []struct {
		name  string
		event any
		// want is a fragment of the refusal, so the message says which field and which
		// definition rather than only that something was wrong.
		want string
	}{
		{
			name:  "an octet string shorter than its SIZE",
			event: AMFUEPolicyTransfer{SUPI: IMSI("262019876543210"), UEPolicy: make(UEPolicy, 15)},
			want:  "UEPolicy is defined as SIZE(16..65540)",
		},
		{
			name: "an address whose length is not its family's",
			event: SMFPDUSessionEstablishment{
				SUPI:       IMSI("262019876543210"),
				UEEndpoint: []any{IPv4Address{10, 250, 0}},
			},
			want: "IPv4Address is defined as SIZE(4..4)",
		},
		{
			name: "an integer above its range",
			event: AMFRANHandoverRequest{
				UserIdentifiers: sampleIdentifiers(),
				// AMFUENGAPID ::= INTEGER (0..1099511627775).
				AMFUENGAPID: 1099511627776,
				RANUENGAPID: 2,
			},
			want: "AMFUENGAPID is defined as INTEGER (0..1099511627775)",
		},
		{
			name: "a UTF8String longer than its SIZE",
			event: AMFPositioningInfoTransfer{
				SUPI:             IMSI("262019876543210"),
				LCSCorrelationID: LCSCorrelationID(strings.Repeat("x", 256)),
			},
			want: "LCSCorrelationID is defined as UTF8String (SIZE(1..255))",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := EncodeXIRI(ctx, tc.event)
			if err == nil {
				t.Fatal("a record violating its own definition was encoded: a conformant mediation " +
					"function discards it, this element believes it delivered, and no fault is " +
					"raised on either side")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refusal is %q, want it to name the field and the definition (%q)",
					err, tc.want)
			}
		})
	}

	// And a conformant record still encodes: the check must not be a way of emitting nothing.
	if _, err := EncodeXIRI(ctx, AMFUEPolicyTransfer{
		SUPI: IMSI("262019876543210"), UEPolicy: conformantPolicy,
	}); err != nil {
		t.Errorf("a conformant record was refused: %v", err)
	}
}

// TestAnAbsentOptionalLeafIsNotTooShort keeps the check from refusing every record that omits
// an optional field. An absent OPTIONAL octet string is a nil slice, which the codec omits —
// so zero length is "not present" rather than "present and too short", and treating them the
// same would make the validation itself the reason no record is delivered.
func TestAnAbsentOptionalLeafIsNotTooShort(t *testing.T) {
	if _, err := EncodeXIRI(NewContext(), AMFPositioningInfoTransfer{
		SUPI: IMSI("262019876543210"),
		// LCSCorrelationID omitted, which is what an element with none does.
	}); err != nil {
		t.Errorf("a record omitting an optional constrained leaf was refused: %v", err)
	}
}
