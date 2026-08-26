// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package asn1

import (
	"bytes"
	"math/big"
	"testing"
)

// A pointer field is how an OPTIONAL member says "present, and equal to my type's
// zero value". The encoder decides emptiness by comparing against the zero value
// (isEmpty), so without pointers an OPTIONAL BOOLEAN can encode true and can never
// encode false — and false is the meaningful value for TS 33.128's
// sUPIUnauthenticated, which is set when the SUPI *was* authenticated.
//
// Absence and false must be distinguishable on the wire. These tests are about
// that distinction, not about pointers as a convenience.
type optionalBool struct {
	Before int   `asn1:"tag:1"`
	Flag   *bool `asn1:"tag:2,optional"`
	After  int   `asn1:"tag:3"`
}

func TestOptionalPointerDistinguishesFalseFromAbsent(t *testing.T) {
	ctx := NewContext()
	no, yes := false, true

	absent, err := ctx.Encode(optionalBool{Before: 1, After: 2})
	if err != nil {
		t.Fatalf("encoding with a nil pointer: %v", err)
	}
	present, err := ctx.Encode(optionalBool{Before: 1, Flag: &no, After: 2})
	if err != nil {
		t.Fatalf("encoding false: %v", err)
	}
	if bytes.Equal(absent, present) {
		t.Fatalf("false and absent encode identically (%x), so the receiver cannot tell "+
			"an authenticated SUPI from a record that says nothing about authentication", absent)
	}
	if len(present) <= len(absent) {
		t.Errorf("the present-and-false encoding (%x) is not longer than the absent one (%x), "+
			"so the field is not on the wire", present, absent)
	}

	// true must still work, and must differ from false.
	istrue, err := ctx.Encode(optionalBool{Before: 1, Flag: &yes, After: 2})
	if err != nil {
		t.Fatalf("encoding true: %v", err)
	}
	if bytes.Equal(istrue, present) {
		t.Error("true and false encode identically")
	}
}

func TestOptionalPointerRoundTrips(t *testing.T) {
	ctx := NewContext()
	no, yes := false, true

	for _, tc := range []struct {
		name string
		flag *bool
	}{
		{"absent", nil},
		{"false", &no},
		{"true", &yes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := ctx.Encode(optionalBool{Before: 1, Flag: tc.flag, After: 2})
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			var got optionalBool
			if _, err := ctx.Decode(data, &got); err != nil {
				t.Fatalf("decode: %v", err)
			}
			switch {
			case tc.flag == nil && got.Flag != nil:
				t.Errorf("absent decoded as present (%v)", *got.Flag)
			case tc.flag != nil && got.Flag == nil:
				t.Errorf("present %v decoded as absent — this is the case isEmpty cannot "+
					"express, so a regression here silently drops the field", *tc.flag)
			case tc.flag != nil && *got.Flag != *tc.flag:
				t.Errorf("round trip changed the value: sent %v, got %v", *tc.flag, *got.Flag)
			}
			if got.Before != 1 || got.After != 2 {
				t.Errorf("neighbouring fields disturbed: %+v", got)
			}
		})
	}
}

// Many li/iri fields are explicit-tagged, which routes through a different decoder
// closure than the implicit case above. Cover it so the pointer support is known to
// hold on both paths rather than on the one the first test happened to use.
func TestOptionalPointerUnderExplicitTag(t *testing.T) {
	type explicitBool struct {
		Flag *bool `asn1:"tag:2,explicit,optional"`
	}
	ctx := NewContext()
	no := false

	absent, err := ctx.Encode(explicitBool{})
	if err != nil {
		t.Fatalf("encode absent: %v", err)
	}
	present, err := ctx.Encode(explicitBool{Flag: &no})
	if err != nil {
		t.Fatalf("encode false: %v", err)
	}
	if bytes.Equal(absent, present) {
		t.Fatalf("explicit: false and absent encode identically (%x)", absent)
	}

	var got explicitBool
	if _, err := ctx.Decode(present, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Flag == nil {
		t.Fatal("explicit: present false decoded as absent")
	}
	if *got.Flag {
		t.Errorf("explicit: round trip changed false to true")
	}
}

// A nil pointer on a mandatory field is an error, not a silent omission — the same
// rule the nil-interface patch already applies.
func TestNilPointerOnMandatoryFieldIsAnError(t *testing.T) {
	type mandatory struct {
		Flag *bool `asn1:"tag:1"`
	}
	if _, err := NewContext().Encode(mandatory{}); err == nil {
		t.Error("a nil pointer on a mandatory field encoded without error, so the record " +
			"would go out missing a field its definition requires")
	}
}

// *big.Int is a pointer the encoder handles as a special type. Dereferencing it in
// the pointer branch would strip the type its dispatch keys on, and an INTEGER
// would encode as an empty SEQUENCE.
func TestBigIntIsNotTreatedAsAnOptionalPointer(t *testing.T) {
	ctx := NewContext()
	data, err := ctx.Encode(big.NewInt(0))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if want := []byte{0x02, 0x01, 0x00}; !bytes.Equal(data, want) {
		t.Errorf("big.Int(0) encoded as %#v, want %#v", data, want)
	}
}
