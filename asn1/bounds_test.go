// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package asn1

import (
	"math/big"
	"testing"
)

// TestMalformedPrimitiveIsAnErrorNotACrash: a decoder that indexes into contents
// octets before establishing there are any fails on input a conformant peer never
// sends — which is exactly the input that arrives when the peer is not conformant,
// or is not the peer it claims to be.
//
// This codec has no production decode caller today, so the crash is unreachable
// from a network interface. That is a property of the current wiring and not of
// the codec: the wiring is what changes the day a mediation-side tool is written
// against this library, and a codec that is safe only because nothing calls it is
// not safe.
func TestMalformedPrimitiveIsAnErrorNotACrash(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		into func() interface{}
	}{
		{"INTEGER with no content octets", []byte{0x02, 0x00}, func() interface{} { var v *big.Int; return &v }},
		{"INTEGER into a machine int", []byte{0x02, 0x00}, func() interface{} { var v int; return &v }},
		{"BOOLEAN with no content octets", []byte{0x01, 0x00}, func() interface{} { var v bool; return &v }},
		{"an empty encoding", []byte{}, func() interface{} { var v int; return &v }},
		{"a header with no length", []byte{0x02}, func() interface{} { var v int; return &v }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Decode(%#v) panicked: %v — malformed input must be refused, not fatal", tc.data, r)
				}
			}()
			if _, err := Decode(tc.data, tc.into()); err == nil {
				t.Errorf("Decode(%#v) returned no error; malformed input must be refused", tc.data)
			}
		})
	}
}

// TestBERBooleanStillDecodes guards the other side of the guard: the length check
// added for empty contents must not reject an encoding that carries them.
func TestBERBooleanStillDecodes(t *testing.T) {
	ctx := NewContext()
	for _, tc := range []struct {
		data []byte
		want bool
	}{
		{[]byte{0x01, 0x01, 0x00}, false},
		{[]byte{0x01, 0x01, 0xff}, true},
		{[]byte{0x01, 0x01, 0x2a}, true}, // BER: any non-zero is true
	} {
		var got bool
		if _, err := ctx.Decode(tc.data, &got); err != nil {
			t.Fatalf("Decode(%#v): %v", tc.data, err)
		}
		if got != tc.want {
			t.Errorf("Decode(%#v) = %v, want %v", tc.data, got, tc.want)
		}
	}
}
