// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: MIT

package asn1

import (
	"reflect"
	"testing"
)

// The OCTET STRING guards used to read
//
//	if !(kind == Array || kind == Slice) && value.Type().Elem().Kind() == Uint8
//
// which contradicts the "Invalid type or element type" comment above it and is
// wrong in both directions. With &&, a kind that is neither array nor slice still
// reaches Type().Elem(), and reflect panics there for a type with no element type;
// and an array or slice short circuits the check entirely, so one whose elements
// are not bytes was accepted and panicked later on a type assertion. A codec has to
// answer both with an error.
func TestOctetStringRejectsWrongTypes(t *testing.T) {
	ctx := NewContext()

	for _, tc := range []struct {
		name  string
		value any
	}{
		{"not an array or slice", 42},
		{"slice of non-bytes", []int{1, 2, 3}},
		{"array of non-bytes", [2]int{1, 2}},
		{"struct", struct{ X int }{1}},
	} {
		t.Run("encode/"+tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked instead of returning an error: %v", r)
				}
			}()
			if _, err := ctx.encodeOctetString(reflect.ValueOf(tc.value)); err == nil {
				t.Error("expected an error, got nil")
			}
		})

		t.Run("decode/"+tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked instead of returning an error: %v", r)
				}
			}()
			v := reflect.New(reflect.TypeOf(tc.value)).Elem()
			if err := ctx.decodeOctetString([]byte{1, 2}, v); err == nil {
				t.Error("expected an error, got nil")
			}
		})
	}
}

// The valid shapes must still work, so the stricter guard cannot have closed the
// door on what the codec is for.
func TestOctetStringAcceptsBytes(t *testing.T) {
	ctx := NewContext()

	if _, err := ctx.encodeOctetString(reflect.ValueOf([]byte{1, 2, 3})); err != nil {
		t.Errorf("encode []byte: %v", err)
	}
	if _, err := ctx.encodeOctetString(reflect.ValueOf([3]byte{1, 2, 3})); err != nil {
		t.Errorf("encode [3]byte: %v", err)
	}

	var into []byte
	if err := ctx.decodeOctetString([]byte{1, 2, 3}, reflect.ValueOf(&into).Elem()); err != nil {
		t.Errorf("decode into []byte: %v", err)
	}
	if len(into) != 3 {
		t.Errorf("decoded %d bytes, want 3", len(into))
	}
}
