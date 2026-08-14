// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: MIT

package asn1

import (
	"bytes"
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

// LOCAL PATCH 8/8: the guards above accept any array or slice whose element kind
// is uint8, which includes *named* types — `type IPv4Address []byte` is how
// TS 33.128 models the alternatives of the UEEndpointAddress CHOICE. The bodies
// did not: encodeOctetString asserted the value to []byte and decodeOctetString
// assigned a plain []byte back, so a shape the guard admitted panicked with
// "interface conversion: interface {} is asn1.namedBytes, not []uint8".
//
// A guard that accepts what the body cannot handle is worse than a strict one:
// it turns a type error into a crash, and the crash surfaces at encode time, on
// the delivery path.
type (
	namedBytes  []byte
	namedArray  [4]byte
	namedBytes2 []uint8
)

func TestOctetStringHandlesNamedByteTypes(t *testing.T) {
	ctx := NewContext()

	t.Run("encode named slice", func(t *testing.T) {
		got, err := ctx.encodeOctetString(reflect.ValueOf(namedBytes{1, 2, 3}))
		if err != nil {
			t.Fatalf("encode namedBytes: %v", err)
		}
		if !bytes.Equal(got, []byte{1, 2, 3}) {
			t.Errorf("got % x, want 01 02 03", got)
		}
	})

	t.Run("encode named array", func(t *testing.T) {
		got, err := ctx.encodeOctetString(reflect.ValueOf(namedArray{10, 20, 30, 40}))
		if err != nil {
			t.Fatalf("encode namedArray: %v", err)
		}
		if !bytes.Equal(got, []byte{10, 20, 30, 40}) {
			t.Errorf("got % x, want 0a 14 1e 28", got)
		}
	})

	t.Run("decode into named slice", func(t *testing.T) {
		var into namedBytes
		if err := ctx.decodeOctetString([]byte{4, 5, 6}, reflect.ValueOf(&into).Elem()); err != nil {
			t.Fatalf("decode into namedBytes: %v", err)
		}
		if !bytes.Equal(into, namedBytes{4, 5, 6}) {
			t.Errorf("got % x, want 04 05 06", into)
		}
	})

	t.Run("decode into named array", func(t *testing.T) {
		var into namedArray
		if err := ctx.decodeOctetString([]byte{7, 8, 9, 10}, reflect.ValueOf(&into).Elem()); err != nil {
			t.Fatalf("decode into namedArray: %v", err)
		}
		if into != (namedArray{7, 8, 9, 10}) {
			t.Errorf("got %v, want [7 8 9 10]", into)
		}
	})

	t.Run("round trip through a struct field", func(t *testing.T) {
		type holder struct {
			Addr namedBytes2 `asn1:"tag:1"`
		}
		der, err := ctx.Encode(holder{Addr: namedBytes2{192, 168, 0, 1}})
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		var got holder
		if _, err := ctx.Decode(der, &got); err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if !bytes.Equal(got.Addr, namedBytes2{192, 168, 0, 1}) {
			t.Errorf("Addr = % x, want c0 a8 00 01", got.Addr)
		}
	})
}

// A named *element* type — `type b uint8; type X []b` — is admitted by the same
// guard, because the guard tests the element's kind. The bodies did not handle
// it: reflect.Copy and Value.Convert both require identical element types, so
// each panicked. That is the defect patch 8 exists to fix, surviving inside
// patch 8's own fix, and it was found by enumerating what the guard admits
// against what the body handles rather than by anything failing.
//
// It is latent rather than live: every named byte type in li/iri is `[]byte`,
// the shape above. It matters because encodeOctetString accepts these shapes, so
// leaving decode unable to read them would make a value this codec can write and
// cannot read back.
type (
	namedByteElem  uint8
	namedElemSlice []namedByteElem
	namedElemArray [4]namedByteElem
)

func TestOctetStringHandlesNamedElementTypes(t *testing.T) {
	ctx := NewContext()

	for _, tc := range []struct {
		name string
		val  any
	}{
		{"named slice of named byte", namedElemSlice{1, 2, 3, 4}},
		{"named array of named byte", namedElemArray{1, 2, 3, 4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A panic here is the regression: it is how both paths failed before.
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on a shape the guard admits: %v", r)
				}
			}()
			enc, err := ctx.encodeOctetString(reflect.ValueOf(tc.val))
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if !bytes.Equal(enc, []byte{1, 2, 3, 4}) {
				t.Errorf("encoded % x, want 01 02 03 04", enc)
			}
			into := reflect.New(reflect.TypeOf(tc.val)).Elem()
			if err := ctx.decodeOctetString(enc, into); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !reflect.DeepEqual(into.Interface(), tc.val) {
				t.Errorf("round-trip = %v, want %v", into.Interface(), tc.val)
			}
		})
	}
}
