// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package asn1

import (
	"reflect"
	"testing"
)

// Types for the SEQUENCE OF CHOICE tests. Distinct Go types so the CHOICE codec
// can tell the alternatives apart by reflect.Type, which is how TS 33.128's
// alternatives are modelled in li/iri.
type (
	choiceAlpha string
	choiceBeta  int
	choiceBytes []byte
)

func seqOfChoiceContext(t *testing.T) *Context {
	t.Helper()
	ctx := NewContext()
	if err := ctx.AddChoice("elem", []Choice{
		{Type: reflect.TypeOf(choiceAlpha("")), Options: "tag:1"},
		{Type: reflect.TypeOf(choiceBeta(0)), Options: "tag:2"},
		{Type: reflect.TypeOf(choiceBytes(nil)), Options: "tag:3"},
	}); err != nil {
		t.Fatalf("AddChoice: %v", err)
	}
	return ctx
}

// seqOfChoice is the shape the patch exists for: a SEQUENCE OF whose members are
// a CHOICE. Before LOCAL PATCH 7/8 the encoder rejected this with
// "invalid Go type '[]interface {}' for choice 'elem'".
type seqOfChoice struct {
	Items []any `asn1:"tag:1,choice:elem"`
}

// TestSequenceOfChoiceRoundTrip covers LOCAL PATCH 7/8: every alternative survives
// a round trip through a SEQUENCE OF, with its concrete Go type restored.
func TestSequenceOfChoiceRoundTrip(t *testing.T) {
	ctx := seqOfChoiceContext(t)
	in := seqOfChoice{Items: []any{
		choiceAlpha("first"),
		choiceBeta(42),
		choiceBytes{0xDE, 0xAD, 0xBE, 0xEF},
		choiceAlpha("second"),
	}}

	der, err := ctx.Encode(in)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	var got seqOfChoice
	if _, err := ctx.Decode(der, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(got.Items) != len(in.Items) {
		t.Fatalf("decoded %d items, want %d: %#v", len(got.Items), len(in.Items), got.Items)
	}
	for i, want := range in.Items {
		if !reflect.DeepEqual(got.Items[i], want) {
			t.Errorf("item %d = %#v (%T), want %#v (%T)", i, got.Items[i], got.Items[i], want, want)
		}
	}
}

// TestSequenceOfChoiceOrderPreserved checks that a SEQUENCE OF keeps its order —
// it is a sequence, not a set, and an endpoint or identifier list that reorders
// would misreport which address or identity came first.
func TestSequenceOfChoiceOrderPreserved(t *testing.T) {
	ctx := seqOfChoiceContext(t)
	in := seqOfChoice{Items: []any{choiceBeta(1), choiceBeta(2), choiceBeta(3)}}

	der, err := ctx.Encode(in)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var got seqOfChoice
	if _, err := ctx.Decode(der, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	for i, want := range []choiceBeta{1, 2, 3} {
		if got.Items[i] != any(want) {
			t.Errorf("item %d = %#v, want %v", i, got.Items[i], want)
		}
	}
}

// TestSequenceOfChoiceSingleElement covers the case the TS 33.128
// FiveGSSubscriberIDs field constrains to: SEQUENCE SIZE(1..MAX) OF a CHOICE.
func TestSequenceOfChoiceSingleElement(t *testing.T) {
	ctx := seqOfChoiceContext(t)
	der, err := ctx.Encode(seqOfChoice{Items: []any{choiceAlpha("only")}})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var got seqOfChoice
	if _, err := ctx.Decode(der, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(got.Items) != 1 || got.Items[0] != any(choiceAlpha("only")) {
		t.Errorf("got %#v, want exactly [choiceAlpha(\"only\")]", got.Items)
	}
}

// TestSequenceOfChoiceRejectsUnknownAlternative covers LOCAL PATCH 7/8's decode
// rule: an element whose tag matches no registered alternative must fail the
// decode. Skipping it would return a shorter list that the caller cannot
// distinguish from a genuinely shorter one — for an identifier or endpoint list
// that means silently dropping one of the values that names the subject.
func TestSequenceOfChoiceRejectsUnknownAlternative(t *testing.T) {
	ctx := seqOfChoiceContext(t)
	valid, err := ctx.Encode(seqOfChoice{Items: []any{choiceAlpha("x")}})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Rewrite the inner element's context tag 1 -> 7, which is not registered.
	// The inner element is the last TLV; its tag byte is the third from the end
	// for this one-byte-length, one-byte-content encoding.
	crafted := make([]byte, len(valid))
	copy(crafted, valid)
	inner := -1
	for i := len(crafted) - 1; i >= 0; i-- {
		if crafted[i] == 0x81 { // context-specific, primitive, tag 1
			inner = i
			break
		}
	}
	if inner < 0 {
		t.Fatalf("could not locate the inner choice element in % x", valid)
	}
	crafted[inner] = 0x87 // context-specific, primitive, tag 7 — unregistered

	var got seqOfChoice
	if _, err := ctx.Decode(crafted, &got); err == nil {
		t.Fatalf("expected an error for an unregistered alternative, got items %#v", got.Items)
	}
}

// TestChoiceOnInterfaceFieldHoldingSlice guards the disambiguation in
// splitElementChoice: `choice` on a field *declared* as an interface applies to the
// whole value even when that value is a slice, so a slice-typed CHOICE alternative
// keeps working. Only a field declared as a slice means SEQUENCE OF CHOICE.
func TestChoiceOnInterfaceFieldHoldingSlice(t *testing.T) {
	ctx := seqOfChoiceContext(t)
	// `explicit` mirrors how li/iri declares every CHOICE-typed member: a context
	// tag on a CHOICE has to wrap it, or the field's own tag overwrites the tag
	// that identifies which alternative was chosen.
	type wrapper struct {
		Value any `asn1:"tag:1,explicit,choice:elem"`
	}
	in := wrapper{Value: choiceBytes{0x01, 0x02, 0x03}}

	der, err := ctx.Encode(in)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var got wrapper
	if _, err := ctx.Decode(der, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !reflect.DeepEqual(got.Value, choiceBytes{0x01, 0x02, 0x03}) {
		t.Errorf("Value = %#v (%T), want choiceBytes{1,2,3}", got.Value, got.Value)
	}
}

// TestDecodeRejectsOversizedElement covers LOCAL PATCH 4/4: a crafted definite
// length must be rejected before allocation rather than triggering a multi-GB
// make([]byte) (OOM) or a makeslice panic.
func TestDecodeRejectsOversizedElement(t *testing.T) {
	ctx := NewContext()
	var out struct {
		A int `asn1:"tag:0"`
	}
	// SEQUENCE (0x30), long-form length of 4 octets (0x84) = 0xFFFFFFFF, but the
	// buffer is only 6 bytes — pre-patch this attempts a ~4 GB allocation.
	crafted := []byte{0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF}

	// Must return an error, and must not panic/OOM.
	if _, err := ctx.Decode(crafted, &out); err == nil {
		t.Fatal("expected an error for an oversized element length, got nil")
	}
}

// setOfChoice answers design open-question D-open: does SET OF CHOICE work as a
// side effect of LOCAL PATCH 7/8? The slice codecs are shared between SEQUENCE OF
// and SET OF — the `set` option only rewrites the outer universal tag — so it
// should. TS 33.128 uses SEQUENCE OF throughout and nothing in li/iri exercises
// SET OF, which is exactly why it is worth a test rather than an assumption.
type setOfChoice struct {
	Items []any `asn1:"tag:1,set,choice:elem"`
}

func TestSetOfChoiceRoundTrip(t *testing.T) {
	ctx := seqOfChoiceContext(t)
	in := setOfChoice{Items: []any{choiceAlpha("a"), choiceBeta(7)}}

	der, err := ctx.Encode(in)
	if err != nil {
		t.Fatalf("Encode SET OF CHOICE: %v", err)
	}
	var got setOfChoice
	if _, err := ctx.Decode(der, &got); err != nil {
		t.Fatalf("Decode SET OF CHOICE: %v", err)
	}
	if len(got.Items) != 2 {
		t.Fatalf("decoded %d items, want 2: %#v", len(got.Items), got.Items)
	}
	if got.Items[0] != any(choiceAlpha("a")) || got.Items[1] != any(choiceBeta(7)) {
		t.Errorf("round trip = %#v, want [choiceAlpha(a) choiceBeta(7)]", got.Items)
	}
}
