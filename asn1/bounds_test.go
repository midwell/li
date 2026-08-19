// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package asn1

import (
	"math/big"
	"strings"
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

// TestIndefiniteLengthIsHeldToTheSameCeiling is patch 4's own defect, reached through the
// sibling encoding.
//
// The patch caps the length a sender *declares*, because an unbounded `make([]byte, length)`
// from peer-supplied BER is a remote denial of service. The indefinite-length branch beside it
// buffered until an end-of-contents marker arrived, so the sender set the cost twice over: the
// `bytes.Buffer` grew with whatever it sent, and `readEoc` recursed once per nested construct
// with no depth bound at all. So the ceiling was bypassed simply by choosing the other form.
//
// The patch's own README states the caller it was written for — "any caller that decodes
// peer-supplied BER (e.g. an MDF/receiver)" — which is exactly the caller left exposed.
func TestIndefiniteLengthIsHeldToTheSameCeiling(t *testing.T) {
	t.Run("a construct larger than the ceiling", func(t *testing.T) {
		// An indefinite-length constructed element containing one OCTET STRING whose declared
		// length is past the ceiling. The definite branch refuses this; so must this one.
		var data []byte
		data = append(data, 0x30, 0x80) // SEQUENCE, indefinite
		// OCTET STRING with a 4-byte length of 0x7fffffff
		data = append(data, 0x04, 0x84, 0x7f, 0xff, 0xff, 0xff)

		var v struct{}
		_, err := Decode(data, &v)
		if err == nil {
			t.Fatal("an indefinite-length construct declaring more than the ceiling was accepted: " +
				"the cap the definite form is held to is bypassed by choosing this encoding")
		}
		// **The reason has to name the ceiling.** Without the check, this input also fails —
		// skipBytes runs off the end of the message and reports an EOF — so a test asserting
		// only "an error" passes against the defect. What distinguishes the two is that the
		// bounded decoder refuses the *declared length* before reading anything.
		if !strings.Contains(err.Error(), "exceeds maximum") {
			t.Errorf("refused with %q, want a refusal naming the ceiling: an unbounded decoder "+
				"fails on this input too, by running off the end of the message", err)
		}
	})

	t.Run("nesting deeper than the depth bound", func(t *testing.T) {
		// Nothing but nested indefinite constructors: each costs one stack frame in readEoc,
		// and the nesting is the sender's to choose. A few bytes per level, so a small message
		// exhausts the stack of whichever goroutine is decoding — a delivery or signalling
		// goroutine, whose panic takes the network function with it.
		data := make([]byte, 0, 2*(maxIndefiniteDepth+64))
		for range maxIndefiniteDepth + 64 {
			data = append(data, 0x30, 0x80)
		}

		var v struct{}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("decoding deeply nested indefinite lengths panicked: %v — a sender chooses "+
					"the nesting, so this must be refused rather than fatal", r)
			}
		}()
		_, err := Decode(data, &v)
		if err == nil {
			t.Fatal("indefinite-length nesting past the depth bound was accepted")
		}
		// As above: an unbounded decoder also fails here, by exhausting the message rather
		// than by refusing the nesting. Only the depth bound says so.
		if !strings.Contains(err.Error(), "maximum depth") {
			t.Errorf("refused with %q, want a refusal naming the depth bound", err)
		}
	})

	t.Run("content larger than the cumulative budget", func(t *testing.T) {
		// The budget is what stops a sender setting the cost by *volume* rather than by a
		// declared length: an indefinite construct buffers until its end-of-contents marker,
		// so without a ceiling the buffer grows with whatever arrives.
		//
		// Driven with a lowered budget, because proving it at the real ceiling means feeding
		// sixteen megabytes of conformant BER through the decoder — and a test that expensive
		// is a test that gets skipped.
		restore := indefiniteBudget
		indefiniteBudget = 32
		t.Cleanup(func() { indefiniteBudget = restore })

		var data []byte
		data = append(data, 0x30, 0x80) // SEQUENCE, indefinite
		for range 20 {
			// Small, well-formed children whose total exceeds the budget: no single one is
			// over the ceiling, which is exactly the case a per-element check misses.
			data = append(data, 0x04, 0x04, 0xde, 0xad, 0xbe, 0xef)
		}
		data = append(data, 0x00, 0x00)

		var v struct{}
		_, err := Decode(data, &v)
		if err == nil {
			t.Fatal("an indefinite-length construct whose content exceeded the budget was accepted")
		}
		if !strings.Contains(err.Error(), "exceeds maximum") {
			t.Errorf("refused with %q, want a refusal naming the budget", err)
		}
	})

	t.Run("an ordinary indefinite construct still decodes", func(t *testing.T) {
		// The bound must not be a way of refusing the encoding: BER's indefinite form is
		// legitimate, and a peer may send it.
		//
		// SEQUENCE (indefinite) { INTEGER 1 } — the shape a conformant sender produces.
		data := []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00}

		var v struct {
			N int
		}
		if _, err := Decode(data, &v); err != nil {
			t.Errorf("a conformant indefinite-length element was refused: %v", err)
		}
		if v.N != 1 {
			t.Errorf("decoded N = %d, want 1", v.N)
		}
	})
}
