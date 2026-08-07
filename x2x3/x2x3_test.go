// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x2x3

import (
	"bytes"
	"errors"
	"testing"
)

// Fixed XID and correlation identifier, for deterministic vectors.
var (
	sampleXID = [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	sampleCID = [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
)

// TestMarshalGolden pins the exact byte layout against a hand-derived vector so
// any drift from the TS 103 221-2 / sipgate wire format is caught.
func TestMarshalGolden(t *testing.T) {
	p := &PDU{
		Type:          PDUTypeX2,
		PayloadFormat: PayloadFormat3GPP33128,
		Direction:     DirectionFromTarget,
		XID:           sampleXID,
		CorrelationID: sampleCID,
		Payload:       []byte("hi"),
	}
	got, err := p.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	want := []byte{
		0x00, 0x05, // version 0.5
		0x00, 0x01, // PDU type = X2
		0x00, 0x00, 0x00, 0x28, // header length = 40
		0x00, 0x00, 0x00, 0x02, // payload length = 2
		0x00, 0x02, // payload format = 3GPP 33.128
		0x00, 0x03, // direction = from target
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, // XID
		1, 2, 3, 4, 5, 6, 7, 8, // correlation ID
		'h', 'i', // payload
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("golden mismatch\n got: % x\nwant: % x", got, want)
	}
}

func TestRoundTrip(t *testing.T) {
	orig := &PDU{
		Type:          PDUTypeX3,
		PayloadFormat: PayloadFormatIPv4,
		Direction:     DirectionToTarget,
		XID:           sampleXID,
		CorrelationID: sampleCID,
		Attributes: []TLV{
			{Type: 1, Value: []byte{0xde, 0xad}},
			{Type: 7, Value: []byte("beef")},
		},
		Payload: []byte{0x45, 0x00, 0x00, 0x1c}, // looks like an IPv4 header start
	}
	enc, err := orig.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	dec, n, err := Unmarshal(enc)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if n != len(enc) {
		t.Errorf("consumed %d bytes, want %d", n, len(enc))
	}
	if dec.Type != orig.Type || dec.PayloadFormat != orig.PayloadFormat ||
		dec.Direction != orig.Direction || dec.XID != orig.XID || dec.CorrelationID != orig.CorrelationID {
		t.Errorf("header mismatch: %+v vs %+v", dec, orig)
	}
	if !bytes.Equal(dec.Payload, orig.Payload) {
		t.Errorf("payload mismatch: % x vs % x", dec.Payload, orig.Payload)
	}
	if len(dec.Attributes) != 2 || dec.Attributes[0].Type != 1 ||
		!bytes.Equal(dec.Attributes[1].Value, []byte("beef")) {
		t.Errorf("attributes mismatch: %+v", dec.Attributes)
	}
}

func TestUnmarshalIncomplete(t *testing.T) {
	//nolint:errcheck // test
	full, _ := (&PDU{Type: PDUTypeX2, PayloadFormat: PayloadFormat3GPP33128, Payload: []byte("payload")}).Marshal()
	for _, n := range []int{0, 5, 11, len(full) - 1} {
		if _, _, err := Unmarshal(full[:n]); !errors.Is(err, ErrIncomplete) {
			t.Errorf("Unmarshal(%d bytes) err = %v, want ErrIncomplete", n, err)
		}
	}
	if _, consumed, err := Unmarshal(full); err != nil || consumed != len(full) {
		t.Errorf("Unmarshal(full) = %d, %v; want %d, nil", consumed, err, len(full))
	}
}

func TestRejectsBadVersionAndFormat(t *testing.T) {
	// Bad version on the wire.
	//nolint:errcheck // test
	b, _ := (&PDU{Type: PDUTypeX2, PayloadFormat: PayloadFormat3GPP33128}).Marshal()
	b[0] = 9 // corrupt major version
	if _, _, err := Unmarshal(b); err == nil {
		t.Error("Unmarshal accepted a bad major version")
	}

	// GTP-U is not allowed on X2 (it is X3-only) — must be rejected on encode.
	if _, err := (&PDU{Type: PDUTypeX2, PayloadFormat: PayloadFormatGTPU}).Marshal(); err == nil {
		t.Error("Marshal accepted GTP-U payload on an X2 PDU")
	}
	// IPv4 is X3-allowed — must succeed.
	if _, err := (&PDU{Type: PDUTypeX3, PayloadFormat: PayloadFormatIPv4}).Marshal(); err != nil {
		t.Errorf("Marshal rejected a valid X3 IPv4 PDU: %v", err)
	}
}
