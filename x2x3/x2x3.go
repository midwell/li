// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

// Package x2x3 encodes and decodes the ETSI TS 103 221-2 X2/X3 PDU used to
// deliver xIRI (X2) and xCC (X3) from a Point of Interception to a Mediation
// and Delivery Function. The wire layout (all multi-byte fields big-endian) is:
//
//	off 0      major version (1, = 0)
//	off 1      minor version (1, = 5)
//	off 2-3    PDU type (2)
//	off 4-7    header length (4, = 40 + conditional attributes)
//	off 8-11   payload length (4)
//	off 12-13  payload format (2)
//	off 14-15  payload direction (2)
//	off 16-31  XID (16, a UUID)
//	off 32-39  correlation ID (8)
//	off 40..   conditional attribute fields: [type(2)|length(2)|value]*
//	then       payload
//
// The layout and validation rules were read against ETSI TS 103 221-2 V1.10.1
// (2026-03) field by field; CONFORMANCE.md in this directory records the
// disposition of every header field, PDU type, conditional attribute and payload
// format the specification defines, including what this package does not
// implement. Read it before assuming a field is handled — that document, and
// this comment, are claims rather than evidence, and the gaps it lists were
// invisible for as long as the comment here asserted conformance without naming
// a revision.
//
// Interoperability against the independent sipgate li-lib implementation
// exercises the parts both sides emit, which is why the gaps are all in fields
// neither implementation ever sends.
package x2x3

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The Version field (TS 103 221-2 clause 5.2.1) asserts which revision of the
// specification a PDU was created against, so it is a conformance claim and not
// a build stamp. Value 5 is what V1.6.1 through V1.9.1 define; V1.10.1 raised it
// to 6.
//
// It stays at 5 deliberately. Raising it to 6 would claim conformance to V1.10.1
// while the keepalive mechanism of clause 6.2.4 is unimplemented — see the gaps
// in CONFORMANCE.md — which would hide the gap rather than close it. The bump
// belongs with the change that implements keepalive.
const (
	MajorVersion          = 0
	MinorVersion          = 5
	MandatoryHeaderLength = 40
	CorrelationIDLength   = 8
	xidLength             = 16
)

// ErrIncomplete is returned by Unmarshal when the buffer does not yet hold a
// full PDU (header length + payload length). A stream reader should wait for
// more bytes and retry.
var ErrIncomplete = errors.New("x2x3: incomplete PDU")

// PDUType identifies the PDU kind (TS 103 221-2).
type PDUType uint16

const (
	PDUTypeX2           PDUType = 1
	PDUTypeX3           PDUType = 2
	PDUTypeKeepalive    PDUType = 3
	PDUTypeKeepaliveAck PDUType = 4
)

// PayloadFormat identifies the encoding of the payload.
type PayloadFormat uint16

const (
	PayloadFormatReserved     PayloadFormat = 0
	PayloadFormatETSI102232_1 PayloadFormat = 1
	PayloadFormat3GPP33128    PayloadFormat = 2 // xIRI / xCC defined by TS 33.128
	PayloadFormat3GPP33108    PayloadFormat = 3
	PayloadFormatProprietary  PayloadFormat = 4
	PayloadFormatIPv4         PayloadFormat = 5 // decapsulated inner IPv4 (X3 CC)
	PayloadFormatIPv6         PayloadFormat = 6 // decapsulated inner IPv6 (X3 CC)
	PayloadFormatEthernet     PayloadFormat = 7
	PayloadFormatRTP          PayloadFormat = 8
	PayloadFormatSIP          PayloadFormat = 9
	PayloadFormatDHCP         PayloadFormat = 10
	PayloadFormatRADIUS       PayloadFormat = 11
	PayloadFormatGTPU         PayloadFormat = 12
	PayloadFormatMSRP         PayloadFormat = 13
	PayloadFormat33108EPSIRI  PayloadFormat = 14
	PayloadFormatMIME         PayloadFormat = 15
	PayloadFormatUnstructured PayloadFormat = 16
	PayloadFormatPSPDUPayload PayloadFormat = 17 // ETSI TS 102 232-1 PS-PDU.Payload, added in V1.8.1
)

// payloadFormatRules records whether each format is permitted on X2 and X3
// respectively, transcribed from TS 103 221-2 table 5.4.1-1.
//
// TRANSCRIBED FROM V1.10.1 (2026-03). Restate the revision whenever this table
// is updated: the table is not checked against any published source, so without
// a version a stale copy and a current one look identical. That is exactly how
// value 17 stayed missing for three revisions. CONFORMANCE.md carries the
// per-value disposition, and x2x3_test.go asserts this whole table.
var payloadFormatRules = map[PayloadFormat][2]bool{
	PayloadFormatReserved:     {false, false},
	PayloadFormatETSI102232_1: {true, true},
	PayloadFormat3GPP33128:    {true, true},
	PayloadFormat3GPP33108:    {true, true},
	PayloadFormatProprietary:  {true, true},
	PayloadFormatIPv4:         {true, true},
	PayloadFormatIPv6:         {true, true},
	PayloadFormatEthernet:     {false, true},
	PayloadFormatRTP:          {false, true},
	PayloadFormatSIP:          {true, false},
	PayloadFormatDHCP:         {true, false},
	PayloadFormatRADIUS:       {true, false},
	PayloadFormatGTPU:         {false, true},
	PayloadFormatMSRP:         {false, true},
	PayloadFormat33108EPSIRI:  {true, false},
	PayloadFormatMIME:         {true, true},
	PayloadFormatUnstructured: {false, true},
	PayloadFormatPSPDUPayload: {true, true},
}

func (f PayloadFormat) allowedOn(t PDUType) bool {
	r, ok := payloadFormatRules[f]
	if !ok {
		return false
	}
	switch t {
	case PDUTypeX2:
		return r[0]
	case PDUTypeX3:
		return r[1]
	default:
		return true // keepalive PDUs do not carry a checked payload
	}
}

// PayloadDirection indicates the direction of the intercepted communication.
type PayloadDirection uint16

const (
	DirectionReservedKeepalive PayloadDirection = 0
	DirectionUnknown           PayloadDirection = 1
	DirectionToTarget          PayloadDirection = 2
	DirectionFromTarget        PayloadDirection = 3
	DirectionMultiple          PayloadDirection = 4
	DirectionNotApplicable     PayloadDirection = 5
)

// TLV is a conditional attribute field carried in the header (type, value); the
// 2-byte length is computed on the wire.
type TLV struct {
	Type  uint16
	Value []byte
}

// PDU is a decoded X2/X3 PDU. Header length and payload length are derived on
// encode and validated on decode, so they are not stored.
type PDU struct {
	Type          PDUType
	PayloadFormat PayloadFormat
	Direction     PayloadDirection
	XID           [xidLength]byte
	CorrelationID [CorrelationIDLength]byte
	Attributes    []TLV
	Payload       []byte
}

func (p *PDU) validate() error {
	if (p.Type == PDUTypeX2 || p.Type == PDUTypeX3) && !p.PayloadFormat.allowedOn(p.Type) {
		return fmt.Errorf("x2x3: payload format %d not allowed on PDU type %d", p.PayloadFormat, p.Type)
	}
	return nil
}

// Marshal encodes the PDU to its TS 103 221-2 wire form.
func (p *PDU) Marshal() ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}

	// Size the attribute region before allocating, so the header is written once
	// into a buffer of its final length. Building the TLVs into a separate slice
	// first would cost an allocation per PDU, which on X3 is an allocation per
	// duplicated packet.
	attrsLen := 0
	for _, t := range p.Attributes {
		if len(t.Value) > 0xFFFF {
			return nil, fmt.Errorf("x2x3: TLV type %d value too long (%d bytes)", t.Type, len(t.Value))
		}
		attrsLen += 4 + len(t.Value)
	}

	headerLen := MandatoryHeaderLength + attrsLen
	out := make([]byte, headerLen, headerLen+len(p.Payload))
	out[0] = MajorVersion
	out[1] = MinorVersion
	binary.BigEndian.PutUint16(out[2:4], uint16(p.Type))
	binary.BigEndian.PutUint32(out[4:8], uint32(headerLen))
	binary.BigEndian.PutUint32(out[8:12], uint32(len(p.Payload)))
	binary.BigEndian.PutUint16(out[12:14], uint16(p.PayloadFormat))
	binary.BigEndian.PutUint16(out[14:16], uint16(p.Direction))
	copy(out[16:32], p.XID[:])
	copy(out[32:40], p.CorrelationID[:])

	off := MandatoryHeaderLength
	for _, t := range p.Attributes {
		binary.BigEndian.PutUint16(out[off:off+2], t.Type)
		binary.BigEndian.PutUint16(out[off+2:off+4], uint16(len(t.Value)))
		off += 4
		off += copy(out[off:], t.Value)
	}

	out = append(out, p.Payload...)
	return out, nil
}

// Unmarshal decodes a single PDU from the front of b, returning the PDU and the
// number of bytes it consumed (so callers can frame a stream). It returns
// ErrIncomplete if b does not yet hold a complete PDU.
func Unmarshal(b []byte) (*PDU, int, error) {
	// Need at least version(2)+type(2)+headerLen(4)+payloadLen(4) to size the PDU.
	if len(b) < 12 {
		return nil, 0, ErrIncomplete
	}
	headerLen := binary.BigEndian.Uint32(b[4:8])
	payloadLen := binary.BigEndian.Uint32(b[8:12])
	if headerLen < MandatoryHeaderLength {
		return nil, 0, fmt.Errorf("x2x3: header length %d below mandatory %d", headerLen, MandatoryHeaderLength)
	}
	if uint64(headerLen)+uint64(payloadLen) > uint64(len(b)) {
		return nil, 0, ErrIncomplete
	}
	total := int(headerLen) + int(payloadLen) // safe: the uint64 check above bounds the sum by len(b) ≤ maxInt
	// TS 103 221-2 clause 5.2.1 defines the major version as incrementing on a
	// backwards-incompatible change and the minor on a backwards-compatible
	// addition, so a peer ahead of us on the minor number is required to remain
	// decodable: it can only have added a PDU type, direction, conditional
	// attribute or payload format, none of which changes the layout parsed here.
	// Rejecting that peer outright — which this did — would refuse a conformant
	// MDF running a newer revision than ours.
	// A differing minor in either direction stays decodable: a lower one uses a
	// subset of what we know, a higher one adds values that do not move any field.
	if b[0] != MajorVersion {
		return nil, 0, fmt.Errorf("x2x3: unsupported major version %d (this implementation speaks %d.x)", b[0], MajorVersion)
	}

	p := &PDU{
		Type:          PDUType(binary.BigEndian.Uint16(b[2:4])),
		PayloadFormat: PayloadFormat(binary.BigEndian.Uint16(b[12:14])),
		Direction:     PayloadDirection(binary.BigEndian.Uint16(b[14:16])),
	}
	copy(p.XID[:], b[16:32])
	copy(p.CorrelationID[:], b[32:40])

	attrs, err := parseTLVs(b[MandatoryHeaderLength:headerLen])
	if err != nil {
		return nil, 0, err
	}
	p.Attributes = attrs
	p.Payload = append([]byte(nil), b[headerLen:total]...)

	if err := p.validate(); err != nil {
		return nil, 0, err
	}
	return p, total, nil
}

func parseTLVs(b []byte) ([]TLV, error) {
	var out []TLV
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, errors.New("x2x3: truncated TLV header")
		}
		typ := binary.BigEndian.Uint16(b[0:2])
		n := int(binary.BigEndian.Uint16(b[2:4]))
		if len(b) < 4+n {
			return nil, errors.New("x2x3: truncated TLV value")
		}
		out = append(out, TLV{Type: typ, Value: append([]byte(nil), b[4:4+n]...)})
		b = b[4+n:]
	}
	return out, nil
}
