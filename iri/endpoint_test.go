// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package iri

import (
	"bytes"
	"net"
	"testing"
)

// TestUEEndpointDiscriminatesAddressFamily covers the To4-before-To16 ordering.
// net.IP holds an IPv4 address in 16-byte 4-in-6 form, so To16 answers for both
// families; asking To4 first is what keeps a v4 address from being reported as
// IPv6 with a ::ffff: prefix an agency would have to unpick.
func TestUEEndpointDiscriminatesAddressFamily(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want any
	}{
		{"dotted quad", "10.45.0.2", IPv4Address{10, 45, 0, 2}},
		{"v4 in v6 form", "::ffff:10.45.0.2", IPv4Address{10, 45, 0, 2}},
		{"v6", "2001:db8::1", IPv6Address(net.ParseIP("2001:db8::1").To16())},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := UEEndpoint(net.ParseIP(tc.ip))
			if len(got) != 1 {
				t.Fatalf("got %d entries, want 1: %#v", len(got), got)
			}
			switch want := tc.want.(type) {
			case IPv4Address:
				v4, ok := got[0].(IPv4Address)
				if !ok {
					t.Fatalf("got %T, want IPv4Address", got[0])
				}
				if !bytes.Equal(v4, want) {
					t.Errorf("got % x, want % x", v4, want)
				}
				if len(v4) != 4 {
					t.Errorf("IPv4Address is %d bytes, want the SIZE(4) form", len(v4))
				}
			case IPv6Address:
				v6, ok := got[0].(IPv6Address)
				if !ok {
					t.Fatalf("got %T, want IPv6Address", got[0])
				}
				if !bytes.Equal(v6, want) {
					t.Errorf("got % x, want % x", v6, want)
				}
				if len(v6) != 16 {
					t.Errorf("IPv6Address is %d bytes, want the SIZE(16) form", len(v6))
				}
			}
		})
	}
}

// TestUEEndpointAbsentAddress: no address means no list, not an empty one.
func TestUEEndpointAbsentAddress(t *testing.T) {
	if got := UEEndpoint(nil); got != nil {
		t.Errorf("UEEndpoint(nil) = %#v, want nil", got)
	}
}

// TestUEEndpointRoundTripsEveryAlternative checks each arm of the CHOICE survives
// encode and decode inside a real record with its concrete type intact.
func TestUEEndpointRoundTripsEveryAlternative(t *testing.T) {
	ctx := NewContext()
	tests := []struct {
		name string
		addr any
	}{
		{"ipv4", IPv4Address{10, 45, 0, 2}},
		{"ipv6", IPv6Address(net.ParseIP("2001:db8::1").To16())},
		{"mac", MACAddress{0x02, 0x42, 0xac, 0x11, 0x00, 0x02}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := SMFStartOfInterceptionWithEstablishedPDUSession{
				SUPI:           IMSI("262019876543210"),
				PDUSessionID:   5,
				GTPTunnelID:    FTEID{TEID: 1, IPv4Address: []byte{10, 20, 30, 40}},
				PDUSessionType: PDUSessionTypeIPv4,
				UEEndpoint:     []any{tc.addr},
				DNN:            DNN("internet"),
				RequestType:    SMRequestExisting,
			}
			der, err := EncodeXIRI(ctx, in)
			if err != nil {
				t.Fatalf("EncodeXIRI: %v", err)
			}
			var got XIRIPayload
			if _, err := ctx.Decode(der, &got); err != nil {
				t.Fatalf("Decode: %v", err)
			}
			rec, ok := got.Event.(SMFStartOfInterceptionWithEstablishedPDUSession)
			if !ok {
				t.Fatalf("decoded as %T", got.Event)
			}
			if len(rec.UEEndpoint) != 1 {
				t.Fatalf("uEEndpoint has %d entries, want 1", len(rec.UEEndpoint))
			}
			if gotType, wantType := typeName(rec.UEEndpoint[0]), typeName(tc.addr); gotType != wantType {
				t.Errorf("alternative decoded as %s, want %s", gotType, wantType)
			}
		})
	}
}

func typeName(v any) string {
	switch v.(type) {
	case IPv4Address:
		return "IPv4Address"
	case IPv6Address:
		return "IPv6Address"
	case MACAddress:
		return "MACAddress"
	default:
		return "unknown"
	}
}

// TestUEEndpointCarriesMultipleAddresses: the field is a SEQUENCE OF, so a
// dual-stack session can report both families. The SMF only tracks one address
// today, but the record shape is the specification's, not the SMF's.
func TestUEEndpointCarriesMultipleAddresses(t *testing.T) {
	ctx := NewContext()
	in := SMFStartOfInterceptionWithEstablishedPDUSession{
		SUPI:           IMSI("262019876543210"),
		PDUSessionID:   5,
		PDUSessionType: PDUSessionTypeIPv4v6,
		UEEndpoint: []any{
			IPv4Address{10, 45, 0, 2},
			IPv6Address(net.ParseIP("2001:db8::1").To16()),
		},
		DNN:         DNN("internet"),
		RequestType: SMRequestExisting,
	}
	der, err := EncodeXIRI(ctx, in)
	if err != nil {
		t.Fatalf("EncodeXIRI: %v", err)
	}
	var got XIRIPayload
	if _, err := ctx.Decode(der, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	rec := got.Event.(SMFStartOfInterceptionWithEstablishedPDUSession) //nolint:errcheck // asserted above by construction
	if len(rec.UEEndpoint) != 2 {
		t.Fatalf("uEEndpoint has %d entries, want 2", len(rec.UEEndpoint))
	}
	if typeName(rec.UEEndpoint[0]) != "IPv4Address" || typeName(rec.UEEndpoint[1]) != "IPv6Address" {
		t.Errorf("order not preserved: %s then %s", typeName(rec.UEEndpoint[0]), typeName(rec.UEEndpoint[1]))
	}
}

// TestStartOfInterceptionRefusesEmptyEndpoint is the spec rule made enforceable:
// uEEndpoint is mandatory in this record and an empty list positively asserts the
// session has no endpoint address, which is never true of an established session.
// It encodes cleanly and no receiver rejects it, so nothing downstream would catch
// this — which is exactly why the refusal lives on the encode path.
func TestStartOfInterceptionRefusesEmptyEndpoint(t *testing.T) {
	ctx := NewContext()
	rec := SMFStartOfInterceptionWithEstablishedPDUSession{
		SUPI:           IMSI("262019876543210"),
		PDUSessionID:   5,
		PDUSessionType: PDUSessionTypeIPv4,
		DNN:            DNN("internet"),
		RequestType:    SMRequestExisting,
	}
	if _, err := EncodeXIRI(ctx, rec); err == nil {
		t.Fatal("encoded a start-of-interception record with an empty uEEndpoint; want an error")
	}
}

// TestEstablishmentOmitsAbsentEndpoint: uEEndpoint is OPTIONAL in the
// establishment record, so an absent address must omit the field rather than emit
// it empty — and the record must still encode, unlike the mandatory case above.
func TestEstablishmentOmitsAbsentEndpoint(t *testing.T) {
	ctx := NewContext()
	base := SMFPDUSessionEstablishment{
		SUPI:           IMSI("262019876543210"),
		PDUSessionID:   5,
		GTPTunnelID:    FTEID{TEID: 1, IPv4Address: []byte{10, 20, 30, 40}},
		PDUSessionType: PDUSessionTypeIPv4,
		DNN:            DNN("internet"),
		RequestType:    SMRequestInitial,
	}
	without, err := EncodeXIRI(ctx, base)
	if err != nil {
		t.Fatalf("EncodeXIRI without endpoint: %v", err)
	}

	withAddr := base
	withAddr.UEEndpoint = UEEndpoint(net.ParseIP("10.45.0.2"))
	with, err := EncodeXIRI(ctx, withAddr)
	if err != nil {
		t.Fatalf("EncodeXIRI with endpoint: %v", err)
	}

	if len(without) >= len(with) {
		t.Errorf("absent endpoint encoding (%d bytes) is not smaller than present (%d) — "+
			"the optional field is being emitted empty rather than omitted", len(without), len(with))
	}

	var got XIRIPayload
	if _, err := ctx.Decode(with, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	rec := got.Event.(SMFPDUSessionEstablishment) //nolint:errcheck // asserted by construction
	if len(rec.UEEndpoint) != 1 {
		t.Fatalf("uEEndpoint has %d entries, want 1", len(rec.UEEndpoint))
	}
	v4, ok := rec.UEEndpoint[0].(IPv4Address)
	if !ok || !bytes.Equal(v4, IPv4Address{10, 45, 0, 2}) {
		t.Errorf("uEEndpoint[0] = %#v, want IPv4Address 10.45.0.2", rec.UEEndpoint[0])
	}
}

// TestEndpointIsNotTheTunnelEndpoint guards the distinction the whole change is
// about: gTPTunnelID carries the serving UPF's address and uEEndpoint carries the
// subject's. Reporting one as the other would answer a question nobody asked.
func TestEndpointIsNotTheTunnelEndpoint(t *testing.T) {
	ctx := NewContext()
	rec := SMFPDUSessionEstablishment{
		SUPI:           IMSI("262019876543210"),
		PDUSessionID:   5,
		GTPTunnelID:    FTEID{TEID: 1, IPv4Address: []byte{192, 168, 252, 3}}, // UPF N3
		PDUSessionType: PDUSessionTypeIPv4,
		UEEndpoint:     UEEndpoint(net.ParseIP("10.45.0.2")), // the subject
		DNN:            DNN("internet"),
		RequestType:    SMRequestInitial,
	}
	der, err := EncodeXIRI(ctx, rec)
	if err != nil {
		t.Fatalf("EncodeXIRI: %v", err)
	}
	var got XIRIPayload
	if _, err := ctx.Decode(der, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	out := got.Event.(SMFPDUSessionEstablishment) //nolint:errcheck // asserted by construction
	if !bytes.Equal(out.GTPTunnelID.IPv4Address, []byte{192, 168, 252, 3}) {
		t.Errorf("gTPTunnelID address = % x, want c0 a8 fc 03", out.GTPTunnelID.IPv4Address)
	}
	v4, _ := out.UEEndpoint[0].(IPv4Address)
	if !bytes.Equal(v4, IPv4Address{10, 45, 0, 2}) {
		t.Errorf("uEEndpoint = % x, want 0a 2d 00 02", v4)
	}
	if bytes.Equal(v4, out.GTPTunnelID.IPv4Address) {
		t.Error("uEEndpoint and gTPTunnelID carry the same address; they are different endpoints")
	}
}

// TestEstablishmentRefusesPresentButEmptyEndpoint closes the other half of the
// no-empty-list rule. uEEndpoint is OPTIONAL on this record, so a nil slice is
// correct and simply omits the field — but a non-nil empty slice is not omitted
// (the codec's isEmpty compares against the zero value, and an empty slice is
// not nil), so it would be emitted as a present empty SEQUENCE: schema-valid,
// unrejectable downstream, and asserting the session has no endpoint address.
//
// No caller produces that shape today; UEEndpoint returns nil or one entry. The
// guard is here because the rule was deliberately placed on the encode path both
// record builders share, and enforcing it for only one of the two records leaves
// it one careless edit from being false again.
func TestEstablishmentRefusesPresentButEmptyEndpoint(t *testing.T) {
	ctx := NewContext()
	base := SMFPDUSessionEstablishment{
		SUPI:           IMSI("262019876543210"),
		PDUSessionID:   5,
		GTPTunnelID:    FTEID{TEID: 1, IPv4Address: []byte{10, 20, 30, 40}},
		PDUSessionType: PDUSessionTypeIPv4,
		DNN:            DNN("internet"),
		RequestType:    SMRequestInitial,
	}

	// nil: the field is optional and absent, which is correct.
	if _, err := EncodeXIRI(ctx, base); err != nil {
		t.Fatalf("absent (nil) endpoint must still encode: %v", err)
	}

	// present but empty: refused.
	empty := base
	empty.UEEndpoint = []any{}
	if _, err := EncodeXIRI(ctx, empty); err == nil {
		t.Error("encoded an establishment record with a present but empty uEEndpoint; want a refusal")
	}

	// populated: encodes.
	full := base
	full.UEEndpoint = UEEndpoint(net.ParseIP("10.45.0.2"))
	if _, err := EncodeXIRI(ctx, full); err != nil {
		t.Errorf("populated endpoint must encode: %v", err)
	}
}
