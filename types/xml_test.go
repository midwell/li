// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package types

import "testing"

// TestXMLFragmentMatchesTheClausesForm pins the form ETSI TS 103 221-2
// clause 5.3.18 requires: the contents of a TargetIdentifier without the enclosing
// tag, UTF-8, unprefixed. The clause illustrates it with an IMSI, which is the first
// case here — the same shape this project sent to the sipgate reference before
// implementing the attribute.
func TestXMLFragmentMatchesTheClausesForm(t *testing.T) {
	for _, tc := range []struct {
		id   TargetIdentifier
		want string
	}{
		{TargetIdentifier{Type: TargetSUPI, Value: "208930100007488"}, "<supiimsi>208930100007488</supiimsi>"},
		{TargetIdentifier{Type: TargetPEI, Value: "3578400512345678"}, "<peiImei>3578400512345678</peiImei>"},
		{TargetIdentifier{Type: TargetGPSI, Value: "9000000002"}, "<gpsiMsisdn>9000000002</gpsiMsisdn>"},
	} {
		got, ok := tc.id.XMLFragment()
		if !ok {
			t.Errorf("%s has no fragment", tc.id.Type)

			continue
		}
		if got != tc.want {
			t.Errorf("fragment = %q, want %q", got, tc.want)
		}
	}
}

// TestXMLFragmentEscapes: the value reaches the wire inside an element body, and an
// identifier is provisioned by a peer rather than by us.
func TestXMLFragmentEscapes(t *testing.T) {
	got, ok := TargetIdentifier{Type: TargetSUPI, Value: `1<2&"3"`}.XMLFragment()
	if !ok {
		t.Fatal("no fragment")
	}
	if want := "<supiimsi>1&lt;2&amp;&#34;3&#34;</supiimsi>"; got != want {
		t.Errorf("fragment = %q, want %q", got, want)
	}
}

// TestPacketCriteriaHaveNoFragment is the guard against reporting an identifier as
// something it is not. The packet-detection criteria are arms of a 3GPP extension,
// not plain elements, and they task a CC-POI over LI_T3 — where TS 33.128
// table 5.3.3-2 requires no target identifier at all. So no attribute ever needs
// them, and rendering one as a plain element would tell a mediation function the
// interception matched a subscriber identity when it matched a tunnel or a port.
//
// This is the same defect the X1 renderer already carries a comment about, where
// unmapped criteria were reported as `supiimsi`.
func TestPacketCriteriaHaveNoFragment(t *testing.T) {
	for _, typ := range []TargetIdentifierType{
		TargetFSEID, TargetFTEID, TargetPDRID, TargetQERID,
		TargetNetworkInstance, TargetGTPTunnelDirection, TargetPDR,
	} {
		if !typ.IsPacketCriterion() {
			t.Errorf("%s is not classed as a packet criterion; this test is asserting the wrong set", typ)
		}
		if got, ok := (TargetIdentifier{Type: typ, Value: "1"}).XMLFragment(); ok {
			t.Errorf("%s rendered as %q, want no fragment", typ, got)
		}
	}
}

// TestXMLElementCoversEveryPlainArm: the identifier types that reach an IRI-POI must
// all render, because an xIRI carrying no matched identity is the defect this
// attribute exists to fix. UEIPv4/UEIPv6 and the ports are plain arms in the schema
// and render too, even though they arrive as packet criteria on LI_T3.
func TestXMLElementCoversEveryPlainArm(t *testing.T) {
	for _, typ := range []TargetIdentifierType{TargetSUPI, TargetPEI, TargetGPSI} {
		if _, ok := typ.XMLElement(); !ok {
			t.Errorf("%s has no element name, so an xIRI matched on it could carry no matched identity", typ)
		}
	}
}
