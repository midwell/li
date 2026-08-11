// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package types

import "testing"

// Every criterion TS 33.128 table 6.2.3-7 requires must be a distinct type that
// survives a round trip through a task, and must be distinguishable from the
// PFCP Session ID that was the only one supported before. A duplicated constant
// value would silently conflate two criteria and intercept the wrong traffic.
func TestTableCriteriaAreDistinct(t *testing.T) {
	criteria := []TargetIdentifierType{
		TargetFTEID, TargetUEIPv4, TargetUEIPv6, TargetTCPPort, TargetUDPPort,
		TargetPDRID, TargetQERID, TargetNetworkInstance, TargetGTPTunnelDirection,
		TargetPDR, TargetFSEID,
	}
	if len(criteria) != 11 {
		t.Fatalf("expected the nine table types plus the two address forms, got %d", len(criteria))
	}

	seen := make(map[TargetIdentifierType]bool, len(criteria))
	for _, c := range criteria {
		if c == "" {
			t.Error("a criterion has an empty value, so it cannot be distinguished on the wire")
		}
		if seen[c] {
			t.Errorf("criterion %q is duplicated: two criteria sharing a value would select each other's traffic", c)
		}
		seen[c] = true

		if !c.IsPacketCriterion() {
			t.Errorf("%q names traffic and must be usable on LI_T3", c)
		}
	}
}

// Subscriber identifiers must not be mistaken for packet-detection criteria: the
// CC-POI has no way to evaluate them, and the IRI-POIs must keep matching on them.
func TestSubscriberIdentifiersAreNotPacketCriteria(t *testing.T) {
	for _, c := range []TargetIdentifierType{TargetSUPI, TargetPEI, TargetGPSI} {
		if c.IsPacketCriterion() {
			t.Errorf("%q is a subscriber identifier, not a packet-detection criterion", c)
		}
	}
}

func TestCriterionRoundTripsThroughATargetIdentifier(t *testing.T) {
	for _, tc := range []struct {
		typ TargetIdentifierType
		val string
	}{
		{TargetFTEID, "1234@192.0.2.1"},
		{TargetUEIPv4, "192.0.2.50"},
		{TargetUEIPv6, "2001:db8::1"},
		{TargetTCPPort, "443"},
		{TargetUDPPort, "2152"},
		{TargetPDRID, "7"},
		{TargetQERID, "3"},
		{TargetNetworkInstance, "internet"},
		{TargetGTPTunnelDirection, "Outbound"}, // the schema enumerates Outbound/Inbound, not uplink/downlink
		{TargetPDR, "0a0b0c"},
	} {
		id := TargetIdentifier{Type: tc.typ, Value: tc.val}
		if id.Type != tc.typ || id.Value != tc.val {
			t.Errorf("%q did not round trip: got %+v", tc.typ, id)
		}
	}
}
