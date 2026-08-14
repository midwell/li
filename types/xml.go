// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"bytes"
	"encoding/xml"
)

// XMLElement gives the ETSI TS 103 221-1 element name for an identifier type that
// the schema carries as a plain `TargetIdentifier` arm. The names are the schema's,
// which are lowercase-initial — table 6.2.1.2-2 names the *types* (IPv4Address,
// TCPPort) and the elements are spelled differently, so the two are not
// interchangeable.
//
// It reports false for the packet-detection criteria, which the schema carries in a
// vendor extension rather than as a plain element: those reach a CC-POI over LI_T3
// and belong to X3, where no target identifier is reported.
//
// This lives here, on the leaf package both interfaces already depend on, because two
// interfaces now render these names: the X1 responses that tell an ADMF what tasking
// an element holds, and the X2 conditional attribute that tells a mediation function
// which identity matched. A second copy of the mapping would be free to disagree with
// the first, and nothing would notice.
func (t TargetIdentifierType) XMLElement() (string, bool) {
	switch t {
	case TargetSUPI:
		return "supiimsi", true
	case TargetPEI:
		return "peiImei", true
	case TargetGPSI:
		return "gpsiMsisdn", true
	case TargetUEIPv4:
		return "ipv4Address", true
	case TargetUEIPv6:
		return "ipv6Address", true
	case TargetTCPPort:
		return "tcpPort", true
	case TargetUDPPort:
		return "udpPort", true
	default:
		return "", false
	}
}

// XMLFragment renders this identifier in the form ETSI TS 103 221-2 clause 5.3.18
// requires of the Matched and Other Target Identifier conditional attributes: the
// contents of a TS 103 221-1 `TargetIdentifier` *without* the enclosing tag, encoded
// in UTF-8. The clause's own example is `<imsi>204081234567890</imsi>`.
//
// Unprefixed, deliberately. Inside an X1 document the element names carry the
// prefixes that document binds; lifted into a PDU header the fragment stands alone,
// so a prefix here would be undeclared. The unprefixed form is what the clause
// illustrates and what the sipgate reference accepted when asked directly.
//
// It reports false rather than guessing for an identifier with no plain element —
// the same rule the X1 renderer follows, and for the same reason: an identifier
// reported as nothing is visibly missing, while one reported as something else is
// not.
func (t TargetIdentifier) XMLFragment() (string, bool) {
	el, ok := t.Type.XMLElement()
	if !ok {
		return "", false
	}

	return "<" + el + ">" + escapeXMLText(t.Value) + "</" + el + ">", true
}

// escapeXMLText escapes text for inclusion in an XML element body.
func escapeXMLText(s string) string {
	var b bytes.Buffer
	//nolint:errcheck // writing to a bytes.Buffer cannot fail
	_ = xml.EscapeText(&b, []byte(s))

	return b.String()
}
