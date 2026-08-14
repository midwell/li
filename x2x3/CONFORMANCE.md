<!--
SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
SPDX-License-Identifier: Apache-2.0
-->

# TS 103 221-2 conformance disposition

**Made against ETSI TS 103 221-2 V1.10.1 (2026-03).** Every table and clause number below
refers to that revision. When a newer revision is published, this document is what tells you
whether the code disagrees with the specification or merely predates it — that distinction
is the reason the version is stated at the top rather than left implied.

## What this is, and what it is not

This is a **reading**, not a check. ETSI publishes no machine-readable definition of the
X2/X3 framing: the sole attachment to part 2 is `TS_103_221_02_Configuration.xsd`, which
describes how an X2/X3 interface is *configured* over X1 (keepalive enable and two timers)
and says nothing about the PDU layout. The X1 side of this project can and does verify
itself against a published XSD on every build; nothing equivalent is possible here, so this
document is a per-field disposition maintained by hand and is only as current as its version
stamp.

Two things do provide external validation, and it is worth being precise about what each
covers:

- **Interoperability testing against the independent sipgate li-lib implementation.** This
  catches anything that breaks decode — a wrong offset, a bad length, a mis-ordered field.
  It cannot catch a field or PDU type that *neither* implementation emits, because nothing
  ever exercises it. Every gap recorded below is of that second kind.
- **A table-driven test over the payload format table** (`x2x3_test.go`), which asserts the
  whole of table 5.4.1-1 including the X2/X3 permissions. That is not a check against the
  published source, but it does make the next addition fail a test rather than pass
  unnoticed.

Do not close a question about this package by citing the package comment, or this document,
as evidence of conformance. Both are claims. The specification is the evidence.

## Version field

The Version field (clause 5.2.1) is a claim about which revision of the specification a PDU
was created against. Its value is a 16-bit integer split into an 8-bit major and an 8-bit
minor: the major increments on a backwards-incompatible change to the PDU structure, the
minor on a backwards-compatible addition (a new PDU type, payload direction, conditional
attribute or payload format).

| Specification revision | Version field value |
|---|---|
| V1.6.1 (2022-03) | 5 (major 0, minor 5) |
| V1.7.1 (2024-12) | 5 |
| V1.8.1 (2025-05) | 5 |
| V1.9.1 (2025-08) | 5 |
| V1.10.1 (2026-03) | **6** (major 0, minor 6) |

This table was compiled by reading clause 5.2.1 of each revision, because the change-history
annex flattens ambiguously and invites the conclusion that the value had been static since
2019. It had not; it changed once, in V1.10.1.

**This package emits 5**, which was correct for every revision through V1.9.1. It is
deliberately not raised to 6 while the keepalive mechanism (clause 6.2.4) is unimplemented,
because the field would then assert conformance to a revision this element does not meet.
Raising it belongs with the work that implements keepalive.

**On decode**, a differing minor version is accepted and a differing major version is
rejected, which follows the compatibility rule the clause defines. Note that this package is
write-only in production today — `Unmarshal` is reached only from tests — so decode leniency
matters from the moment anything reads from an X2/X3 socket, which the keepalive
acknowledgement will be the first thing to do.

## Mandatory header fields — table 5.1-1

| Field | Octets | Clause | Disposition |
|---|---|---|---|
| Version | 2 | 5.2.1 | **Emitted and parsed.** See above. |
| PDU Type | 2 | 5.2.2 | **Emitted and parsed.** Only X2 and X3 are ever emitted; see the PDU type table below. |
| Header Length | 4 | 5.2.3 | **Emitted and parsed.** Derived on encode from 40 + the conditional attribute bytes, validated on decode against the mandatory minimum of 40. Not stored on the struct, so it cannot disagree with the bytes. |
| Payload Length | 4 | 5.2.4 | **Emitted and parsed.** Derived on encode, used on decode to frame the stream. Not stored, as above. |
| Payload Format | 2 | 5.2.5 | **Emitted and parsed**, and validated against the PDU type — see table 5.4.1-1 below. |
| Payload Direction | 2 | 5.2.6 | **Emitted and parsed.** All six values are modelled; see the direction table below. |
| XID | 16 | 5.2.7 | **Emitted and parsed.** Correctly implements the ProductID override: the clause requires that when the X1 task carries an optional ProductID, the XID field is populated with it instead of the task's own XID. `types.InterceptTask.DeliveryXID` encodes that rule and all three POIs label product through it. |
| Correlation ID | 8 | 5.2.8 | **Emitted and parsed.** Supplied by the triggering function for triggered tasks and never derived locally; zero when the POI does not correlate the PDU, as the clause requires. |
| Conditional Attribute Fields | variable | 5.3 | **Parsed, never emitted.** See table 5.3.1-2 below — this is the largest gap. |
| Payload | variable | 5.4 | **Emitted and parsed.** |

## PDU types — table 5.2.2-1

| Value | Meaning | Disposition |
|---|---|---|
| 1 | X2 PDU | **Emitted** by the AMF and SMF IRI-POIs. |
| 2 | X3 PDU | **Emitted** by the UPF CC-POI. |
| 3 | Keepalive | **Declared, never emitted — a known gap.** Clause 6.2.4 states that the type shall be supported by POIs and MDFs, and that the POI shall send a Keepalive PDU at least every TIME_P1 (default 60 s). This element sends none. |
| 4 | Keepalive Acknowledgement | **Declared, never read — the same gap.** Clause 6.2.4 has the MDF answer each Keepalive with a matching Sequence Number, and requires the POI to disconnect, reconnect and report an error over X1 if none arrives within TIME_P2 (default 180 s). |

## Payload directions — table 5.2.6-1

All six values are modelled and match the table. Value 0 is reserved for the keepalive
mechanism and is consequently never emitted, for the reason in the PDU type table above.

| Value | Meaning | Modelled as |
|---|---|---|
| 0 | Reserved for the keepalive mechanism | `DirectionReservedKeepalive` |
| 1 | Direction not known to the POI | `DirectionUnknown` |
| 2 | Sent to (received by) the target | `DirectionToTarget` |
| 3 | Sent from the target | `DirectionFromTarget` |
| 4 | Result of data or events in more than one direction | `DirectionMultiple` |
| 5 | Direction not applicable | `DirectionNotApplicable` |

## Conditional attributes — table 5.3.1-2

**None of the 22 defined attribute types is ever emitted.** The TLV mechanism itself is
implemented — `Marshal` writes the type/length/value structure of table 5.3.1-1 and
`Unmarshal` parses it back — but no producer in this project populates `PDU.Attributes`, and
no consumer reads them.

Clause 5.3 makes these attributes something the POI "may provide … as directed by the
relevant LI architecture", and for this project the relevant architecture is 3GPP TS 33.128 —
which directs a great deal. **Six of the 22 are required, and this project emits none of
them.**

TS 33.128 table 5.3.1-2 applies to both LI_X2 and LI_X3 and says the **NFID** "shall be set
to indicate the NF that contains the POI" and the **IPID** "shall be set to indicate the POI
(within the NF) that generated the xIRI". Table 5.3.2-2 adds, for every xIRI on LI_X2,
**Timestamp** ("shall be present and set to the time at which the event occurred"),
**Sequence Number** ("shall be present"), **Matched Target Identifier** ("shall be set to
indicate what target identity was matched") and **Other Target Identifier** ("shall be set
with all other target identities present at the NF"). Table 5.3.3-2 requires Timestamp and
Sequence Number on LI_X3 too, and makes AXRI optional.

So the AMF and SMF IRI-POIs each owe six attributes on every xIRI, and the UPF CC-POI owes
four on every xCC. This is the largest gap this disposition records, and it is sized as its
own change rather than patched here.

| Type | Name | Clause | Disposition |
|---|---|---|---|
| 1 | ETSI TS 102 232-1 defined attribute | 5.3.2 | Absent. Carries an attribute defined by a specification this project does not implement. |
| 2 | 3GPP TS 33.128 defined attribute | 5.3.3 | Absent. **The one most likely to be required**, since TS 33.128 is this project's governing architecture. |
| 3 | 3GPP TS 33.108 defined attribute | 5.3.4 | Absent. TS 33.108 is the EPS-generation interface; not implemented here. |
| 4 | Proprietary attribute | 5.3.5 | Absent by choice. A standardized attribute is preferable and the clause frames this as temporary support. |
| 5 | Domain ID (DID) | 5.3.6 | Absent. TS 33.128 does not require it; the destination is resolved from the X1 task. |
| 6 | Network Function ID (NFID) | 5.3.7 | **Absent and REQUIRED** on X2 and X3 (TS 33.128 table 5.3.1-2, "shall be set"). |
| 7 | Interception Point ID (IPID) | 5.3.8 | **Absent and REQUIRED** on X2 and X3 (table 5.3.1-2, "shall be set"). |
| 8 | Sequence Number | 5.3.9 | **Absent and REQUIRED** on X2 and X3 (tables 5.3.2-2 and 5.3.3-2, "shall be present"). Also a dependency of the keepalive mechanism, which matches an acknowledgement to its request by it. |
| 9 | Timestamp | 5.3.10 | **Absent and REQUIRED** on X2 and X3 (tables 5.3.2-2 and 5.3.3-2, "shall be present"). The record carries its own timestamps inside the payload; the header attribute is required in addition. |
| 10 | Source IPv4 address | 5.3.11 | Absent. For X3 the addresses are inside the intercepted packet. |
| 11 | Destination IPv4 address | 5.3.12 | Absent, as above. |
| 12 | Source IPv6 address | 5.3.13 | Absent, as above. |
| 13 | Destination IPv6 address | 5.3.14 | Absent, as above. |
| 14 | Source port | 5.3.15 | Absent, as above. |
| 15 | Destination port | 5.3.16 | Absent, as above. |
| 16 | IP protocol | 5.3.17 | Absent, as above. |
| 17 | Matched target identifier | 5.3.18 | **Absent and REQUIRED** on X2 (table 5.3.2-2, "shall be set to indicate what target identity was matched"). |
| 18 | Other target identifier | 5.3.19 | **Absent and REQUIRED** on X2 (table 5.3.2-2, "shall be set with all other target identities present at the NF"). |
| 19 | MIME content type | 5.3.20 | Absent. Applies to the MIME payload format, which this project does not emit. |
| 20 | MIME content transfer encoding | 5.3.21 | Absent, as above. |
| 21 | Additional XID related information (AXRI) | 5.3.22 | Absent. TS 33.128 clause 5.3.3 makes it a "may" for efficient xCC delivery, not a requirement. |
| 22 | SDP session description | 5.3.23 | Absent. Applies to session descriptions this project does not intercept. |

## Payload formats — table 5.4.1-1

Values 1 to 16 were compared field by field against the table and the X2/X3 permissions
match it exactly. Value 0 is `N/A` in the specification, because a keepalive PDU carries no
payload, and is refused here on both interfaces, which is consistent with that. **Value 17
is missing from the code and has been added**; it was introduced by CR019r2 in V1.8.1 and
went unnoticed because the transcribed table carried no version stamp.

Of these, this project emits exactly three: format 2 on X2, and formats 5 and 12 on X3.

| Value | Payload format | X2 | X3 | Disposition |
|---|---|---|---|---|
| 0 | Reserved for keepalive | N/A | N/A | Refused on both, consistent with the reservation. |
| 1 | ETSI TS 102 232-1 defined payload | Yes | Yes | Permitted, never emitted. |
| 2 | 3GPP TS 33.128 defined payload | Yes | Yes | **Emitted** — every xIRI record. |
| 3 | 3GPP TS 33.108 defined payload | Yes | Yes | Permitted, never emitted. |
| 4 | Proprietary payload | Yes | Yes | Permitted, never emitted. |
| 5 | IPv4 packet | Yes | Yes | **Emitted** on X3 — decapsulated inner IPv4. |
| 6 | IPv6 packet | Yes | Yes | Permitted, not currently emitted. |
| 7 | Ethernet frame | No | Yes | Permitted on X3, never emitted. |
| 8 | RTP packet | No | Yes | Permitted on X3, never emitted. |
| 9 | SIP message | Yes | No | Permitted on X2, never emitted. |
| 10 | DHCP message | Yes | No | Permitted on X2, never emitted. |
| 11 | RADIUS packet | Yes | No | Permitted on X2, never emitted. |
| 12 | GTP-U message | No | Yes | **Emitted** on X3 — the encapsulated form. |
| 13 | MSRP message | No | Yes | Permitted on X3, never emitted. |
| 14 | 3GPP TS 33.108 EpsIRIContent | Yes | No | Permitted on X2, never emitted. |
| 15 | MIME message | Yes | Yes | Permitted, never emitted. |
| 16 | 3GPP unstructured PDU | No | Yes | Permitted on X3, never emitted. |
| 17 | ETSI TS 102 232-1 PS-PDU.Payload | Yes | Yes | Permitted, never emitted. Added in V1.8.1. |

## What this disposition does not cover

An audit that finds nothing is not proof there is nothing, and this one is a reading. Stated
plainly, so nobody mistakes its scope for a clean bill of health:

- **The framing was read, not checked.** No test compares this package against TS 103 221-2,
  because ETSI publishes nothing machine-readable to compare it against. The reading is as
  good as the person who did it, which is exactly the standard that let earlier defects
  through on the X1 side before a check existed there.
- **The byte-level layout is covered by interoperability, not by this document.** Offsets,
  lengths and field order are exercised every time this element delivers to the sipgate
  reference implementation. What that cannot see — and what this disposition is aimed at —
  is anything neither implementation emits.
- **Nothing here was verified against a mediation function that requires the missing
  attributes.** The gaps below are established from the specification text; how a strict MDF
  reacts to them has not been observed.
- **Only the profile this project uses was read.** TS 103 221-2 clause 6 defines a default
  profile that is mandatory to support and permits others; alternatives were not considered.

## Known gaps, in order of consequence

1. **The keepalive mechanism of clause 6.2.4 is unimplemented.** The specification says the
   PDU types shall be supported and the POI shall emit a Keepalive at least every TIME_P1.
   This element emits none, answers none, and never applies the TIME_P2 disconnect. It
   depends on conditional attribute type 8.
2. **No conditional attribute is ever emitted, and TS 33.128 requires six of them.** NFID
   and IPID on both interfaces, plus Timestamp, Sequence Number, Matched Target Identifier
   and Other Target Identifier on X2, and Timestamp and Sequence Number on X3. Every xIRI
   and every xCC this project has ever sent is missing them.
3. **The emitted Version field is 5, and V1.10.1 defines 6.** Deliberate while gap 1 stands;
   see the version section above.
