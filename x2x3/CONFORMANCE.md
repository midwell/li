<!--
SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
SPDX-License-Identifier: Apache-2.0
-->

# TS 103 221-2 conformance disposition

**Made against ETSI TS 103 221-2 V1.10.1 (2026-03).** Every table and clause number below
refers to that revision. When a newer revision is published, this document is what tells you
whether the code disagrees with the specification or merely predates it — that distinction
is the reason the version is stated at the top rather than left implied.

**This disposition was last reviewed 2026-08-15.** The revision above says what was read;
this says when, so that a statement quoted from here can be checked against the revision of
this document it was taken from.

## What this is, and what it is not

This is a **reading**, not a check. ETSI publishes no machine-readable definition of the
X2/X3 framing: the sole attachment to part 2 is `TS_103_221_02_Configuration.xsd`, which
describes how an X2/X3 interface is *configured* over **X0** — annex C.1 opens "this annex
is only applicable when the X0 interface (see ETSI TS 104 000) is used", and the schema
extends `etsi104000:ConfigurationDetails` in namespace `urn:etsi:li:104000:xsdns:v2` — and
says nothing about the PDU layout. (It said "over X1" here until 2026-08-14. TS 103 221-1
defines no message carrying these fields, so there was never an X1 route to support or to
decline; the element implements no X0 interface and the timers are deployment
configuration.) The X1 side of this project can and does verify
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

**This package emits 5**, which was correct for every revision through V1.9.1.

The reason it is not 6 changed on 2026-08-14. It used to be that keepalive was
unimplemented, so the field would have asserted conformance to a revision this element did
not meet. Keepalive is now implemented — see the PDU type table below — and the bump is
held back by the peer instead: the reference implementation this project interoperates with
**refuses a 0.6 PDU**, closing the connection and storing nothing
(`tests/e2e-li/evidence-260814/x2-probe-keepalive.json`). Confirmed from that peer's own
source, which it ships with its classes: `li-lib-x1x2x3` 1.0.3 holds `MINOR_VERSION = 5` and
throws on anything else. Clause 5.2.1 makes a minor
increment backwards-compatible, so that is a defect in the peer — and one that would cost
all delivery to it, not part of it, if this element raised the field.

So this is blocked on a mediation function that accepts 0.6, not on work here. It is the
one gap in this document whose remedy is not in this repository.

**On decode**, a differing minor version is accepted and a differing major version is
rejected, which follows the compatibility rule the clause defines. This package is no longer
write-only: the keepalive reader is the first thing here that reads an X2/X3 socket, so that
leniency is now load-bearing rather than latent. The read path is bounded — a peer's
declared length beyond a few kilobytes is refused and the connection dropped — because
`Unmarshal` waits for as many bytes as a header claims and imposes no maximum of its own.

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
| Conditional Attribute Fields | variable | 5.3 | **Emitted and parsed.** The six TS 33.128 requires are populated by all three POIs; the remaining sixteen are absent with a reason. See table 5.3.1-2 below. |
| Payload | variable | 5.4 | **Emitted and parsed.** |

## PDU types — table 5.2.2-1

| Value | Meaning | Disposition |
|---|---|---|
| 1 | X2 PDU | **Emitted** by the AMF and SMF IRI-POIs. |
| 2 | X3 PDU | **Emitted** by the UPF CC-POI. |
| 3 | Keepalive | **Emitted**, on every X2/X3 connection at least every TIME_P1 (default 60 s), unconditionally rather than when idle — product PDUs are not acknowledged, so traffic says nothing about the mediation function's liveness. Also **answered**: a Keepalive arriving at this element is acknowledged with its own Sequence Number, clause 6.2.4 making both types supported by POIs *and* MDFs. |
| 4 | Keepalive Acknowledgement | **Emitted and read.** Read to apply the TIME_P2 rule (default 180 s), measured from the last *valid* acknowledgement seen rather than per Keepalive; on expiry the connection is disconnected, redialled and reported to the ADMF as `mdfUnreachable`. **What establishes liveness is the Sequence Number**: clause 6.2.4 numbers the acknowledgement from the Keepalive it answers, so the number is the only evidence available that the peer is answering *this element* rather than emitting traffic. An acknowledgement carrying no usable number, or one beyond what this connection has issued, is counted as a mismatch and does **not** postpone TIME_P2 — a peer stuck in a loop, a middlebox replaying, and an endpoint a misroute put in the path all satisfy "something is answering", and each of them takes no product. It is not treated as a protocol error either: the connection is not torn down over a numbering defect in a peer that is carrying product, so the fail-safe decides. This changed on 2026-08-19; previously any acknowledgement refreshed the deadline and the mismatch was counted and acted on nowhere. |

## Payload directions — table 5.2.6-1

All six values are modelled and match the table. Value 0 is reserved for the keepalive
mechanism, and is emitted on exactly the PDUs that reservation is for: clause 5.1 has a
Keepalive zero every mandatory field but three, so its direction is 0 and never anything
else. No product PDU carries it.

| Value | Meaning | Modelled as |
|---|---|---|
| 0 | Reserved for the keepalive mechanism | `DirectionReservedKeepalive` |
| 1 | Direction not known to the POI | `DirectionUnknown` |
| 2 | Sent to (received by) the target | `DirectionToTarget` |
| 3 | Sent from the target | `DirectionFromTarget` |
| 4 | Result of data or events in more than one direction | `DirectionMultiple` |
| 5 | Direction not applicable | `DirectionNotApplicable` |

## Conditional attributes — table 5.3.1-2

**Six of the 22 defined attribute types are emitted; the other sixteen are not.** That is a
change: until `add-li-x2x3-conditional-attributes`, every xIRI and every xCC this project had
ever delivered carried none of them. The TLV mechanism was implemented — `Marshal` writes the
type/length/value structure of table 5.3.1-1 and `Unmarshal` parses it back — and no producer
populated `PDU.Attributes`.

**Correction to what this document previously claimed.** The Timestamp row used to say that
"the record carries its own timestamps inside the payload; the header attribute is required in
addition". That is wrong, and it understated the defect. `li/iri` reads no clock, and every
`Timestamp` field in `TS33128Payloads.asn` is OPTIONAL and left unset here — so before this
change an agency receiving our product could not tell when an intercepted event happened, only
when the PDU arrived. The header attribute is not additional metadata; it is the only event
time this element sends.

Clause 5.3 makes these attributes something the POI "may provide … as directed by the
relevant LI architecture", and for this project the relevant architecture is 3GPP TS 33.128 —
which directs a great deal. **Six of the 22 are required, and all six are now emitted.**

TS 33.128 table 5.3.1-2 applies to both LI_X2 and LI_X3 and says the **NFID** "shall be set
to indicate the NF that contains the POI" and the **IPID** "shall be set to indicate the POI
(within the NF) that generated the xIRI". Table 5.3.2-2 adds, for every xIRI on LI_X2,
**Timestamp** ("shall be present and set to the time at which the event occurred"),
**Sequence Number** ("shall be present"), **Matched Target Identifier** ("shall be set to
indicate what target identity was matched") and **Other Target Identifier** ("shall be set
with all other target identities present at the NF"). Table 5.3.3-2 requires Timestamp and
Sequence Number on LI_X3 too, and makes AXRI optional.

So the AMF and SMF IRI-POIs each owe six attributes on every xIRI, and the UPF CC-POI owes
four on every xCC. All are emitted as of `add-li-x2x3-conditional-attributes`.

**What that change verified, and what it did not.** Four PDUs were sent to the independent
sipgate reference before any of it was implemented — a 40-byte control beside headers of 49, 80
and 163 bytes — and it stored all four and parsed the attribute region of each
(`tests/e2e-li/evidence-260814/`). So a peer accepts a header longer than the mandatory 40, and
accepts the unprefixed target-identifier fragment clause 5.3.18 illustrates. That peer does not
validate the fragment as XML, and no mediation function that *requires* these attributes has
been observed at all — the same limit every interoperability result here carries.

| Type | Name | Clause | Disposition |
|---|---|---|---|
| 1 | ETSI TS 102 232-1 defined attribute | 5.3.2 | Absent. Carries an attribute defined by a specification this project does not implement. |
| 2 | 3GPP TS 33.128 defined attribute | 5.3.3 | Absent. **The one most likely to be required**, since TS 33.128 is this project's governing architecture. |
| 3 | 3GPP TS 33.108 defined attribute | 5.3.4 | Absent. TS 33.108 is the EPS-generation interface; not implemented here. |
| 4 | Proprietary attribute | 5.3.5 | Absent by choice. A standardized attribute is preferable and the clause frames this as temporary support. |
| 5 | Domain ID (DID) | 5.3.6 | Absent. TS 33.128 does not require it; the destinations are resolved from the X1 task, and where a task names more than one of a delivery type every one of them receives that task's product. |
| 6 | Network Function ID (NFID) | 5.3.7 | **Emitted** on X2 and X3, set to the identifier the element asserts on X1 (its `neId`), so the identity an MDF receives is the one the ADMF tasks. |
| 7 | Interception Point ID (IPID) | 5.3.8 | **Emitted** on X2 and X3: `AMF-IRI-POI`, `SMF-IRI-POI`, `UPF-CC-POI`. Each network function contains one point of interception, so the value is a property of the code rather than of the deployment. |
| 8 | Sequence Number | 5.3.9 | **Emitted** on X2 and X3, numbered per the clause's `(XID, DID, NFID, IPID, Correlation ID)` context and not per connection — `Sequencer` holds one counter per live context and drops it when the tasking does — on an ordinary withdrawal, a bulk deactivation and a fail-safe purge alike, since the numbering belongs to the tasking and not to the circumstances of its removal, and *not* on a modification, which keeps the XID and so keeps every context the task's own records have already numbered. **The DID is deliberately not part of the key.** The other four components are constant for a task at one POI, so the varying part is `(XID, Correlation ID)`; keying on the DID as well would number one record separately per destination, and a record delivered to two of a task's destinations must carry one number or each mediation function holds a numbering no other does, with gaps in it indistinguishable from loss. The keepalive mechanism has its own counter, one per connection, for the reason the clause implies: a Keepalive PDU zeroes the XID and Correlation ID, so its context is not any task's, and numbering keepalives from a task's sequence would advance the numbers an MDF reads to detect that task's lost product. |
| 9 | Timestamp | 5.3.10 | **Emitted** on X2 and X3 as the clause's POSIX timespec, two *unsigned* 32-bit integers. On X2 it is the time the event occurred, captured at the report hook; on X3 the time the xCC was generated, taken at framing. **It is the only time information this element sends** — see the note below. |
| 10 | Source IPv4 address | 5.3.11 | Absent. For X3 the addresses are inside the intercepted packet. |
| 11 | Destination IPv4 address | 5.3.12 | Absent, as above. |
| 12 | Source IPv6 address | 5.3.13 | Absent, as above. |
| 13 | Destination IPv6 address | 5.3.14 | Absent, as above. |
| 14 | Source port | 5.3.15 | Absent, as above. |
| 15 | Destination port | 5.3.16 | Absent, as above. |
| 16 | IP protocol | 5.3.17 | Absent, as above. |
| 17 | Matched target identifier | 5.3.18 | **Emitted** on X2, one occurrence per identity of the task that the subject presents, as the clause's bare UTF-8 fragment (`<supiimsi>…</supiimsi>`). Not emitted on X3, which table 5.3.3-2 does not require and a CC-POI tasked by packet criteria could not populate without inventing it. |
| 18 | Other target identifier | 5.3.19 | **Emitted** on X2, one occurrence per remaining identity **of that subject**. Not every identity the network function holds: the literal reading of table 5.3.2-2 would disclose unrelated subscribers to an agency holding a warrant for one. |
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

1. **A fragmented IPv4 datagram whose first fragment has not been seen is discarded.** This
   is a CC-POI limit rather than a wire-format one, and it is declared here because the loss
   it leaves is otherwise invisible: a copy dropped before framing leaves no gap in the X3
   sequence, so a mediation function cannot detect it.

   Only a transport-port criterion is affected, because it is the only one that has to read
   the packet. A fragmented datagram carries its transport header in the first fragment only,
   so the classification is taken from that fragment and applied to the datagram's later ones
   through a bounded, direction- and identity-scoped memo held for the life of the tasking
   generation. Every fragment of an authorised datagram is therefore delivered *provided the
   fragments arrive in order*, which is the normal case over a GTP-U path.

   What is not done is **retaining a fragment that arrives before the one carrying the
   transport header**. Holding copies would be a second mechanism on the one path in this
   element whose cost is per packet, in front of a datagram queue that holds ten by default,
   and it is reachable by a peer who can choose fragment order — a denial-of-service surface
   introduced to recover the rarest arrival order. So such a fragment is discarded, and
   reported through the same X3 content-loss condition a full delivery queue raises. The same
   applies to a classification that has expired or that the memo's ceiling refused to record.

   If measurement ever shows out-of-order arrival is material, holding is its own change with
   its own bounds. IPv6 fragmentation is out of scope for the reason the criteria disposition
   gives: this core has no IPv6 PDU sessions.

2. **The emitted Version field is 5, and V1.10.1 defines 6.** No longer a matter of this
   element's own conformance: the mechanism the bump was waiting on is implemented, and what
   holds it back now is that the only interoperability peer available refuses 0.6. See the
   version section above. **Blocked externally**, not deferred.

**Closed since this disposition was written**, in order:

- Every conditional attribute TS 33.128 requires was absent on both interfaces. All six are
  now emitted — see table 5.3.1-2 above — which leaves the sixteen that are absent by
  decision rather than by omission.
- **The keepalive mechanism of clause 6.2.4 was unimplemented**: this element emitted no
  Keepalive, answered none, and never applied the TIME_P2 disconnect. All three are now
  done, on X2 and X3, in `keepalive.go`. What that has *not* been verified against is an
  independent implementation, and cannot currently be: the reference declares
  `PduType.KEEPALIVE` and `KEEPALIVE_ACK` and references neither anywhere in its X2/X3 code —
  precisely the state this package was in before this change — so the acknowledgement path is
  exercised only against this project's own endpoint. That is a
  limit of the evidence, not of the implementation, and it is recorded here because the
  distinction is exactly what this document exists to keep visible.
