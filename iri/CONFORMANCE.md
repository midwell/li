<!--
SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
SPDX-License-Identifier: Apache-2.0
-->

# TS 33.128 record conformance

**Made against 3GPP TS 33.128 V18.16.0**, and against the `TS33128Payloads.asn` module
published with it. Both are cited below; where they disagree, that disagreement is itself
recorded, because one of the findings here lives exactly in the gap between them.

**This disposition was last reviewed 2026-08-20.** The specification revision above says
what was read; this says when. Any count quoted from here — in `../CONFORMANCE.md`, or on a
public compliance page — is a count as of that date, and carrying the date in the document
the count came from is what lets a reader check it from this end rather than only from the
end that quotes it.

## Why decoding is not enough

Every record this project emits is decoded against the published ASN.1 module by the
end-to-end suite, and `golden_test.go` pins the codec's output byte for byte. Neither proves
conformance:

- **The golden file pins our own encoder's output.** It catches a codec regression. It
  cannot notice a field that was never populated in the first place.
- **A successful decode proves the record is well formed.** It does not prove the record
  carries the fields TS 33.128 says it carries — because the ASN.1 module marks nearly
  everything `OPTIONAL`, while the payload tables in clause 6.2 carry the real M/C/O
  markers. A record can omit a field the tables mark **M** and still decode cleanly against
  the module.

The finding below is precisely that case, which is why this document compares against the
**payload tables**, not only the ASN.1.

## Scope

Bounded to the records this project actually emits, since a record we do not emit cannot
carry a wrong field to a mediation function.

| | Count |
|---|---|
| Record types defined in `li/iri` | 17 |
| Emitted by the AMF | 11 |
| Emitted by the SMF | 5 |
| Emitted by the UPF | 0 — the UPF is a CC-POI and produces no xIRI |
| Defined but deliberately not emitted | 1 — `AMFPositioningInfoTransfer` |

`AMFPositioningInfoTransfer` is out of scope by an earlier decision, not an oversight: every
trigger event in clause 6.2.2.2.8 requires an LMF, and this AMF has no LMF integration — it
decodes the NRPPa PDU and drops it. The definition stays because it is correct and tested,
and becomes usable the day an LMF is wired up. `li/README.md` carries the reasoning.

The list was derived from the code — the record alternatives registered in `li/iri`, checked
against which of them the AMF and SMF actually construct — not from the specification, so it
describes what is emitted rather than what ought to be.

## Mandatory fields — complete

Every field the clause 6.2 payload tables mark **M**, for all 16 emitted records, against
the Go definition in `iri.go`. This pass is complete.

| Record | Payload table | Mandatory fields | Verdict |
|---|---|---|---|
| AMFRegistration | 6.2.2.2.2-1 | registrationType, registrationResult, sUPI, gUTI | All present |
| AMFDeregistration | 6.2.2.2.3-1 | deregistrationDirection, accessType | All present |
| AMFLocationUpdate | 6.2.2.2.4-1 | sUPI, location | All present |
| AMFStartOfInterceptionWithRegisteredUE | 6.2.2.2.5-1 | registrationResult, sUPI, gUTI | All present |
| AMFUnsuccessfulProcedure | 6.2.2.2.6-1 | failedProcedureType, failureCause | All present |
| AMFIdentifierAssociation | 6.2.2.2.7-1 | sUPI, gUTI, location | All present |
| AMFIdentifierDeassociation | 6.2.2.2.7-2 | sUPI, gUTI | All present |
| AMFRANHandoverCommand | 6.2.2.2.9.2-1 | userIdentifiers, aMFUENGAPID, rANUENGAPID, handoverType, targetToSourceContainer | All present |
| AMFRANHandoverRequest | 6.2.2.2.9.3-1 | userIdentifiers, aMFUENGAPID, rANUENGAPID, handoverType, handoverCause, pDUSessionResourceInformation, targetToSourceContainer, rANSourceToTargetContainer | All present |
| AMFUEPolicyTransfer | 6.2.2.2.12-1 | sUPI, uePolicy | All present |
| AMFUEServiceAccept | 6.2.2.2.13-1 | userIdentifiers, serviceMessageIdentity | All present |
| SMFPDUSessionEstablishment | 6.2.3-1 | pDUSessionID, gTPTunnelID, pDUSessionType, dNN, requestType, gTPTunnelInfo | All present (gTPTunnelInfo added, finding 1) |
| SMFPDUSessionModification | 6.2.3-2 | gTPTunnelInfo | All present (gTPTunnelInfo added, finding 1) |
| SMFPDUSessionRelease | 6.2.3-3 | sUPI, pDUSessionID | All present |
| SMFStartOfInterceptionWithEstablishedPDUSession | 6.2.3-4 | pDUSessionID, gTPTunnelID, pDUSessionType, dNN, requestType, gTPTunnelInfo | All present (gTPTunnelInfo added, finding 1) |
| SMFUnsuccessfulProcedure | 6.2.3-5 | failedProcedureType, failureCause, initiator | All present |

**Every record now satisfies its mandatory set.** Three of the five SMF records did not when
this audit began; see finding 1.

## Every unmodelled field, and its marker — complete

`asn1_drift_test.go` enumerates the fields the published module defines for each record and
fails on any this package neither models nor declares absent. That enumeration is **149
fields**, and each one's M/C/O marker has been read from its payload table and recorded in
the test's `declaredAbsent` map:

| Marker | Count | Meaning here |
|---|---|---|
| **M** | 3 | All three are `gTPTunnelInfo`. See finding 1. |
| C | 145 | Conditional. Three are explicitly deprecated by the specification. |
| O | 1 | `AMFUEServiceAccept/deprecatedUERequestType`, itself deprecated. |

This cross-reference was derived mechanically from the module and the payload tables, and it
**independently reproduced the hand comparison above**: the only mandatory-and-unmodelled
fields in the whole set are the three `gTPTunnelInfo` instances.

Three fields needed a human to resolve, because the specification spells them differently in
its tables than in its ASN.1 module — `sMSoverNASIndicator` in the tables versus
`sMSOverNasIndicator` and `sMSOverNASIndicator` in the module. All three are C.

### Every condition, judged

Knowing a field is marked C is not the same as knowing whether this POI meets its condition,
so each of the 146 was judged and the verdict recorded beside it:

| Verdict | Count | Meaning |
|---|---|---|
| NOT HELD | 69 | the network function does not hold the datum |
| **MET** | **26** | **the network function holds it and does not report it — findings 3 and 4** |
| N/A | 26 | the condition cannot arise; the feature is not implemented here |
| DEFERRED | 9 | held, but the subtree is deliberately not modelled |
| UNTRACED | 9 | a similarly named context field exists and the mapping was not followed through |
| BLOCKED | 4 | the codec cannot express the value — finding 2 |
| DEPRECATED | 3 | the specification no longer uses the field |

The nine `UNTRACED` verdicts are an admission, not a conclusion, and are labelled so they
cannot be mistaken for clearance: `pCCRules`, `pCCRuleIDs`, `oldPDUSessionID`,
`handoverState`, `uEPolicy` and `rRCEstablishmentCause` each have a plausibly corresponding
field in a network function's context that was not followed through to the point of
interception.

**The 26 `MET` and 4 `BLOCKED` entries are held in a separate list from the rest.**
`asn1_drift_test.go` keeps `declaredAbsent` for fields this project need not populate and
`knownConditionalDefects` for the 30 it should and does not, and pins that count — so adding
another is a deliberate act rather than one more line among fields that are fine. A field
its payload table marks **M** is rejected from the disposition list outright: a mandatory
field is either populated or a known defect, never a disposition.

The 26 `N/A` verdicts rest on features this deployment does not implement: EPS/5GS
interworking over N26 and the SGW/PGW role, non-3GPP access through an N3IWF, TNGF or TWIF,
satellite backhaul, multi-USIM, and non-public networks. Each was checked against the code
rather than assumed.

## Findings

### 1. `gTPTunnelInfo` was mandatory in three SMF records and modelled in none — FIXED

Tables 6.2.3-1, 6.2.3-2 and 6.2.3-4 all mark it `M` with cardinality 1; it carries the user
plane GTP tunnel information for the session, defined in table 6.2.3-1B. For
`SMFPDUSessionModification` it is the record's *only* mandatory field, so that record
satisfied none of its mandatory set.

**Nothing could have caught this, by construction.** The ASN.1 module declares it
`gTPTunnelInfo [16] GTPTunnelInfo OPTIONAL`, so every record decoded cleanly against the
published module without it and always would have. No round-trip test, no golden fixture and
no live decode against the module can see it. It is visible only by reading the payload
tables — which is the entire argument for auditing the M/C/O markers rather than trusting a
successful decode.

Now modelled as `GTPTunnelInfo`/`FiveGSGTPTunnels` and populated by the SMF from the same UL
NG-U F-TEID it already reports in `gTPTunnelID`, which is what table 6.2.3-1C asks for. The
encodings of all three records changed accordingly. `additionalULNGUUPTunnelInformation`,
`dLRANTunnelInformation` and `ePSGTPTunnels` remain unmodelled: the SMF holds none of them
for the single default path it manages, and the last reports PDN connection events at an
SGW/PGW, which this project does not implement.

### 2. `sUPIUnauthenticated` is never populated — OPEN, blocked on the codec

Absent from all four records that define it (`SMFPDUSessionEstablishment`,
`SMFPDUSessionModification`, `SMFStartOfInterceptionWithEstablishedPDUSession`,
`SMFUnsuccessfulProcedure`) under a condition this project routinely meets: table 6.2.3-1
says it "shall be present if a SUPI is present in the message", `true` when the SUPI has not
been authenticated and `false` when it has.

**It is not fixed here because the shared codec cannot express it.** The field is
`SUPIUnauthenticatedIndication ::= BOOLEAN`, and the meaningful value in the ordinary case is
`false` — the SUPI *was* authenticated. `li/asn1` omits any `optional` field whose value
equals its type's zero value (`isEmpty` in `encode.go`), so an optional BOOLEAN can encode
`true` and can never encode `false`; and Go pointers, the usual way to distinguish absent
from false, are not handled by the encoder at all. Marking the field non-optional instead
would emit it even when no SUPI is present, asserting an authentication status for an
identity that is not in the record.

Doing it properly means teaching the codec to distinguish "absent" from "present and zero",
which changes how every field of every record decides emptiness. That is a shared-codec
change with its own blast radius and belongs in its own piece of work, not folded into an
audit.

### 3. Identity a POI holds and does not report — OPEN

Eight fields are held by the emitting network function and reported by nobody. These are the
"quieter half" this audit went looking for: no decoder can see them, because a record that
omits a conditional field is perfectly well formed.

| Field | Records | Where the data already is |
|---|---|---|
| `sUCI` | 6 AMF records | `AmfUe.Suci`. The AMF holds it; `UeIdentity`, the snapshot the POI reads, does not carry it. |
| `pEI`, `gPSI` | `AMFIdentifierDeassociation` | The AMF reports both in **every other record it emits** — this one record omits them. |
| `fiveGSTAIList` | `AMFRegistration`, `AMFIdentifierAssociation` | The AMF holds the UE's TAI list. |
| `rATType` | 3 SMF records | `SMContext.RatType`, set from the CreateSMContext request. |
| `servingNetwork` | 3 SMF records | `SMContext.ServingNetwork`. |
| `aMFID` | 3 SMF records | `SMContext.ServingNfId`. |
| `uEEndpoint` | `SMFUnsuccessfulProcedure` | `SMContext.PDUAddress`, already reported in the other session records. |

`sUCI` and the `AMFIdentifierDeassociation` pair matter most: they are **target identities**.
An agency correlating product across records gets less to correlate on than the AMF holds,
and the deassociation record — which reports that an identifier is no longer associated with
a subject — omits two of the identifiers it is about.

None of these is fixed here. Each is a plumbing change in a network function rather than a
correction to this module, and `sUCI` needs a field added to the AMF's identity snapshot.

### 4. `location` is inconsistent across the AMF's records — OPEN

The AMF populates a minimal `Location` (`locationInfo.currentLocation` only) in three records
and omits the field entirely from `AMFRegistration` and `AMFDeregistration`, where the tables
mark it conditional on availability. The underlying gap is the deliberately deferred
`userLocation` subtree — the AMF has no reportable location detail to put there — so this is
recorded as an inconsistency to resolve alongside that deferral rather than as a separate
defect. Whichever way it is resolved, the five records should agree.

### 5. `handoverCause` carried NGAP's numbering, not TS 33.128's — FIXED 2026-08-20

**Every handover record this project delivered before 2026-08-20 carried the wrong cause
value, and no party could have noticed.**

The five `HandoverCause` arms are `ENUMERATED`s that TS 33.128 numbers from 1. NGAP numbers
the same five groups from 0. `iri.go` said so, and said the mapping between them "is done
where the record is built" — but the place it is built, the AMF's `handoverCause`, cast the
NGAP value straight into the record type. Nothing in this project performed the mapping. So
each cause was delivered one below its defined value, and NGAP's `unspecified(0)` was
delivered as a zero the arm's own enumeration does not define.

**Why it survived.** The wrong value is a plausible member of the right enumeration: it
decodes, it validates against the published module, and it names a real cause. A mediation
function receiving `handoverDesirableForRadioReasons` cannot tell that the network said
`tXnRelocOverallExpiry`. Neither could this element. The constraint check added in
`li v0.9.2` could not see it either — it treats zero as absence, correctly, because an unset
optional `ENUMERATED` member reads as zero in Go, so the one value that was out of range
passed unremarked.

**What changed.** The correspondence is now established member by member, by name, in
`amf/ngap/licause.go`, and asserted in both directions against two machine-readable
definitions — this module for TS 33.128, the pinned `ngap` module for NGAP — so a value that
stops corresponding when either side is upgraded fails a test rather than reaching an agency.
The values themselves are named constants here (`causevalues.go`), asserted against the
module, and `enumConstraints` now carries each arm's real upper bound instead of an open one.

**What an agency will see.** Product delivered from 2026-08-20 differs from product delivered
before it for the same event: a handover that read `unspecified` may now read a specific
reason, and one that read a specific reason may now read the reason one along. **Records
already delivered cannot be corrected from here** — this project retains no product, by
design, so there is nothing to reissue. The date above is the boundary.

**One cause in nine is still not carried.** NGAP defines nine values across
`CauseRadioNetwork` and `CauseNas` that TS 33.128 V18.16.0 has no equivalent for — six of
them causes NGAP added after this release. Those are delivered as the group's own
`unspecified` and reported over X1 as `recordValueSubstituted` at element scope, because the
field is mandatory and an unreported handover is a larger gap than an imprecise one. The
report is the only thing distinguishing that `unspecified` from one the network gave itself;
the record cannot.

**A discrepancy between the module and the tables, recorded rather than resolved.**
`CauseRadioNetwork` in `TS33128Payloads.asn` runs 1..52 with **no value 28**, so it defines
51 causes where NGAP defines 58. Three of its names are also misspelled relative to NGAP's
(`iMSVoiceeEPSFallbackOrRATFallbackTriggered`, `uPIntegrityProtectioNotPossible`, and
`nPMAccessDenied` for NPN access). Each sits at the position its NGAP counterpart predicts,
so all three are read as the same cause and the aliases are listed explicitly in the mapping
test. `enumConstraints` admits 28 because a range cannot express a hole; nothing this project
builds can produce it, which is asserted.
