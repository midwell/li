<!--
SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
SPDX-License-Identifier: Apache-2.0
-->

# TS 33.128 record conformance

**Made against 3GPP TS 33.128 V18.16.0**, and against the `TS33128Payloads.asn` module
published with it. Both are cited below; where they disagree, that disagreement is itself
recorded, because one of the findings here lives exactly in the gap between them.

**This disposition was last reviewed 2026-08-26.** The specification revision above says
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
| **MET** | **0** | **was 26 — the network function holds it and does not report it. Closed 2026-08-26, findings 2 and 3** |
| N/A | 27 | the condition cannot arise; the feature is not implemented here |
| DEFERRED | 9 | held, but the subtree is deliberately not modelled |
| UNTRACED | 9 | a similarly named context field exists and the mapping was not followed through |
| BLOCKED | 0 | was 4 — the codec could not express the value. Closed 2026-08-26, finding 2 |
| DEPRECATED | 3 | the specification no longer uses the field |

The `MET` and `BLOCKED` rows are kept at zero rather than removed. A verdict that has been
emptied is evidence about how this implementation is audited; a row that disappears reads as
a category that never existed. `N/A` gained one: `AMFPositioningInfoTransfer/sUCI`, which was
counted as `MET` while no point of interception emits that record at all.

`location` remains open under finding 4 and is `DEFERRED`, not `MET` — the earlier version of
this table attributed the `MET` count to "findings 3 and 4", which was wrong: every one of the
26 belonged to finding 3.

The nine `UNTRACED` verdicts are an admission, not a conclusion, and are labelled so they
cannot be mistaken for clearance: `pCCRules`, `pCCRuleIDs`, `oldPDUSessionID`,
`handoverState`, `uEPolicy` and `rRCEstablishmentCause` each have a plausibly corresponding
field in a network function's context that was not followed through to the point of
interception.

**The `MET` and `BLOCKED` entries were held in a separate list from the rest, and that list
is now empty.** `asn1_drift_test.go` keeps `declaredAbsent` for fields this project need not
populate and `knownConditionalDefects` for those it should and does not, and pins that count
— so adding another is a deliberate act rather than one more line among fields that are fine.
The pin is 0, and the list is kept rather than deleted so the next such field has an
established place to be recorded. A field its payload table marks **M** is rejected from the
disposition list outright: a mandatory field is either populated or a known defect, never a
disposition.

**The list's rule changed with these fixes, because it had been enforcing something other
than what it said.** Its own comment describes fields the project "does not populate", but
the staleness check keyed on whether the field was *modelled* — so adding a struct field
would have emptied the list while no emitter set any of them. The check now applies that rule
only to `declaredAbsent`, which really is a claim about modelling. That conflation is why
finding 3's table listed `uEEndpoint` on `SMFUnsuccessfulProcedure` as an open gap for weeks
after the SMF had begun reporting it: the modelled-but-unpopulated case had nowhere to live,
so it lived in prose and went stale.

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

### 2. `sUPIUnauthenticated` was never populated — FIXED 2026-08-26

Absent from all four records that define it and that this project emits
(`SMFPDUSessionEstablishment`, `SMFPDUSessionModification`,
`SMFStartOfInterceptionWithEstablishedPDUSession`, `SMFUnsuccessfulProcedure`) under a
condition this project routinely meets: table 6.2.3-1 says it "shall be present if a SUPI is
present in the message", `true` when the SUPI has not been authenticated and `false` when it
has.

**It was blocked on two things, and the disposition recorded only one.** The codec could not
express it: the field is `SUPIUnauthenticatedIndication ::= BOOLEAN`, the meaningful value in
the ordinary case is `false` — the SUPI *was* authenticated — and `li/asn1` omitted any
`optional` field whose value equalled its type's zero. The second was found only when the fix
was attempted: `SMContext.SetCreateData` retains fifteen fields of the N11 request and dropped
`UnauthenticatedSupi`, which the AMF had been sending all along. Fixing the codec alone would
have left the field unpopulatable while every test passed.

`li/asn1` now supports pointer fields. A nil pointer is absent; a non-nil one is present and
encodes its pointee even when that pointee is the type's zero. The mechanism is opt-in at the
field, which is what made it provable: no field in `li/iri` was a pointer, so the golden
vectors for all seventeen record types were byte-identical across the codec change. Changing
`isEmpty` itself was rejected for exactly that reason — it is on the path of every field of
every record, and two `PDUSessionID` fields annotated *"value 0 indistinguishable from
absent"* would have started emitting.

Marking the field mandatory was also rejected: it would emit an authentication status in
records carrying no SUPI, asserting something about an identity that is not there. Absent now
means the record carries no SUPI, and `false` means the SUPI was authenticated.

### 3. Identity a POI holds and does not report — FIXED 2026-08-26

Fields held by the emitting network function and reported by nobody. These are the "quieter
half" this audit went looking for: no decoder can see them, because a record that omits a
conditional field is perfectly well formed.

**The table below is the version this finding was written with, kept because it was wrong in
six places and the disagreement is the useful part.** It was prose; the enforced list is
`asn1_drift_test.go`'s `knownConditionalDefects`, which is re-derived against the module and
counted by a test. Where the two disagreed, the list was right.

| Field | Records, as first written | What the audited list held |
|---|---|---|
| `sUCI` | 6 AMF records | **9** — every AMF record the module defines it on |
| `pEI`, `gPSI` | `AMFIdentifierDeassociation` | the same |
| `fiveGSTAIList` | `AMFRegistration`, `AMFIdentifierAssociation` | **3** — also `AMFStartOfInterceptionWithRegisteredUE` |
| `rATType` | 3 SMF records | **5** — four SMF records **and `AMFRegistration`** |
| `servingNetwork` | 3 SMF records | 3, but not `SMFUnsuccessfulProcedure`, which has no such field |
| `aMFID` | 3 SMF records | 3, but not `SMFPDUSessionModification`, which has no such field |
| `uEEndpoint` | `SMFUnsuccessfulProcedure` | **`SMFPDUSessionModification`** — see below |

Eight field names, twenty-six record-field sites. A remedy scoped to the eight would have left
eighteen of them open with every test green.

**`uEEndpoint` on `SMFUnsuccessfulProcedure` was already reported when this finding was
written.** The SMF has populated it from `SMContext.PDUAddress` since the commit that
introduced the record. The real gap was `SMFPDUSessionModification`, which had no such field —
the one site the prose did not name. The row was stale because the drift test could not see
modelled-but-unpopulated fields, so that class lived only in this document.

**Two of the recorded sources were wrong, and neither would have worked.** `aMFID` was
recorded as coming from `SMContext.ServingNfId`, which is an NF instance UUID; TS 33.128
defines the field via TS 23.003 clause 2.10.1 as the AMF region, set and pointer — the AMF
half of a GUAMI. The AMF sends its GUAMI on N11 and `SetCreateData` dropped it, the same
defect as finding 2's second half. And `fiveGSTAIList` was recorded as "the UE's TAI list";
the tables ask for the *registration area* — "tracking areas associated with the registration
area within which the UE is current registered" — not the serving TAI the AMF also holds.

**`sUCI` is built from the NAS octets, not from `AmfUe.Suci`.** That string is what
`nasConvert.SuciToString` produced, and parsing it back into the record's six members is lossy
two ways: the routing indicator's `f` padding is stripped so leading zeros are gone, and the
home network public key identifier is rendered with `%d` against an OCTET STRING. The AMF now
retains the raw mobile identity and the point of interception reads the members from it. A
SUCI that does not yield clean members produces no `sUCI` at all: a missing target identity is
a gap an audit can find, a wrong one is a record an agency acts on.

**`schemeOutput` is not the octets, and the first implementation shipped it as though it
were.** Table 8.3.5-1 defines the field as *"the characters resulting as the output of the
permanent identifier with the protection scheme applied"*, and under the null scheme those
characters are the MSIN's digits. NAS carries them nibble-swapped, so carrying the octets
through transposes every pair: MSIN `0100007488` went out as `1000004788`, a well-formed
record naming a subscriber who does not exist. Under any other protection scheme the output is
ciphertext with no characters to speak of, and the octets stand.

**Nothing in this project's own test suite could see that**, and that is the finding rather
than the bug. The encoder accepted it, the record was structurally valid, the field was
present and non-empty, and every unit test asserting "the SUCI is reported" passed. It was
caught by decoding a delivered record against the module 3GPP publishes and reading the
subscriber it named — which is the argument for the cluster run being part of the remedy and
not a formality after it.

**`AMFPositioningInfoTransfer/sUCI` was never a defect against this element.** No point of
interception emits that record — all four of clause 6.2.2.2.8's trigger events are exchanges
with an LMF, and this AMF has none. It is `N/A`, and the field is modelled so the record stays
complete against the module.

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

### 6. `UEPolicy`'s size constraint forbids the containers 5G actually carries — OPEN, declared against TS 33.128

**TS 33.128 mandates a record this project cannot conformantly encode for most real
traffic, and the two halves of the specification contradict each other.**

`AMFUEPolicyTransfer` (clause 6.2.2.2.12) makes `uEPolicy` mandatory, and the trigger for the
record is the AMF transferring a UE policy container. The type is defined as:

```
UEPolicy ::= OCTET STRING (SIZE(16..65540))
```

A UE policy container is a UE POLICY DELIVERY SERVICE message (TS 24.501 / TS 24.587). The
shortest ones are three octets — extended protocol discriminator, PTI, message identity — and
`MANAGE UE POLICY COMPLETE` is exactly that. Measured against `li v0.9.6`: 3, 5 and 15 octets are
refused; 16 is accepted.

So the element must produce the record, and must not encode it. Both cannot hold.

**What this project does: follows the schema, and says so.** The constraint is enforced, the
record is not delivered, and the condition is reported — since `li v0.9.7` — as a task-scoped
`recordNotEncoded` naming the warrant and the record type, alongside the element-scoped delivery
loss it already raised.

**Why not relax the lower bound.** That was considered and rejected. A mediation function
validating against the published module discards a 3-octet `UEPolicy` exactly as this encoder
does, so relaxing it would not deliver the record — it would only move the discard to the far
end, where this element cannot see it. That is the unattributable-record failure arriving
through the payload instead of the header, and closing it is what the constraint checking in
`li v0.9.2` exists for. An element that believes it delivered is worse than one that knows it
did not.

**Why not pad.** Padding invents wire content. The receiver cannot distinguish the invented
octets from the subject's own policy container, which is a populated field asserting something
false.

**What an agency loses, stated plainly.** For a tasked subject, the short half of a policy
exchange is not delivered — typically the UE's `MANAGE UE POLICY COMPLETE`. The downlink
command, which carries the policy itself, is normally long enough to encode. The agency
therefore receives the substantive half and a fault naming the warrant and the missing record
type, rather than silence.

**What would resolve it.** A correction to TS 33.128's `UEPolicy` bounds, or a clause stating
that the field carries something other than the NAS container verbatim. Until then this is
recorded as a defect against the specification rather than against this codec, and the choice
of which half to follow is stated here rather than left to be inferred from behaviour.

