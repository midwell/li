<!--
SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
SPDX-License-Identifier: Apache-2.0
-->

# Conformance dispositions

This project implements a **subset** of the Lawful Interception standards it names. Three
dispositions record which subset, one per wire format, each stamped with the specification
revision it was made against **and with the date it was last reviewed**. This page is the
index and the list of open gaps; it does not restate what the dispositions say, because an
index that duplicates goes stale, which is the failure it exists to stop one level up.

The review dates matter wherever a count travels. A gap below stated as a number is a number
as of the disposition it came from, and the two dates differ — so anything quoting a count,
here or on a public page, names the disposition and its date rather than a single date for
all three. **This index was last reviewed 2026-08-15.**

| Interface | Disposition | Made against | What it covers |
|---|---|---|---|
| **X1** — task provisioning | [`x1/CONFORMANCE.md`](x1/CONFORMANCE.md) | ETSI TS 103 221-1 **V1.21.1**, schema **v1.19.1** | Every clause 6 message: implemented, refused with which code, or diverging by decision. Peer authentication (clause 8). The client direction, where this project's SMF triggers a CC-POI over LI_T3 |
| **X2/X3** — xIRI and xCC delivery | [`x2x3/CONFORMANCE.md`](x2x3/CONFORMANCE.md) | ETSI TS 103 221-2 **V1.10.1** | Header fields, PDU types, payload directions and formats, and every conditional attribute of table 5.3.1-2 |
| **IRI records** — record content | [`iri/CONFORMANCE.md`](iri/CONFORMANCE.md) | 3GPP TS 33.128 **V18.16.0** and its `TS33128Payloads.asn` | Every mandatory field of every record this project emits, and a verdict for all 146 conditional fields |

## Open gaps, across all three

Ordered by consequence, not by interface. Each is stated in full where it belongs; here it is
named with enough detail that a reader can tell whether it matters to them.

### IRI records

1. **30 known conditional-field defects**, of 146 conditions judged: **26 MET** — the network
   function holds the datum and the record does not report it — and **4 BLOCKED**, where the
   codec cannot express the value. A further **9 are UNTRACED**, which that disposition labels
   "an admission, not a conclusion". These counts are as of the IRI disposition of
   **2026-08-20**; `iri/CONFORMANCE.md` carries the same date, so a reader arriving there can
   tell whether the numbers quoted here are still its own.

   The 2026-08-20 review added one finding and closed it in the same pass — **`handoverCause`
   carried NGAP's numbering rather than TS 33.128's**, so every handover record delivered
   before that date named a cause one along from the one that occurred. It is listed here
   because it is not a conditional-field defect and so is in none of the counts above, and
   because it is the only finding in this document that changes what an agency receives for
   an event it has already been sent product about. `iri/CONFORMANCE.md` finding 5 has the
   detail.

### X2/X3

2. **The emitted Version field is 5, where V1.10.1 defines 6.** **Blocked externally**, not
   deferred: the mechanism the bump was waiting on is implemented, and what holds it back is
   that the only available interoperability peer refuses 0.6.
3. **The keepalive acknowledgement path has never been verified against an independent
   implementation.** The mechanism is implemented on both interfaces; the reference declares
   the PDU types and references them nowhere, so nothing but this project's own endpoints has
   ever exercised it. A limit of the evidence rather than of the implementation.

### X1

**None open.**

Six X1 gaps were found by writing that disposition and have since been closed: an X1 response
was not bound to the request that produced it, a nested LI_T3 criteria list was narrowed to its
first member, a target identifier populating more than one arm of the schema's choice was
accepted rather than refused, `TopLevelError` was unimplemented, an issue relating to one
delivery destination was reported at network-element scope, and no fault was ever reported as
cleared. Each is recorded there with what the behaviour was, because a closed gap is evidence
about how this implementation is audited and not merely history.

## Capabilities declared unsupported, which are not gaps

Four capabilities are declared permanently unsupported rather than pending. Each was read
against the question "what here is mandatory", and none is. They are recorded so that a
refusal is distinguishable from unfinished work — the full reasoning, with clause references,
is in the `li-provisioning` specification requirement *"A capability the element does not
implement is declared, not faked"*, and each is summarised in `README.md`'s feature table.

- **Generic Objects** (TS 103 221-1 clause 6.8), and therefore **destination sets** (`dSId`,
  annex E), which are Generic Objects.
- **Traffic policies** (`listOfTrafficPolicyReferences`, annex F). Marked **O**, out of scope
  by annex F.2.1, and a content-plane instrument with no meaning at an IRI-POI.
- **Content interception for more than one warrant covering the same session.** Where several
  tasks' criteria cover one PFCP session, content is delivered under one of them — the lowest
  XID, chosen stably — and the overlap is reported. **The report does not satisfy the warrants
  receiving nothing**, and is deliberately not described as though it does: it says an overlap
  occurred, not which warrants it concerns. Interception-related information is unaffected;
  several tasks matching one subject each produce their own xIRI.
- **Service-type scoping of a task** (`listOfServiceTypes`), which is refused rather than
  acknowledged and ignored.
- **A provisioned `correlationID` at an information point of interception** (TS 103 221-1
  clause 6.2.1.2). Refused at the AMF and the SMF, honoured at the UPF, and this is the one
  disposition in this list that depends on *which element is asked* rather than on the field.

  A content POI stamps the provisioned value on every unit it delivers, and an LI_T3 trigger
  carries one mandatorily, so the UPF acts on it. An IRI-POI in a 5G core cannot: the
  correlation that joins its records to a session's content is derived from the session — the
  SMF sends its F-SEID — and one task covers many sessions, so a single provisioned value
  applied to all of them would join at the mediation function what the network keeps separate.
  That is not what an ADMF asking for a correlation wants, and the element cannot ask which it
  meant.

  Until now it was parsed, stored and then ignored at both IRI-POIs, which is the case this
  project's *"A task field that cannot be honoured is refused, not ignored"* requirement exists
  to prevent: the ADMF was acknowledged and given an interception different from the one it
  authorised, with no channel through which the divergence could be reported. **An ADMF that
  provisions `correlationID` for an AMF or SMF task must stop**; the refusal carries error 3000
  or 3001 and names the reason. Refusing it at every element was considered and rejected — it
  would refuse tasking an ADMF may legitimately send to several elements at once, which is the
  same reasoning the recognised-extension case already follows.

## Two record-shape questions settled by reading, not inference

Recorded here because both were re-derived more than once, and because the answer to the
first decides the shape of a record rather than only its content.

**An `AMFDeregistration` names both accesses in one record, not one record per access.**
TS 33.128 V18.16.0 table 6.2.2.2.3-1 makes `accessType` mandatory with cardinality 1, and
`TS33128Payloads.asn` defines

```
AccessType ::= ENUMERATED { threeGPPAccess(1), nonThreeGPPAccess(2), threeGPPandNonThreeGPPAccess(3) }
```

so "both" is a value of the single field. Clause 6.2.2.2.3's own trigger text agrees: the
xIRI is generated when the IRI-POI detects that a UE "has deregistered from the 5GS over
at least one access type" — one record about a deregistration, however many accesses it
covered. The AMF therefore reports the scope it *acted on* (the access the UE requested,
which NAS can express as both) rather than the access the request happened to arrive over.

**The identifier binding is one binding across accesses**, so `AMFIdentifierDeassociation`
is emitted when the UE is left registered on none — not once per deregistration. A
dual-registered UE deregistering one access keeps its SUPI↔5G-GUTI binding, and the
element goes on producing records under it.

## How to read a disposition

Each follows the same shape: what it is and what it is not, the per-clause or per-table
dispositions, an explicit *what this does not cover*, and *known gaps in order of
consequence*. The middle section is the substance; the third is what stops the document being
mistaken for a clean bill of health.

Two of the three are readings rather than checks, because ETSI publishes nothing
machine-readable for X2/X3 framing and 3GPP's ASN.1 marks nearly everything `OPTIONAL` while
the real M/C/O markers live in the payload tables. X1 is the exception and has both a schema
validator and a drift check — neither of which can notice that a "shall" in the prose has no
code behind it, which is how two of the gaps above were found.
