<!--
SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
SPDX-License-Identifier: Apache-2.0
-->

# Conformance dispositions

This project implements a **subset** of the Lawful Interception standards it names. Three
dispositions record which subset, one per wire format, each stamped with the specification
revision it was made against. This page is the index and the list of open gaps; it does not
restate what the dispositions say, because an index that duplicates goes stale, which is the
failure it exists to stop one level up.

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
   "an admission, not a conclusion".

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
