<!--
SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
SPDX-License-Identifier: Apache-2.0
-->

# TS 103 221-1 conformance disposition

**Made against ETSI TS 103 221-1 V1.21.1 (2025-08)**, and against the published
`TS_103_221_01.xsd` **v1.19.1** vendored under `testdata/schemas/`. Every clause and table
number below refers to that revision of the prose; every statement about element names,
ordering or value formats refers to that revision of the schema. Where the two could
disagree, the prose is normative for behaviour and the schema still decides what validates —
`testdata/schemas/README.md` carries that tension, and `SOURCES.md` carries the quoted
statements the provisioning decisions rest on.

**This disposition was last reviewed 2026-08-15.** The revisions above say what was read;
this says when, so that a statement quoted from here can be checked against the revision of
this document it was taken from.

When a newer revision is published, this document is what tells you whether the code
disagrees with the specification or merely predates it. That distinction is the reason the
versions are stated at the top rather than left implied.

## What this is, and what it is not

Unlike its two siblings, this disposition sits beside a **mechanical** check. X1 is the one
interface of the three for which ETSI publishes a machine-readable definition, and this
package uses it in both directions:

- **`TestRenderedResponsesValidate`** validates what this element *emits* against the
  published XSD. It catches a malformed answer.
- **`schema_drift_test.go`** compares the schema's own content models against the structs
  this package declares, and fails on an unmodelled element. It catches what this element
  fails to *read* — the class that produced two earlier defects, where an unmodelled
  `xs:sequence` element was silently discarded and the task acknowledged with the
  discarded narrowing thrown away.

So the questions this document answers are the ones neither check can reach: **which of the
specification's messages this element implements at all, what it refuses and with which code,
and where a deliberate decision diverges from the prose.** A schema cannot say that a message
type is unimplemented, and it cannot say that a "shall" in clause 6 has no code behind it.

Do not close a question about this package by citing this document alone. It is a reading,
and it is only as current as its version stamp.

## Message envelope — table 6.1-1

| Field | M/C/O | Disposition |
|---|---|---|
| ADMF Identifier | M | Emitted on every message. On inbound, bound per message to the configured responsible ADMF **and** to the peer's X.509 certificate (clause 8.2.4) — 1030 on a certificate mismatch, 1040 on an unexpected ADMF |
| NE Identifier | M | Emitted from configuration. On inbound, a message naming a different NE is refused with 1060 |
| MessageTimestamp | M | Emitted as the TS 103 280 Qualified Microsecond Date Time, rendered to a fixed six digits — see `li/README.md`, *X1 timestamps are rendered to a fixed six digits*, for why that is a conformance decision and not a formatting one |
| Version | M | Emitted as `v1.6.1`. Read below |
| X1TransactionID | C | Echoed on every response. Generated per request when this element is the requester. Substituted when a peer's value is outside the TS 103 280 UUID format — see *Echo substitution* |

**The emitted Version is `v1.6.1`, and the behaviour is built against v1.21.1.** This is a
knowing understatement rather than a claim: clause 4.5 makes minor increments backwards
compatible, so declaring an older revision than you implement is the direction that cannot
mislead a peer into expecting a message you do not answer. The reverse would be. It is
recorded because "the version field says 1.6.1" is otherwise indistinguishable from an
element that was built against v1.6.1 — and this one was not: the 2020 semantics of table
6.2.3-2 and the 3050 ServiceType code both come from later revisions.

**Echo substitution.** Every response echoes the request's `version` and `x1TransactionId`,
and the schema restricts both. A peer sending a value outside the restriction would otherwise
make *our own* answer schema-invalid — and the answer easiest to spoil that way is the one
whose request has been trusted by nothing: the refusal telling a peer it may not task this
element. So a version outside `v1\.\d+\.\d+` is replaced by `v1.6.1`, and a transaction
identifier outside the TS 103 280 UUID format is replaced by a fresh UUID.

The second substitution costs something and it is worth saying who pays. An ADMF matches a
response to its request by that value, so a peer that sent a non-conformant identifier loses
the correlation — but it had no conformant correlation to lose, and echoing the malformed
value would invalidate the whole response, losing the correlation *and* everything else the
message says. A conformant ADMF's value is echoed untouched. A fresh value is chosen rather
than a fixed one so that two refusals to the same peer stay distinguishable.

**A consequence for anyone validating responses**: against a requester that sent a
non-conformant identifier, a conformant server is *required* to answer with a different one.
A strict equality check on the echo is therefore sound only for a requester that always
generates a conformant identifier.

## Tasks — clause 6.2

| Message | Disposition |
|---|---|
| `ActivateTask` (6.2.1) | Implemented |
| `ModifyTask` (6.2.2) | Implemented, mid-interception. Criteria and products may both change; the task is not torn down |
| `DeactivateTask` (6.2.3) | Implemented. An XID the element does not hold is refused with **2020**, per table 6.2.3-2: "it is an error if the XID is not already present at the NE". Not 1020, which is "Unsupported version" |
| `DeactivateAllTasks` (6.2.4) | Implemented, **enabled by default**, which is the specification's own default: "By default (if there has been no agreement in advance) then DeactivateAllTasks is enabled" |

**Task fields refused rather than narrowed.** The rule the element applies is that a field it
cannot honour refuses the task, because acknowledging it would tell the provisioning function
an interception is running that is narrower than the one ordered — and nothing downstream can
discover that:

| Field | Marker | Disposition |
|---|---|---|
| `listOfServiceTypes` | O | Refused, **3050** |
| `listOfTrafficPolicyReferences` | O (annex F) | Refused, 3000/3001. Declared permanently unsupported — see `li/CONFORMANCE.md` |
| `taskDetailsExtensions` other than the LI_T3 one | — | Refused. An extension exists in order to change the meaning of the message carrying it, so an unknown one cannot be ignored. Includes `HeaderReporting`, which TS 33.128 marks C and M in tables 6.2.3-0A and 6.2.3-9 |
| `listOfMediationDetails` | O | Accepted and disregarded, deliberately — `li/README.md`, *Fields accepted and disregarded* |
| `implicitDeactivationAllowed` | O | Accepted and disregarded, likewise |
| LI_T3 `PDRID` and `QERID` | — (TS 33.128 table 6.2.3-7) | **Refused**, 3000/3001. Both name a rule allocated *per PFCP session* and reused across sessions from a low number, and a CC-POI matches a criterion against every session it holds — so a task naming PDR 2 would intercept every subscriber whose session happens to hold a PDR of that number, under that warrant and indistinguishable downstream from the traffic it did name. They cannot be qualified by a session, because a task's criteria are alternatives: naming the PFCP Session ID beside the rule ID widens the interception rather than narrowing it. Declared gap against 6.2.3-7 rather than a silent one; a triggering function needing one session's traffic has `FSEID`, which is exactly that |
| LI_T3 `PDR` whose rule leaves a field to this element | — (same table) | **Refused** where the encoded rule asks the UPF to allocate the UE address or to choose the tunnel endpoint (`CH`). Such a criterion names a value this element assigns, so it can never compare equal to any session's rule: accepted, it is an interception acknowledged and producing nothing. Normalising the assigned fields out of the comparison was the alternative and was rejected — it would make the criterion match every session whose remaining fields agree, widening the interception to make an unusable criterion usable |

**Identifier formats.** `xId`, `dId` and `productID` are all `etsi103280:UUID` in the schema.
A value outside that format is refused with **1010** rather than stored and acted on: an
element that accepts a malformed identifier interoperates with a provisioning function no
conformant one would produce, and hides format defects on both sides until they surface as a
mismatch neither party can attribute.

### Identifier cardinality

`TargetIdentifier` is an `xs:choice` in the schema, and `UPFLIT3TargetIdentifier` is a
sequence of choices. Two decisions about how many members of each are honoured are recorded
here because they are conformance statements and would otherwise live only in an OpenSpec
change, which is not distributed with the code.

**A `TargetIdentifier` populating more than one arm is refused with 1010**, as the schema
violation it is. A message carrying two arms is invalid against the `xs:choice`, so no reading
of it is authoritative, and selecting one would mean the *element* deciding the scope of an
interception the provisioning function ordered. It is a **schema** error rather than a task
this element cannot honour, and the existing ordering — malformed checked before unhonourable
— puts it in the right place: asking whether the contents could be honoured presumes a
well-formed message.

The arms are counted over every field of the structure rather than in the order the mapping
switch happens to try them. That ordering is what let the cardinality go unchecked, so a guard
sharing it would inherit the same blind spot.

**The same rule applies to the inner choice.** `UPFLIT3TargetIdentifier` is a sequence *of*
choices, so several members are valid and several arms of one member are not — and the reason
is unchanged: a member with two arms has no authoritative reading, so selecting one narrows or
widens an interception by this element's decision rather than the provisioning function's.
Also 1010, naming which criterion of how many. Checking the outer choice and not this one
would have left the identical defect at the one level where a CC-POI actually reads its
detection criteria.

**This does not forbid a task from carrying several target identifiers.** The documented
precedence — subscriber identifiers before packet criteria, because a task carrying both is
targeting a subscriber — governs a task's `targetIdentifiers` *list*, where the entries are
legitimate alternatives combined as an OR. What is refused is two arms inside *one*
identifier. The two rules are about different levels of the structure.

**Every member of a `UPFLIT3TargetIdentifier` list becomes a criterion.** It is a SEQUENCE OF
CHOICE, so a list of several is what the structure is for, and a CC-POI is already required to
intercept traffic matching any criterion a task carries. A member that cannot be mapped
**refuses the whole task**, naming which member of how many — the rule already applied to the
outer list, applied one level deeper where it was not. An empty list is refused, unchanged.

Until 2026-08-15 this mapped only the first member and dropped the rest, which acknowledged a
task while running an interception narrower than the one ordered. That under-collection was
invisible to every party: the triggering function was told the task was accepted, and the
mediation function received well-formed product for the criterion that survived.

## Destinations — clause 6.3

| Message | Disposition |
|---|---|
| `CreateDestination` (6.3.1) | Implemented. `dId` validated as the schema's UUID; re-creating an existing DID refused with **2030** per clause 6.3.1.1 |
| `ModifyDestination` (6.3.2) | **Not implemented**, refused with 1080. Optional in TS 103 221-1 |
| `RemoveDestination` (6.3.3) | **Not implemented**, refused with 1080. Optional |
| `RemoveAllDestinations` (6.3.4) | Implemented, **disabled by default** — answered with the specification's own error, 8020, when disabled. When enabled, refused with **8010** while any destination is still referenced by a task, which is the guard the specification itself puts on bulk removal |

The asymmetry between bulk deactivation (on by default) and bulk destination removal (off by
default) is the standard's, not this element's. Deactivating everything fails safe —
interception stops, which is the direction this capability fails in anyway. Removing every
destination is not symmetric with that: it strands an element that is still tasked and now has
nowhere to deliver.

**`deliveryAddress` must be an IP address and port.** A URI, an E.164 number or an email
address is refused with **6020**, the registry's own entry for an unsupported delivery address
type.

**Destination sets (`dSId`)** are refused. A set is a `DestinationSetDetails` Generic Object
(annex E) and this element implements none, so a `dSId` can never name anything it holds while
carrying failover and duplication semantics an acknowledgement would silently promise.
Declared permanently unsupported — see `li/CONFORMANCE.md`.

## Interrogation — clause 6.4

**All eight messages clause 6.4.1 makes mandatory are implemented**: `GetTaskDetails`,
`GetAllDetails`, `GetAllTaskDetails`, `GetDestinationDetails`, `GetAllDestinationDetails`,
`GetNEStatus`, `ListAllDetails`, `GetAllGenericObjectDetails`.

Two properties of the answers matter more than the coverage:

- **Holding nothing is a successful empty answer, not an error.** An ADMF reconciling after a
  restart must be able to tell "this element holds no tasks" from "this element would not
  say".
- **`GetAllGenericObjectDetails` answers with its object list omitted**, not empty. That is
  how the standard states that Generic Objects are unsupported — tables 6.4.6.1-2 and
  6.4.9.1-2 mark the lists **C** and say they "may be omitted if Generic Objects are not
  supported by the NE". An empty list would claim the capability is implemented and none is
  held.
- **`GetNEStatus` answers for the conditions the element can currently observe**, and stops
  reporting each when it stops holding — `mdfUnreachable` while delivery is failing,
  `x3EgressDown` while the datapath egress is down.
- **`destinationDeliveryStatus` answers from the delivery layer**, not from a constant.
  `deliveryFault` while the element cannot reach that destination's endpoint,
  `activeAndWorking` while it can, computed per request and never cached — so a destination
  that recovers is reported as recovered without anything having to clear a stored flag. The
  answer comes from the same reachability state `ReportDestinationIssue` reports from, which is
  the point: until 2026-08-19 this field was hard-coded `activeAndWorking`, so an element that
  had just told the ADMF an endpoint was unreachable answered "working" when the ADMF checked.
  Interrogation is how a provisioning function checks a pushed report, so the answer it would
  have acted on was the wrong one — and wrong in the unsafe direction, claiming product was
  arriving when it was not. An element that supplies no reachability answer at all still
  reports `activeAndWorking`; that is now a stated default rather than a claim made on its
  behalf.

`GetTaskDetails` round-trips a task's target identifiers back into the vocabulary the request
used, across all fifteen identifier types, so an ADMF can compare what the element holds
against what it believes it sent.

### What the status answer does not cover — declared 2026-08-25

`GetNEStatus` answering "the conditions the element can currently observe" is only half a
statement. **The conditions it does not answer for are named here**, so that "no faults" is a
stated answer rather than an omission. Until now it was an omission.

**The CC-POI does not answer for a disagreement between its record of what it programmed and what
the datapath actually holds.** It cannot: the BESS `ExactMatch` module carrying each FAR's
duplication flag accepts `add`, `delete`, `clear` and `set_default_gate` and offers no read, so the
element's own record is the only copy of that state on the control-plane side. There is no peer to
ask, and so no path that could ask again.

The consequence is stated rather than left to be inferred. Where a rule is programmed into the
datapath but not recorded — the case `omec-project/upf#1219` exists to remove — content can be
duplicated with no task covering it, and **an interrogation of this element will answer that no
fault holds**, because by its own record none does. The copies are dropped as unattributable rather
than delivered, so no agency receives them; the condition is invisible from both ends.

Three things bound it, and none of them makes it observable:

- A monotone set of every FAR ever told to duplicate means that whenever duplication is
  re-derived, "off" is pushed for such a FAR whatever the record claims.
- A re-derivation is triggered by any session event touching such a FAR, not only by a tasking
  change, so an ordinary session event corrects it.
- The correction is **blind**: it pushes defensively and never learns whether the datapath had
  diverged, so the element cannot report the moment a divergence *ends*.

A divergence therefore persists until the next event touching that session. For an idle,
long-lived session there may be none.

**Corrected 2026-08-26 — the divergence itself is detectable, and this entry first said it was
not.** Two different events were conflated. The *recovery* is unobservable, for the reason above.
The *onset* is not: it happens when a batch of rule writes fails to complete within its deadline,
and at that point the element holds both facts it needs — that the batch was not confirmed, and
whether the rules in it carried duplication. Nothing in the datapath has to be read to know this;
it is the element's own send path.

So of the two reporting routes, only one is closed:

| Route | Available | State |
|---|---|---|
| Answer for it in `GetNEStatus` — a condition that currently holds | **no** — needs a read the BESS module does not offer | declared here |
| Report the onset when it happens — an event, over the push mechanism | **yes** | **not implemented** |

The second is a gap, not a limitation, and it is the one that matters: an unconfirmed write of a
duplicating rule is precisely the moment over-collection may begin. Until it is reported, the
element is silent about a condition it is able to detect. Recorded so the distinction is not lost
again — declaring a condition unobservable when only half of it is unobservable understates what
the element owes.

Closing this needs a read path into the datapath, which needs a command the BESS module does not
have. It is declared here rather than deferred silently because the requirement is on the element
regardless of whether the capability exists: a condition whose observation and classification
cannot be made to agree must be named, not omitted.

## Issue reporting — clause 6.5

| Message | Disposition |
|---|---|
| `ReportTaskIssue` (6.5.2) | Implemented, with the closed `TaskReportType` enumeration and the clause 6.7 issue codes |
| `ReportDestinationIssue` (6.5.3) | Implemented, naming the DID. See *Scope, and the ending of a fault* |
| `ReportNEIssue` (6.5.4) | Implemented, with the closed `TypeOfNEIssueMessage` enumeration — `Warning`, `FaultCleared`, `FaultReport`, `Alert` — and issue codes from table 6.7-3 |
| `TopLevelError` (6.1) | Implemented: an unparseable request is answered with `X1TopLevelErrorResponse` and its four fields, at HTTP 200 per clause 7.2.2.2 |

**Reports are throttled to one per issue type per 30 seconds**, and this is a conformance
statement rather than a performance one: an ADMF that receives one report of a persistent
fault has been told about it, and an ADMF flooded off the interface has not. It also means a
condition that recurs inside the window is reported once, so a report is evidence that a
condition occurred and not a count of occurrences.

**A failed report has nowhere to go.** The LI plane must not surface faults through any
channel but this one, so a report that cannot be delivered is discarded rather than logged.
That is deliberate — writing the error anywhere general would be the disclosure this plane
exists to avoid — and it means the fault channel is best-effort by construction.

### Scope, and the ending of a fault

Clause 6.5.1 scopes an issue three ways — to a task, to a delivery destination, or to the
whole network element — and **the scope is what tells a provisioning function where to act**.
Until 2026-08-15 this element collapsed the middle case into the third: every site that
noticed an unreachable mediation function reported `mdfUnreachable` at element scope, so an
ADMF that had provisioned several destinations learned one of them was unreachable and could
not learn which.

A destination-scoped fault is now reported as one, naming the DID. **Naming it is not a
widening of what this channel discloses**: it is the provisioning function's own identifier
for an endpoint it created, and it names neither a target nor a warrant. Where one endpoint
serves several provisioned identifiers, the fault is reported for each — the provisioning
function's unit of action is the destination it created, and reporting per endpoint would
require it to know how this element resolves them.

**A fault that ends is reported as having ended**, per clause 5.3 — "The NE shall also
indicate that a fault has been cleared (see clauses 6.5.2 and 6.5.3) unless otherwise
configured" — as `AllClear` at task and destination scope and `FaultCleared` at element
scope. Both values were declared in this package from the beginning and emitted by nothing,
so an ADMF told a fault began was never told it ended.

Three properties of how that is done, because each is a place the obvious implementation is
wrong:

- **One party owns both edges.** Reachability is re-observable — every supplier answers from
  state its senders already hold — so an ending is detectable, which is what makes the
  clearing report possible at all. Nothing in the delivery layer signals recovery, and adding
  a recovery callback beside the failure one would have put edge detection at five sites
  across three network functions, each free to disagree about what "recovered" means. An
  element where one party announces and another retracts eventually announces something
  nobody retracts.
- **The report is no later than it was.** Moving it off the delivery path would otherwise
  have delayed first notice by up to one sampling interval; the sites that used to report now
  ask the watcher to sample immediately, so the decision moved and the promptness did not.
- **A fault that cannot be re-observed gets no clearing report.** A destination that could
  not be *prepared* is a credential or configuration fault rather than a reachability one,
  and a fault that cannot be observed to hold cannot be observed to end. Those are still
  reported where they are noticed, at element scope. This is the existing
  event-versus-condition rule applied, not a second mechanism.

**Clause 5.3 also says "The NE shall remember which of the XIDs are in fault and whether the
NE itself is in a fault situation", and that does not conflict with this element's status
answer being recomputed.** What is remembered is *what has been said to the provisioning
function*, which is the only thing a clearing report can be derived from — knowing a fault
cleared requires knowing it was previously set, and no amount of re-observing the present
supplies that. The status answer remains determined from what is observable when it is asked
and remains not a history of what was reported. These are the standard's own two mechanisms,
answering "what changed" and "what holds now", and each is insufficient alone.

**Report rate limiting is scoped to the condition, not to the message type.** One issue type
was the right key while every report was element-scoped; it becomes wrong the moment a report
names a destination, because two destinations failing inside one window would be one report
and whichever failed first would hide the other. The limit also does not apply across a state
change: a fault beginning and that same fault clearing are two events, not a repetition, and
throttling the second against the first would report a fault this element never retracts.

### The withdrawal-durability surface

`fix-li-withdrawal-durability` added X1-visible behaviour and is archived, so it can no longer
carry a documentation task. It is recorded here because there is nowhere else in a
distributed document that it appears.

- **`OnTaskChange`** replaced the `OnActivate`/`OnDeactivate` pair as the lifecycle callback,
  and the reason is an X1 semantics one. A `ModifyTask` keeps the XID, so "the old task" and
  "the new task" share a key; a POI receiving them as two events had to infer an ordering the
  provisioning interface never states, and where it installed state for the new task and
  removed state for the old under that shared key, the removal could reclaim what the
  installation had just created. One event per transition, carrying the task as it was and as
  it becomes, states what X1 actually said.
- **An exact replay is not a transition and fires nothing.** Re-provisioning is how a
  provisioning function restores tasking after a restart, and it must not re-emit records
  reporting the beginning of an interception that never stopped.
- **`OnPurge` names its reason** — `PurgeWithdrawal`, `PurgeBulkDeactivate`,
  `PurgeKeepaliveLapse` — because only the third is unasked-for. A purge an ADMF requested and
  a purge caused by that ADMF falling silent are the same event to the element and completely
  different events to an operator.
- **`taskingWithdrawalFailed` and `taskingWithdrawalStuck` are separate conditions.** The
  first says the last attempt to withdraw failed; the second says authority was removed some
  time ago and content is probably still flowing. Repeating the first would never say the
  second, and the operator action differs.
- **Withdrawals are retried rather than forgotten**, and the endpoint keeps receiving
  keepalives while a withdrawal is pending — deliberately, because a withdrawal in flight is
  tasking this function is still answerable for.
- **`reconcileFailed`** is the same ignorance arrived at from a restart rather than from a
  refused instruction, and is reported distinctly for the same reason.

## Pings and keepalives — clause 6.6

`Ping` (6.6.1) and `Keepalive` (6.6.2) are both implemented. The keepalive fail-safe — purging
all tasking when the controlling function stops answering within the configured window — is
**opt-in**, off unless a window is configured, and a window that is present but unparseable is
an error rather than a silent "off": a deployment that asked for the fail-safe and did not get
it holds tasking nothing will ever reclaim.

**Only an authenticated message resets the watchdog.** Unauthenticated traffic must not, or
anyone able to reach the X1 port could hold the fail-safe open indefinitely while the real
ADMF is gone.

## Protocol errors — clause 6.7

Table 6.7-3 instructs implementers to use the most specific code they can, and this element
does. The codes it emits, and what each means here:

| Code | Meaning | Where |
|---|---|---|
| 1010 | Syntax/schema error | An identifier outside the format the schema defines, or a `targetIdentifier` populating more than one arm of the schema's choice |
| 1030 | ADMF Identifier does not match certificate details | Clause 8.2.4 binding |
| 1040 | Unexpected ADMF Identifier | A peer in the LI domain that is not this element's responsible ADMF |
| 1060 | Unexpected NE Identifier | A message addressed to a different element |
| 1080 | Unsupported request | An unimplemented message type, and the Generic Object CRUD |
| 2020 | XID does not exist on NE | `DeactivateTask` / `GetTaskDetails` for tasking not held |
| 2030 | DID already exists on the NE | `CreateDestination` re-creating a DID |
| 3000 / 3001 | Generic ActivateTask / ModifyTask failure | Task details this element cannot honour and has no more specific code for |
| 3050 | Unsupported ServiceType | `listOfServiceTypes` |
| 6000 | Generic destination failure | |
| 6020 | Unsupported DeliveryAddress type | A URI, E.164 number or email address |
| 8010 | Destinations in use | `RemoveAllDestinations` while a task still references one |
| 8020 | RemoveAllDestinations not enabled | |

**Malformed is checked before unhonourable**, and the ordering is deliberate: a message that
violates its schema has no authoritative reading at all, so asking whether the element could
honour its contents presumes something not established.

## Generic Objects — clause 6.8

The whole capability is **refused, not acknowledged**. `CreateObject`, `ModifyObject`,
`GetObject`, `DeleteObject`, `ListObjectsOfType` and `DeleteAllObjects` all return 1080.

This is the conditional half of the pair: clause 6.8.6 makes `DeleteAllObjects` conditional on
supporting Generic Objects, and clause 6.8.1.1 provides for an NE that cannot store an object
type. The *mandatory* half — the `GetAllGenericObjectDetails` query — is answered
successfully with the list omitted, as above. Declared permanently unsupported; the reasoning
is in `li/CONFORMANCE.md`.

## Peer authentication — clause 8

Mutual TLS from an X0-provisioned LI PKI, with the peer certificate checked **per message**
rather than per connection: a certificate proves membership of the LI domain and not which
element the peer is, so clause 8.2.4's identity binding is what says this particular peer may
task this particular element. An attempt that fails it is refused silently and reported to the
ADMF as `x1AuthFailed` — nothing is malfunctioning, but somebody inside the LI trust domain is
attempting to task or untask network elements, and that channel is the only place it can be
said.

**One responsible ADMF per network element.** A second identity is refused.

## This element as an X1 client

The SMF acts as a CC Triggering Function over LI_T3, which makes it an X1 *requester* against
the UPF's CC-POI. Three dispositions belong to that direction.

**The destinations a trigger names are the task's, not the triggering function's.** A CC-TF
resolves the warrant's own X3 destinations, provisions each distinct endpoint at the POI with
`CreateDestination`, and names those identifiers on the trigger. Its configured `mdf3` serves
only a task that names no X3 destination the element can resolve — the same three-source
precedence, and the same fallback, that the IRI path applies to `mdf2`.

Until 2026-08-17 it did not. A task's X3 destinations were parsed, resolved, carried into the
task and then ignored: every trigger named one endpoint, the one in the triggering function's
own configuration. With a single agency that is invisible. With two, both agencies' **content**
— the subscriber's own traffic, not metadata — arrived wherever configuration happened to
point, which is the disclosure `li-security-isolation` forbids unconditionally for every
product type and every delivery path. It survived the equivalent fix on the IRI path because
that fix was made in the IRI-POI, and the content path resolves its destinations somewhere
else entirely.

**A change to a task's labelling reaches the triggers already installed for it.** Where a
`ModifyTask` changes the `productID` a warrant's product is labelled with, its correlation
value, or its X3 destinations, the CC-TF sends a `ModifyTask` to each POI holding one of that
warrant's triggers, restating the session's own detection criterion and correlation. The
trigger is not withdrawn and reinstalled: content the warrant still authorises is not
interrupted to change a label. An IRI-POI reads these from the task per record and so picks
them up at once; a triggered POI reads them from a trigger built once, and without this the
two diverge — signalling under one warrant identifier and content under another, both
well-formed, with nothing in either stream to show they were meant to join.

**Every response is bound to the request that produced it** — the third disposition, and the
one the two above both lean on when they fail. In one validator both response readers go
through. Refused unless all of the following hold:

| Check | Why |
|---|---|
| Exactly one message | Every request this element sends asks one question; clause 6.1 makes a ResponseContainer "all the responses to the requests in the container". Taking the first of several would be choosing which answer to believe |
| The response type is the request type's | Catches a peer answering a different question. An `ErrorResponse` is admitted, since it is a legitimate answer to any request |
| `x1TransactionId` equals the one sent | This message is the answer to *this* request |
| `neIdentifier` is the element addressed | The only check that can detect a misroute |
| `admfIdentifier` is this element | The client-side form of the binding the server already performs |
| The version is one this element speaks | |

Every field checked is a member of the schema's `X1ResponseMessage` base type, so every
response type carries all of them and each check can be **required** rather than applied only
when present. That was measured against the responder rather than read off the schema alone,
because a required check against a field a peer never sends is a permanent refusal by
construction — and on the withdrawal path a permanent refusal holds open both the withdrawal
and the fail-safe that would otherwise have completed it.

**Deliberately not required: an acknowledgement.** `oK` is *not* on the base type, and a
`GetAllDetailsResponse` carries none — it carries `neStatusDetails` and three lists. A
validator requiring one would refuse every details answer this element receives, which on a
reconciliation path means never learning what a POI holds. It is checked by the callers whose
own response type defines one.

**A validation failure is reported distinctly from a peer's refusal**, as
`x1ResponseUnattributable`. A refusal is a task-level condition the triggering function can
attribute to a warrant; an answer that cannot be bound to its request is element-level,
because which task it concerned is exactly what has not been established. The distinction is
not cosmetic on the withdrawal path: a systematic mismatch produces a pending entry that never
clears, and pending entries keep their endpoint's keepalives flowing, so the POI's own
fail-safe cannot reclaim the tasking either. Reported only as `taskingWithdrawalFailed`, that
presents as a POI at fault while the POI is answering perfectly well and being disbelieved
here — and the operator action is the opposite one.

Until 2026-08-15 none of this was checked. The requester posted a request and read the first
message, checking only whether it carried `errorInformation` and — on one of its two readers,
not the other — whether it carried an acknowledgement at all.

Two limits on what the binding achieves, stated so it is not credited with a property it has
not got:

- **Three of the four identity fields are echoes**, copied by a conformant peer straight off
  the request, so any endpoint that received the request can return them correctly. They
  detect a *confused* answer, not a lying one. Only `neIdentifier` is the peer's own assertion
  of who it is, and an endpoint that wants to be believed states whatever the requester
  expects. Mutual TLS and the clause 8.2.4 binding are what bound the lying case; this does
  not extend them.
- **A response's `messageTimestamp` is deliberately not checked for freshness.** It would need
  a clock comparison and a tolerance, both deployment questions, to defend against replay
  inside the LI domain by a certificate holder — a threat this element does not otherwise
  address. Recorded so the omission reads as a decision.

**Issue reports read only the transport status of the ADMF's answer**, and that is a
considered non-change rather than an oversight. `ReportNEIssue` and `ReportTaskIssue` are
fire-and-forget by design — the LI plane must not surface faults through any channel but this
one, so a report that cannot be delivered has nowhere to go — and both callers discard the
result. Binding those responses would produce an error nobody reads. What it would establish
is that the *fault channel itself* can be misrouted: an endpoint that is not the ADMF can
acknowledge a fault report, and this element would believe the ADMF had been told. It is
recorded here because that is true and unaddressed, not because a validator with no reader
would address it.

**The peer that answers is this package's own `Server`.** Worth stating, because it bounds
both the risk and the evidence. `Requester` has one caller — the SMF's CC triggering function,
pointed at a UPF's LI_T3 endpoint — and a UPF runs this server. The sipgate reference is an
ADMF and MDF simulator: an X1 *client* toward these network functions, never the responder to
a request they send. The residual is that the endpoint URL is deployment configuration, so a
third-party CC-POI is possible in principle; nothing this project ships or tests has one.

## What this disposition does not cover

An audit that finds nothing is not proof there is nothing, and this one is a reading. Stated
plainly, so nobody mistakes its scope for a clean bill of health:

- **Only the messages this element implements were read closely.** A message refused with 1080
  was checked for whether refusing it is permitted, not for what implementing it would entail.
- **Annexes were read only where a decision depended on one** — annex E for destination sets,
  annex F for traffic policies. The rest were not.
- **The schema checks cover form, not meaning.** `TestRenderedResponsesValidate` and
  `schema_drift_test.go` between them catch a malformed answer and an unmodelled element.
  Neither can notice that a "shall" in clause 6 has no code behind it, which is how both of
  the gaps below were found.
- **Nothing here was verified against a strict third-party ADMF.** The interoperability
  evidence is against the sipgate reference and against this project's own endpoints. A gap
  that only a strict validator would reject has not been exercised.
- **The client direction has the least evidence.** The suite's negative cases are all
  absences — a path removed, a withdrawal watched to fail — and there is no fixture that
  *answers* X1 on the SMF's behalf, so no test has yet observed this element reading a
  well-formed answer it should have refused.

## Known gaps, in order of consequence

**No known gap remains at the top of this list.** The entry that stood here — that
`triggerFaulty` could not be raised against a point of interception by this project — was closed
on 2026-08-20 and is recorded among the closures below, since a gap that has been closed belongs
with the others rather than at the head of a list ordered by consequence.

**Closed since this disposition was written**, most consequential first. Six of the eight were
found by writing it, and none of those six could have been found by the schema checks — that is
the class this document exists for. One, near the end, was found by review rather than by
writing, and it is the same class: a field whose value validated against the schema and
contradicted what the element was reporting elsewhere.

The eighth is the `triggerFaulty` entry that heads the list, and it is the only one that was
found by *writing this document* and then took four further changes to close — it was recorded
as a known gap three times before the mechanism that closes it existed. What it needed was not
a bigger effort but a different one: every attempt assumed a held task would have to carry a
fault state, and the answer was to compute the state when asked.

- **`triggerFaulty` could not be raised against a point of interception (2026-08-20).** The
  condition was declared, encoded and reportable, and the SMF's CC Triggering Function was the
  element that would raise it — but the fault it names has to come from the POI's own answer
  about the task, and this library's POIs could not give one. `taskStatus` answered
  `provisioningStatus: complete` with an empty `listOfFaults` for every task in the store,
  unconditionally, because a task reaches the store only after activation has established that
  the element can carry it out. So a POI that had been triggered, had acknowledged, and was
  producing nothing answered exactly as one that was working.

  **The destination half had already been closed** — `destinationDeliveryStatus` answers from the
  delivery layer, so a POI whose X3 delivery has failed says so when interrogated. What remained
  was a POI whose *duplication* was not in place while its task was held. Those conditions were
  reported, at element scope, by the POI's own `ReportNEIssue`; the information reached the
  triggering function and the attribution did not, which is precisely what `triggerFaulty` is
  for.

  Closed by `WithTaskFaults`, an element-supplied answer consulted when `taskStatus` is
  rendered, and by the CC-POI supplying it from datapath state it already holds. **Asked rather
  than stored**, which is what the note here expected to be the obstacle: giving a held task a
  fault *state* would have required every POI to track one and to clear it, and a stored fault
  goes stale — the answer is instead computed from the record of what the datapath was last told,
  compared against what the task's criteria select. The SMF then reports the condition against
  the warrant rather than against itself; it had been reading the POI's `taskStatus` all along and
  reporting at element scope, because there was nothing per-task to attribute.

  Also closed by that: the note that **no end-to-end section could exercise it**. The condition
  no longer rests on interoperation with a third-party POI — this project's own CC-POI populates
  a task's `listOfFaults`. `tests/e2e-li/sections/31_task_scoped_faults.sh` drives it against
  the deployed CC-POI, using the condition arrangeable from outside: a content task whose
  criterion selects no session the element holds. It asserts the attribution as well as the
  presence, since an element answering one condition for every task would satisfy a presence
  check and leave the triggering function exactly where it was.

  Named here rather than left as "a suite could": a disposition that claims a condition is
  drivable end to end, with nothing driving it, is the same defect as one that claims a
  constraint is checked. The remaining condition — a duplication rule the datapath refuses —
  needs a datapath that can be made to refuse one on demand, which this deployment cannot do;
  it is covered by `pfcpiface.TestATaskTheDatapathIsNotDuplicatingReportsAFault`.

- **`ReportDestinationIssue` was not implemented (clause 6.5.3)**, so an issue relating
  specifically to one DID was reported at network-element scope instead. The information
  reached the ADMF; the scoping clause 6.5.1 draws did not. See *Scope, and the ending of a
  fault*.
- **No fault was ever reported as cleared (clause 5.3).** `AllClear` and `FaultCleared` were
  both declared and emitted by nothing, for task issues as well as destination ones, so an
  ADMF told a fault began was never told it ended. Same section.

- **An X1 response was not bound to the request that produced it.** A well-formed
  acknowledgement from the wrong element was accepted, so a triggering function could record
  an interception as installed at a POI that never received the trigger. Silent in both
  directions. See *This element as an X1 client*.
- **A `UPFLIT3TargetIdentifier` list was narrowed to its first member**, so a task naming
  several detection criteria was acknowledged and a narrower interception run. See *Identifier
  cardinality*.
- **A `TargetIdentifier` populating more than one arm of the schema's choice was accepted**,
  as whichever arm the mapping switch reached first, rather than refused. Now 1010.
- **`TopLevelError` was not implemented (clause 6.1)**, and the answer violated clause 7.2.2.2
  as well. An unparseable request was answered with an HTTP 400 carrying the XML decoder's own
  message. Clause 7.2.2.2 is explicit that "HTTP error codes shall only be used to indicate
  HTTP-level errors, and shall not be used to indicate errors with the X1 responses
  themselves"; a request that arrived intact and could not be parsed is an X1-level error. It
  is now a 200 carrying `X1TopLevelErrorResponse` with its four fields — and no
  `x1TransactionId`, which table 6.1-1 says "shall be omitted for 'TopLevelError' situations",
  consistently, since the identifier would have had to come from the message nobody could
  read. The ADMF identifier comes from configuration, or from the peer's certificate where
  this element has none configured, which is clause 6.1's own provision.
- **`destinationDeliveryStatus` was hard-coded `activeAndWorking`** (clause 6.4.5), so the
  answer to an interrogation contradicted the element's own `ReportDestinationIssue` about the
  same endpoint. Closed 2026-08-19; see *Interrogation*.

**Deliberate divergences, which are not gaps**, are recorded above with their reasoning rather
than repeated here: the emitted Version, the echo substitutions, the timestamp rendering, the
report throttle, and the four capabilities declared permanently unsupported in
`li/CONFORMANCE.md`.
