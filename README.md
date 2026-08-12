<!--
SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
SPDX-License-Identifier: Apache-2.0
-->

# li — Lawful Interception for SD-Core

This module provides the in-network **Points of Interception (POIs)** and the
X1/X2/X3 interfaces that let SD-Core meet a Communication Service Provider's
Lawful Interception (LI) obligations. It is imported by the AMF, SMF, and UPF.

The Administration (ADMF/LIPF) and Mediation & Delivery (MDF2/MDF3) functions
are **external, third-party systems** (e.g. the sipgate X1/X2/X3 simulator for
testing) — SD-Core implements only the POIs and the interfaces toward them.

LI is **opt-in and undetectable**: with no LI configuration a network function
behaves and looks exactly as before, and even when active it emits nothing to
general logs, metrics, or signalling that would reveal that a subscriber — or
the network element itself — is being intercepted.

---

## How it works

Three network functions act as POIs:

| NF  | Role | Produces | Interface |
|-----|------|----------|-----------|
| **AMF** | IRI-POI | Intercept Related Information (registration, deregistration, location update, identifier (de)association, unsuccessful procedure, start-of-interception) as 3GPP TS 33.128 **xIRI** | X2 → MDF2 |
| **SMF** | IRI-POI + CC Triggering Function | PDU-session xIRI (establishment/modification/release/start-of-interception); instructs the UPF to duplicate a tasked target's user plane, and tasks its interception point with the warrant | X2 → MDF2; PFCP `DUPL` FAR + X1 trigger → UPF |
| **UPF** | CC-POI | Content of Communication — the duplicated user-plane packets — as ETSI TS 103 221-2 **xCC** | X3 → MDF3 |

```
                 ┌─────────────┐
   task warrants │ ADMF / LIPF │  (external)
   over X1 ─────▶│             │
   (mTLS)        └─────────────┘
                   │ X1        │ X1
                   ▼           ▼
              ┌────────┐   ┌────────┐  PFCP   ┌──────┐
              │  AMF   │   │  SMF   │──DUPL──▶│ UPF  │
              │ IRI-POI│   │IRI-POI │  FAR    │CC-POI│
              │        │   │ CC-TF  │───X1───▶│      │
              └────┬───┘   └───┬────┘ trigger └──┬───┘
             xIRI  │   xIRI    │             xCC │
             X2    ▼   X2      ▼             X3  ▼
              ┌──────────────────┐         ┌──────────┐
              │       MDF2       │         │   MDF3   │   (external)
              └──────────────────┘         └──────────┘
```

- The **ADMF** provisions interception tasks (warrants) over **X1** (ETSI TS 103 221-1,
  XML over mutual TLS). All three network functions expose an X1 listener, but the
  UPF's authorised peer is the **SMF**, not the ADMF: the UPF is a *triggered* point
  of interception, and the SMF's triggering function tasks it in the ADMF's role.
- Each tasked network function matches events/traffic against the target
  (by SUPI, PEI, or GPSI) using a local task store — no external lookup at
  interception time.
- **xIRI** is delivered over **X2** to the configured **MDF2**; **xCC** over
  **X3** to the configured **MDF3** (both ETSI TS 103 221-2, mutual TLS).
- **CC takes two interfaces, and needs both.** PFCP tells the UPF *to* copy a
  session's packets; the X1 trigger tells it *whose warrant* the copies serve,
  which correlation identifier to stamp on them, and where to send them. A copy
  the UPF cannot attribute to a warrant is discarded and reported, never delivered,
  because a mediation function attributes product by warrant alone and silently
  drops what it cannot place.
- **CC** works via PFCP: the SMF sets the `DUPL` apply-action + Duplicating
  Parameters on the target session's FAR; the UPF's BESS datapath tees a copy of
  the packets to a userspace socket, and the UPF's X3 shipper frames and
  delivers them.
- **Keepalive fail-safe (opt-in):** when a `keepaliveTimeout` is configured and
  the controlling ADMF goes silent (no X1 message within that window) the network
  function purges all tasking — so warrants never outlive an operational
  controller. It is off until that window is set.
- **Security:** X1/X2/X3 all use mutual TLS with credentials from a dedicated LI
  PKI, kept separate from the SBI certificates. Verification is never skipped.

### Module layout

| Package | Purpose |
|---------|---------|
| `types`  | Target identifiers, tasks, product/delivery types (transport-agnostic) |
| `store`  | Concurrency-safe active-task store, indexed by target identifier |
| `x1`     | ETSI TS 103 221-1 X1 provisioning listener + NE-issue reporter (ADMF direction) |
| `iri`    | 3GPP TS 33.128 xIRI record builders + BER/CHOICE encoder |
| `x2x3`   | ETSI TS 103 221-2 X2/X3 PDU framing + delivery client |
| `mtls`   | Loads the LI PKI credentials and builds the X1/X2/X3 TLS configs |
| `asn1`   | Bundled BER/CHOICE ASN.1 codec used by `iri` |

---

## Feature support

What this module and its network functions implement, and what they do not. The
gaps are listed as plainly as the capabilities: an operator planning an
integration needs both, and a missing feature discovered during a deployment is
more expensive than one read here.

### Supported

| Area | Feature | Notes |
|---|---|---|
| **X1 provisioning** | `ActivateTask`, `ModifyTask`, `DeactivateTask` | ETSI TS 103 221-1, mutual TLS |
| | `Keepalive` and the fail-safe purge of all tasking | Purge is opt-in via a keepalive window; off by default |
| | The whole interrogation set clause 6.4.1 makes mandatory: `GetTaskDetails`, `GetAllDetails`, `GetAllTaskDetails`, `GetDestinationDetails`, `GetAllDestinationDetails`, `GetNEStatus`, `ListAllDetails`, `GetAllGenericObjectDetails` | How an ADMF audits what an element actually holds — and how it reconciles after one restarts. Holding nothing is a successful empty answer, not an error. Every response is validated against the published XSD |
| | `DeactivateAllTasks`, **enabled by default** | The specification's own default. One authenticated message stops every interception on the element — see *[Bulk deactivation is enabled by default](#bulk-deactivation-is-enabled-by-default)* |
| | `RemoveAllDestinations`, **disabled by default** | Answered with the specification's error when disabled (8020); when enabled, refused while any destination is referenced by a task (8010) |
| | `CreateDestination` | DID → endpoint; re-creating a DID is refused (clause 6.3.1.1) |
| | Clause 8.2.4 peer authentication | Identity binding checked per message: 1030 / 1040 / 1060 / 1080 |
| | NE-initiated fault reporting | `ReportNEIssue`, `ReportTaskIssue`, with schema-valid message types and issue codes |
| **Targets** | SUPI/IMSI, PEI/IMEI, GPSI/MSISDN | |
| | Eight of the nine LI_T3 detection criteria of TS 33.128 table 6.2.3-7 in full, and the ninth for IPv4 | Session ID, tunnel ID, TCP/UDP port, PDR ID, QER ID, network instance, tunnel direction, PDR; UE IP Address for IPv4 — see *LI_T3 detection criteria* below |
| | Several criteria on one task, matched as alternatives | Traffic matching any of them is intercepted, and ships **once** however many matched |
| | Criteria replaced by `ModifyTask`, mid-interception | Table 6.2.3-8. The task is not torn down: superseded traffic stops, newly selected traffic starts, attribution is unchanged |
| | A criterion this element cannot evaluate is refused **before** the task is acknowledged | Accepting one would leave the requesting function believing an interception is running that can never produce anything — undiscoverable from outside |
| **IRI (X2)** | AMF: registration, deregistration, location update, identifier (de)association, unsuccessful procedure, start of interception with a registered UE | 11 record types in total |
| | SMF: PDU session establishment, modification, release, start of interception with an established session | |
| | TS 33.128 ASN.1 (BER) encoding | Verified against the published module, not against our own codec |
| | Activation mid-session, on already-established sessions | |
| | Delivery asynchronous, off the signalling path | A slow MDF cannot delay a target's signalling |
| **CC (X3)** | UPF CC-POI duplication via the PFCP `DUPL` apply-action | Both directions |
| | The CC-POI enables duplication itself, for criteria the SMF has not marked | So a task keyed by an address or a tunnel intercepts, rather than being acknowledged and producing nothing |
| | Duplication survives the SMF's own session modifications | Re-derived from the tasking wherever rules change; the SMF's `DUPL` bit is never overwritten |
| | Criteria apply to sessions established after the task | No re-tasking when a subscriber attaches later |
| | Copies the duplication over-collected are dropped before delivery | See *the coverage model* below |
| | LI_T3 triggering interface, with the SMF as triggering function | TS 33.128 clause 6.2.3.3 |
| | Correlation joining X2 and X3 | The session's real F-SEID |
| | `ProductID` → X2/X3 XID labelling | TS 103 221-1 clause 6.2.1.2, as a general rule |
| | Untasked or unattributable content dropped **and reported** | Never delivered with a label an MDF would discard |
| **Security** | Mutual TLS on X1, X2 and X3, from an X0-provisioned LI PKI | |
| | Undetectability: nothing in any general operator log | No target, warrant, ADMF/MDF address or LI configuration |
| | Unauthorised peers refused silently, reported only to the ADMF | |
| | Per-warrant delivery isolation | Several agencies' warrants concurrently |
| | Subscriber traffic and usage accounting unchanged | Measured exactly once despite duplication |
| **Operational** | UPF restart: interception continues, with no operator action | The destination is re-provisioned and the POI re-triggered |
| | SMF/AMF restart: tasking is lost, the ADMF is told, and it can interrogate the element to reconcile | The whole sequence in one place: *[What happens after a restart](#what-happens-after-a-restart-and-what-the-admf-does-about-it)* |
| | Tasking left behind by a previous process is withdrawn at startup | |
| | UPF address change (its Service recreated): triggering recovers | No SMF restart needed |

### Not supported

| Area | Feature | Why, or status |
|---|---|---|
| **Delivery destinations** | **An ADMF cannot set an IRI-POI's X2 destination over X1** | The AMF and SMF deliver to the `mdf2` in their own configuration. `CreateDestination` is accepted and a task's `listOfDIDs` is parsed, but unknown DIDs are skipped and the IRI-POIs ignore them. Only the **CC-POI's X3** destination is provisioned over X1, and by the SMF as triggering function rather than by the ADMF |
| | `ModifyDestination`, `RemoveDestination` | Not implemented. Both are optional in TS 103 221-1, unlike the interrogation set above |
| **Generic Objects** | The whole capability, so `CreateObject`, `ModifyObject`, `GetObject`, `DeleteObject`, `ListObjectsOfType`, `DeleteAllObjects` | **Refused**, not acknowledged. These are conditional — "`DeleteAllObjects` shall be supported *if* the implementation supports Generic Objects" — and an acknowledgement would tell an ADMF its object had been stored. The mandatory *query*, `GetAllGenericObjectDetails`, is answered with its object list **omitted**, which is how the standard says a Generic-Object-less element answers; an empty list would claim they are implemented and none is held |
| **Targets** | The IPv6 form of one LI_T3 detection criterion, **UE IP Address** | *Refused*, not ignored — and an interception-scope question rather than an LI one: SD-Core has no IPv6 PDU sessions to intercept. See the breakdown below |
| | Service-type scoping of a task (`listOfServiceTypes`) | Not applied, so a task carrying it is **refused** rather than acknowledged — accepting it would deliver every service for the target when a narrower set was authorised |
| **Provisioning** | More than one ADMF per network element | One responsible ADMF; a second identity is refused |
| **State** | Warrants persisted across a restart | Deliberate. Interception must not outlive contact with the function that authorised it, so the failure direction is "stopped" — which means a planned upgrade needs re-provisioning in the runbook. What the ADMF is told, and what it asks next, is in *[What happens after a restart](#what-happens-after-a-restart-and-what-the-admf-does-about-it)* |
| **Scope** | HI1/HI2/HI3 and delivery to the LEMF | The mediation function's role, not a POI's |
| | 4G/LTE interception (MME, S-GW) | 5G only |
| | IMS/voice and SMS content | |
| | Location detail beyond the mandatory minimum | Records carry the minimal `Location` the schema requires; richer detail is deferred |

#### LI_T3 detection criteria

TS 33.128 clause 6.2.3 requires a CC-POI to support *at least* the identifier
types in table 6.2.3-7. What this implementation does with each:

| Identifier type | ETSI TS 103 221-1 element | Supported | Resolved against |
|---|---|---|---|
| GTP Tunnel ID | `gtpuTunnelId`, or the extension's `FTEID` | **Yes** | The uplink PDR's `tunnelTEID`, and its `tunnelIP4Dst` where the criterion names an address |
| UE IP Address (IPv4) | `ipv4Address` | **Yes** | The PDR's `ueAddress` |
| UE IP Address (IPv6) | `ipv6Address` | No | Nothing to resolve against: SD-Core has no IPv6 PDU sessions |
| UE TCP/UDP Port | `tcpPort` / `udpPort` | **Yes** | The PDR's SDF filter, or the packet where the filter does not constrain the port |
| PFCP Session ID | `TargetIdentifierExtension/FSEID` | **Yes** | The session's own SEID |
| PDR ID | `TargetIdentifierExtension/PDRID` | **Yes** | `pdrID` |
| QER ID | `TargetIdentifierExtension/QERID` | **Yes** | `qerIDList`, so every PDR the QER polices |
| Network Instance | `TargetIdentifierExtension/NetworkInstance` | **Yes** | The PDI's Network Instance, so every session on that DNN |
| GTP Tunnel Direction | `TargetIdentifierExtension/GTPTunnelDirection` | **Yes** | The PDR's source interface, and the datapath's tag on each copy |
| PDR | `TargetIdentifierExtension/PDR` | **Yes** | The encoded Create PDR IE, parsed with the agent's own PFCP parser and compared against a session's rules in that form |

A task's criteria are a list, and its entries are **alternatives**: traffic
matching any one of them is intercepted, once. A triggering function needing
traffic that matches a *combination* of properties cannot express it as a list.

What is left is the IPv6 form of UE IP Address.

That gap is **not an interception limitation**: SD-Core has no IPv6 PDU
sessions to intercept. The SMF cannot allocate an IPv6 UE address — its allocator
computes the pool size over 32 bits, and the NAS session-accept it would build
leaves the PDU address zero-length — the WebConsole provisions subscribers with
`IPv4` as the only allowed session type, and the UPF rejects a PFCP session whose UE
address is not four octets. An IPv6 criterion could therefore never select traffic,
whatever the CC-POI did with it. It becomes supportable when the core does, not
before.

It is **refused**, not ignored: a criterion this element
cannot evaluate would intercept either nothing — mandated interception silently
producing no product — or everything, which is collection beyond the
authorisation. Both are worse than a refusal the triggering function can report to
the LIPF. The refusal arrives *before* the task is acknowledged, so nothing is left
in place appearing to intercept.

Two readings are worth stating because the schema does not.

**A `PDR` criterion is a Create PDR IE**, and it is compared in the parsed form this
agent holds its own rules in, not octet-for-octet. PFCP puts no ordering on the IEs
inside a grouped IE, so two encoders can describe one rule in different bytes and an
octet comparison would miss the match; parsing both sides with the same parser makes
that parser the canonical form. Two consequences follow: fields the agent does not
retain do not take part, so rules differing only in an IE it ignores compare equal;
and the fields a *session* assigns — which session the rule belongs to, the address
that sent it, the counter this UPF chose — are excluded, since they are not
properties of the rule the triggering function described. An Update PDR is refused
even though it parses: one agreed form, so a triggering function cannot say the same
thing two ways and get different answers.

**`GTPTunnelDirection` is
read relative to the UPF.** `Inbound` is the tunnel it receives on, so uplink;
`Outbound` is the tunnel it sends on, so downlink. The enumeration carries no
definition of the vantage point, and taking it the other way round would intercept
the opposite direction to the one authorised.

#### The coverage model

Duplication is an apply-action on a **FAR**, and PDRs reference a FAR, so
duplication covers *the traffic of every PDR pointing at that FAR* — not a criterion,
and not necessarily a whole session. Two consequences an operator should be able to
predict:

- **Coverage is enabled per FAR.** Where a criterion selects some but not all of the
  PDRs sharing a FAR, enabling duplication copies more traffic than the criterion
  identifies. FARs are never split or cloned to avoid this: that would mutate the
  subscriber's own forwarding, which is a surface where two target-visible defects
  have already occurred.
- **The excess is dropped before delivery.** A copy is delivered only if it matches
  a criterion, decided from the datapath's tag and the session's rules where
  possible — a criterion selecting one direction is settled by the tag alone — and
  from the packet only for a transport port the rules do not constrain. A copy that
  did not match is not lost content and is not reported as a delivery fault.

So exactness depends on the rule structure the SMF installed, and precision is
restored by filtering rather than by finer duplication. The residual limitation:
where a FAR is shared by several PDRs *of the same direction* and the criterion
selects only some — distinguishable only by their SDF filters — the copies cannot be
separated by tag or direction, and a criterion without a transport-port test will
over-collect within that FAR. Duplication granularity is bounded by the PDR/FAR
structure that exists; this does not provide per-flow duplication.

#### Bulk deactivation is enabled by default

`DeactivateAllTasks` stops **every** interception on a network element, and it is enabled
unless you disable it. That is the standard's default, stated outright: "By default (if
there has been no agreement in advance) then DeactivateAllTasks is enabled." So on an
element with no LI-specific option set, one authenticated X1 message removes every warrant
it holds and tears down what each warrant was doing — a CC-POI's duplication included, not
merely the task list.

Two things follow for anyone who can reach an X1 endpoint:

- **The blast radius is the whole element**, not one warrant. Interception stops; it does
  not restart by itself, and the ADMF is not told separately, because the deactivation
  *is* its own request.
- **Reaching the endpoint is the control.** It is gated by clause 8.2.4 peer
  authentication — an LI-CA certificate whose bound identity is this element's responsible
  ADMF — and by whatever network controls stand in front of the port. See
  *[Restricting who can reach X1](#restricting-who-can-reach-x1)*, which matters more once
  this message is answered than it did when it was refused.

`RemoveAllDestinations` is the opposite way round: **disabled** unless enabled, answered
with the specification's own error text when it is off. The asymmetry is deliberate and is
the standard's, not ours. Deactivating everything fails safe — interception stops, which is
the direction this whole capability fails in anyway. Removing every destination is not
symmetric with that: it strands an element that is still tasked and now has nowhere to
deliver, which is why the standard also guards it — an NE refuses the request while any
destination is still referenced by a task.

Both are library options rather than configuration keys, so a deployment that wants
non-default behaviour sets them where the X1 server is constructed.

#### What happens after a restart, and what the ADMF does about it

Tasking lives in memory. A restarted AMF or SMF therefore holds **no** warrants — see
*Warrants persisted across a restart* above for why that is deliberate — and the whole
recovery path is built out of the messages in this section. In order:

1. **The element says so, unprompted.** On startup with LI enabled and no tasking, it
   sends `ReportNEIssue` with `taskingAbsent`. Nothing else would tell the ADMF: from
   outside, an element holding no warrants is indistinguishable from one holding warrants
   that match nobody.
2. **It withdraws what its previous life left elsewhere.** A restarted SMF removes tasking
   it had triggered at a CC-POI, which no other party could ever remove — the UPF would
   otherwise keep duplicating for a warrant nothing holds.
3. **The ADMF interrogates to find out where it stands.** `GetNEStatus` for the element's
   own state, `ListAllDetails` for the identifiers it holds, `GetAllTaskDetails` or
   `GetAllDetails` for the detail. An element holding nothing answers all of them
   *successfully*, with empty lists — the specification is explicit that empty is not an
   error, and that is precisely the state a restarted element is in.
4. **The ADMF re-provisions.** An `ActivateTask` naming an XID the element already holds
   replaces it rather than being refused, so re-provisioning is safe to repeat and does not
   depend on the ADMF knowing what survived.

What the status answer will *not* say is that this element restarted. `GetNEStatus`
reports the fault conditions that hold at the moment it is asked, computed from what the
element can observe rather than from a history — so nothing needs clearing and no answer
can go stale. Lost tasking is an event, and events travel by the push in step 1. The two
mechanisms answer different questions, "what just went wrong" and "what is wrong now", and
an operator should expect a restarted, re-provisioned element to answer `OK`.

The UPF is the exception to all of this: its triggering function is the SMF, which is still
running, so it is re-provisioned and re-triggered with no operator action. A UPF restart is
invisible to the ADMF.

## Enabling LI

LI is turned on per network function by adding an `li` configuration block. With
no block present, LI is inactive. Before enabling, you need:

1. **LI PKI credentials**, pre-provisioned out of band (the X0 step): this
   network element's certificate + private key, and the LI CA trust anchor.
   Place them at file paths the NF can read — in Kubernetes, a dedicated,
   access-restricted `Secret` mounted at those paths. Use a PKI **separate**
   from the SBI certificates. **The certificates must carry their owner's X1
   identifier** — see [Certificate requirements](#certificate-requirements)
   below; X1 requests from a certificate that does not are refused.
2. An external **ADMF** (to task the NFs over X1) and **MDF2**/**MDF3** (to
   receive xIRI/xCC). Note their addresses.
3. The **LI-enabled NF images** deployed.

The MDF2/MDF3 delivery endpoints come from NF configuration, not from the ADMF's
per-task provisioning over X1 (which this release does not use): the MDF2 from
each AMF/SMF, and the MDF3 from the SMF, which provisions it to every UPF it
triggers — the UPF holds no MDF3 of its own.

### AMF and SMF

Add an `li` block under `configuration` in `amfcfg.yaml` / `smfcfg.yaml`:

```yaml
configuration:
  # ... existing AMF/SMF configuration ...
  li:
    x1Listen: ":8443"                     # address the NF's X1 listener binds (ADMF connects here)
    mdf2: "mdf2.li.example:9000"          # X2 delivery destination (MDF2 host:port)
    neId: "amf-1"                         # this network element's identifier (use "smf-1" on the SMF)
    cert: "/etc/li/certs/tls.crt"         # X0-pre-provisioned LI certificate
    key: "/etc/li/certs/tls.key"          #   its private key
    caCert: "/etc/li/certs/ca.crt"        #   the LI CA trust anchor
    # --- SMF only: content of communication ---
    # The SMF is the CC triggering function. It tasks the interception point in
    # each UPF over that UPF's X1 endpoint, passing the warrant, the session's
    # correlation identifier and this MDF3 address; the UPF holds none of them in
    # its own configuration. A UPF missing from this list will duplicate traffic
    # that nobody can attribute, which the SMF reports to the ADMF as a fault.
    mdf3: "mdf3.li.example:9001"          # X3 delivery destination (MDF3 host:port)
    upfTriggers:
      - nodeId: "upf"                     # the UPF's N4 node address — IP or DNS name (resolved as on the PFCP path)
        x1Url: "https://upf-1:8443/X1/NE" # its X1 endpoint; the host must be a name its certificate covers
        neId: "upf-1"                     # the identifier its certificate is bound to
    # --- optional: NE→ADMF fault reporting + keepalive fail-safe ---
    admfUrl: "https://admf.li.example/X1/NE"  # ADMF X1 endpoint for NE-initiated issue reports
    admfId: "admf-1"                          # responsible ADMF identifier
    keepaliveTimeout: "30s"                   # Go duration; purge tasking if no X1 message within it
```

### UPF

Add a top-level `li` block in `upf.jsonc`:

```jsonc
{
  // ... existing UPF configuration ...
  "li": {
    "x3_sockaddr": "/tmp/li_x3",         // must match the datapath's LI_X3_SOCKET_PATH (see below)
    "cert": "/etc/li/certs/tls.crt",     // X0-pre-provisioned LI certificate
    "key": "/etc/li/certs/tls.key",      //   its private key
    "ca_cert": "/etc/li/certs/ca.crt",   //   the LI CA trust anchor
    "ne_id": "upf-1",                    // this NE's identifier
    "x1_listen": ":8443",                // the triggering interface the SMF tasks it over
    "tf_id": "smf-1",                    // the only element permitted to task it
    "admf_url": "https://admf.li.example/X1/NE",  // optional: NE→ADMF fault reporting
    "admf_id": "admf-1"                  // optional
  }
}
```

The UPF has **no MDF3 address of its own**. It is a *triggered* point of
interception: the SMF's triggering function tells it which sessions to intercept,
under which warrant, and where to deliver the content — so `x1_listen` and `tf_id`
are as essential as the credentials. Without them the UPF can duplicate a
subscriber's traffic but cannot learn whose warrant the copies serve, and content
that cannot be attributed to a warrant is discarded by any mediation function that
receives it. The UPF refuses to start if either is missing, rather than running in
that state.

`tf_id` names the *only* element permitted to task it. The identity is checked
against the certificate the peer presents, so a certificate the LI CA issued to
some other element cannot be used to task this UPF.

The UPF also requires the **content-egress datapath** to be active:

- Run BESS with a pipeline that contains the LI tee (`Replicate` → `GenericEncap`
  → the `liX3` `UnixSocketPort`). Both `conf/up4.bess` — the pipeline deployments
  run by default — and `conf/closed_loop.bess` carry it. A pipeline **without** the
  tee drops a tasked subscriber's traffic outright, because the PFCP agent marks it
  with a forwarding action that such a pipeline has no gate for.

> **Upgrade the BESS pipeline before, or with, the PFCP agent — never after.**
> This applies to **every** UPF, including ones with no `li` block at all, and it
> is the one ordering constraint LI adds to an existing deployment.
>
> The agent writes an extra `fwd_action` value on every FAR it installs, which the
> pipeline's `farLookup::ExactMatch` must declare. BESS rejects a rule whose value
> count does not match the table, so an agent from an LI-capable image running
> against a pipeline from an older one fails **every** FAR insertion — no
> forwarding rules at all, for any subscriber, tasked or not. The two ship as
> separate images (`upf-pfcpiface` and `upf-bess`), so nothing prevents them being
> rolled independently. Pin both to the same release, or roll `upf-bess` first.
>
> The failure is loud (no user-plane forwarding) rather than silent, but it is a
> full data-plane outage and it looks nothing like a lawful-interception problem.
- Set the BESS container's `LI_X3_SOCKET_PATH` environment variable to the **same
  path** as `li.x3_sockaddr` (both default to `/tmp/li_x3`).
- The BESS and pfcpiface containers must **share** that socket path (e.g. an
  `emptyDir` volume mounted at its directory in both containers), so the datapath
  can tee copies to the socket the pfcpiface agent reads.

### Deploying with Helm or OnRamp

The blocks above are what LI reads on disk; deployment tooling sets them for you.

- **SD-Core Helm charts** expose one `config.<nf>.li` intent block per NF, gated by
  `config.<nf>.li.enabled`. The chart merges it into that NF's `configuration.li`
  (the UPF's `li`) and derives the pieces that must stay in step — the X1 bind
  address, the externally-reachable X1 `Service` (a NodePort for the ADMF to reach),
  and the LI PKI `Secret` mount — from the same values, so they cannot drift apart.
  With `enabled: false` (the default) the render is byte-identical to a non-LI deploy.
- **Aether OnRamp** wraps that in the `main-li.yml` blueprint: a single
  `lawful_intercept:` block (ADMF/MDF endpoints + the two X1 NodePorts) flips the
  chart's `config.<nf>.li` values. Its header lists the deployment prerequisites,
  including the out-of-band LI PKI `Secret` and firewalling the X1 NodePorts to the
  ADMF (see [Restricting who can reach X1](#restricting-who-can-reach-x1)).

### Configuration reference

| AMF/SMF (`configuration.li`) | UPF (`li`) | Meaning | Required |
|---|---|---|---|
| `x1Listen` | — | X1 listener bind address (ADMF → NF) | AMF/SMF: yes |
| `mdf2` | — | xIRI (X2) delivery destination, `host:port` | AMF/SMF: yes |
| `mdf3` | — | xCC (X3) delivery destination the SMF provisions at each UPF it triggers | SMF: with `upfTriggers` |
| `upfTriggers` | — | Per-UPF triggering endpoints (`nodeId`, `x1Url`, `neId`) | SMF: for CC |
| — | `x1_listen` | Bind address of the triggering interface (SMF → UPF) | UPF: yes |
| — | `tf_id` | Identifier of the element permitted to task this UPF | UPF: yes |
| `neId` | `ne_id` | This network element's identifier | yes |
| `cert` / `key` / `caCert` | `cert` / `key` / `ca_cert` | LI PKI credential file paths | yes |
| `admfUrl` | `admf_url` | ADMF X1 endpoint for NE-initiated fault reports | optional |
| `admfId` | `admf_id` | Responsible ADMF identifier — on the AMF/SMF it also restricts who may task the NF (recommended) | optional |
| `keepaliveTimeout` | — | Purge-all-tasking window (Go duration, e.g. `30s`). The fail-safe is **off unless set**; leave it unset until you know the ADMF's keepalive cadence, since a window shorter than that purges live warrants | AMF/SMF: optional |
| — | `x3_sockaddr` | Datapath X3 tee socket (match `LI_X3_SOCKET_PATH`) | UPF: yes |

### Certificate requirements

A certificate signed by the LI CA is **not on its own** accepted for X1. ETSI
TS 103 221-1 clause 8.2.4 requires that the identifier a peer asserts in an X1
message also be bound into the certificate it presented, so that possession of
any LI CA certificate cannot be used to act as some other party. Issue each
certificate with **either** of these (either alone is sufficient):

- a **UID** attribute in the Subject (OID `0.9.2342.19200300.100.1.1`) whose
  value is the owner's X1 identifier; or
- a **`subjectAltName` URI** holding the annex G certificate binding URN:

  ```
  urn:etsi:li:103221-1:cert-binding:{role}:{identifier}
  ```

  where `{role}` is `ADMF` or `NE`, and `{identifier}` is that party's X1
  identifier — the ADMF identifier, or the NF's `neId`.

Prefer the binding URN where you have the choice: it pins the party's **role**
as well as its identifier, so a certificate issued to a network element cannot be
used to act as the ADMF. A bare UID carries no role.

With OpenSSL, either form can be added through the extension config:

```ini
# ADMF certificate, UID form           # ...or the binding-URN form:
subjectAltName = URI:urn:etsi:li:103221-1:cert-binding:ADMF:admf-1
# Subject DN with a UID: -subj "/UID=admf-1/CN=admf"
```

Set `admfId` on the AMF/SMF to the ADMF's identifier as well. The binding proves
the peer is who it says it is; `admfId` is what says *that* party may task this
network element. Without it, any correctly-bound certificate from the LI CA —
including one issued for an MDF or another network element — is accepted.

An X1 request that fails these checks is refused with the standard error code
(`1030` identifier/certificate mismatch, `1040` unexpected ADMF, `1060`
unexpected NE), no tasking is applied, and nothing is written to the operator
log. If X1 tasking is silently refused, this is the first thing to check.

> **Do not terminate X1 TLS at a proxy or ingress.** The network function has to
> see the ADMF's client certificate to perform these checks; an intermediary that
> terminates TLS makes them unenforceable and X1 will refuse every request.

The MDF's own server certificate is verified against the LI CA *and* its name is
checked against the configured MDF address. If you address an MDF by IP
rather than hostname, its certificate needs a matching **IP** SAN.

### Restricting who can reach X1

The AMF's and SMF's X1 listeners are exposed for an ADMF outside the cluster to
reach, which in a NodePort deployment means every host that can reach the node
can open a connection to them. Authentication holds — a peer without a bound LI
certificate gets nowhere — but nothing should be relying on that alone, and a
peer that can connect can consume the listener's capacity before authenticating.

**Do not do this with a NetworkPolicy.** A policy that selects a network
function's pod isolates it for every listed `policyType`, so an Ingress policy
admitting only X1 also denies SBI from the other network functions and NGAP from
the RAN, taking the core down. The `bess-upf` chart offered such a knob once and
it would have severed N4; it now refuses to render instead.

Restrict the node port at the node instead, where the rule concerns one port and
cannot silently cut anything else. Note that kube-proxy DNATs NodePort traffic in
`nat/PREROUTING`, so by the time a packet could reach `filter/INPUT` its
destination port is the pod's, not the node port — the rule has to run before
that, in `raw/PREROUTING`:

```sh
ADMF=192.0.2.1            # the LI system's address
NODE=192.0.2.10           # this node's address
X1_PORTS=30843,30844        # the amf-x1 and smf-x1 node ports

sudo iptables -t raw -N LI-X1 2>/dev/null || sudo iptables -t raw -F LI-X1
sudo iptables -t raw -A LI-X1 -s "$ADMF"/32 -j RETURN
sudo iptables -t raw -A LI-X1 -j DROP
sudo iptables -t raw -C PREROUTING -d "$NODE"/32 -p tcp -m multiport --dports "$X1_PORTS" -j LI-X1 2>/dev/null ||
  sudo iptables -t raw -I PREROUTING -d "$NODE"/32 -p tcp -m multiport --dports "$X1_PORTS" -j LI-X1
```

`DROP` rather than `REJECT` deliberately: a refusal confirms something is
listening, and these ports are best left looking closed to everyone who is not
the ADMF.

Two things this does not cover. Traffic originating **on the node itself** goes
through `OUTPUT`, not `PREROUTING`, so a process already running there is not
stopped by this — it is inside the trust boundary and must be treated as such.
And `iptables` rules do not survive a reboot on their own; persist them the way
the rest of that host's firewall is persisted.

---

## What to expect once enabled

- The ADMF connects to each AMF/SMF X1 listener and provisions warrants; each
  network function acknowledges over X1 and begins matching that target.
- For a tasked target, the AMF/SMF deliver xIRI to the MDF2, and — for a CC
  warrant — the SMF triggers duplication and the UPF delivers xCC to the MDF3.
- **Nothing** about a target appears in the network functions' general logs,
  metrics, or alarms. LI-plane faults (unreachable MDF, X1 bind failure, etc.)
  are reported to the ADMF over X1 when `admfUrl`/`admf_url` is configured, not
  to general logs.
- Removing the `li` block (or deactivating a warrant) stops all product for it;
  and, when `keepaliveTimeout` is set, all tasking is purged automatically if the
  ADMF stops sending keepalives.
- **One edge worth knowing when restarting the SMF under load.** A PDU session
  established while an SMF instance is *shutting down* takes its duplication rule
  from a process that is about to exit. The replacement SMF never knew that
  session, so it never withdraws the rule, and the UPF's CC-POI can be left
  duplicating traffic for a warrant no live SMF holds. Content in that state is
  dropped rather than delivered — the CC-POI refuses to ship what it cannot
  attribute — so nothing unauthorised reaches an MDF, but the duplication persists
  for the life of that session unless `trigger_keepalive` is set on the UPF, in
  which case the fail-safe clears it when the triggering function stops calling.
  Setting `trigger_keepalive` is the mitigation; draining sessions before replacing
  the SMF avoids it entirely.

## Testing

Because the ADMF and MDF are external, LI is exercised end to end against a
third-party stack — for example the **sipgate `li-simulator-x1x2x3`** (an
independent ETSI TS 103 221 implementation, useful as an interop reference).
Point the NFs' `mdf2`/`mdf3`/`admfUrl` at the simulator's endpoints (`mdf3` on the SMF,
which passes it to each UPF) and provision a
task over its X1 client.

## Standards

- ETSI TS 103 221-1 — X1 (task provisioning)
- ETSI TS 103 221-2 — X2/X3 (xIRI/xCC delivery framing)
- 3GPP TS 33.127 — LI architecture; 3GPP TS 33.128 — stage-3 procedures / xIRI records
- ETSI TS 104 000 — X0 (credential pre-provisioning)
