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
- **Keepalive fail-safe:** if the controlling ADMF goes silent (no X1 message
  within the configured window) the network function purges all tasking — so
  warrants never outlive an operational controller.
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
| `keepaliveTimeout` | — | Purge-all-tasking window (Go duration, e.g. `30s`) | AMF/SMF: optional |
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
ADMF=10.0.60.122            # the LI system's address
NODE=10.0.179.176           # this node's address
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
  if the ADMF stops sending keepalives, all tasking is purged automatically.

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
