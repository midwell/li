<!--
SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
SPDX-License-Identifier: Apache-2.0
-->

# li — Lawful Interception for SD-Core

This module provides the in-network **Points of Interception (POIs)** and the
X1/X2/X3 interfaces that let SD-Core meet a Communication Service Provider's
Lawful Interception (LI) obligations. It is imported by the AMF, SMF, and UPF.

The Administration (ADMF/LIPF) and Mediation & Delivery (MDF2/MDF3) functions
are **external, third-party systems** (e.g. OpenLI, or the sipgate
X1/X2/X3 simulator for testing) — SD-Core implements only the POIs and the
interfaces toward them.

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
| **SMF** | IRI-POI + CC Triggering Function | PDU-session xIRI (establishment/modification/release/start-of-interception); and instructs the UPF to duplicate a tasked target's user plane | X2 → MDF2; PFCP `DUPL` FAR → UPF |
| **UPF** | CC-POI | Content of Communication — the duplicated user-plane packets — as ETSI TS 103 221-2 **xCC** | X3 → MDF3 |

```
                 ┌─────────────┐
   task warrants │ ADMF / LIPF │  (external)
   over X1 ─────▶│             │
   (mTLS)        └─────────────┘
                   │ X1        │ X1
                   ▼           ▼
              ┌────────┐   ┌────────┐        ┌──────┐
              │  AMF   │   │  SMF   │──PFCP──▶│ UPF  │
              │ IRI-POI│   │IRI-POI │  DUPL   │CC-POI│
              └────┬───┘   └───┬────┘  FAR    └──┬───┘
             xIRI  │   xIRI    │              xCC │
             X2    ▼   X2      ▼              X3  ▼
              ┌──────────────────┐         ┌──────────┐
              │       MDF2       │         │   MDF3   │   (external)
              └──────────────────┘         └──────────┘
```

- The **ADMF** provisions interception tasks (warrants) over **X1** (ETSI TS 103 221-1,
  XML over mutual TLS). The AMF and SMF each expose an X1 listener; the UPF has
  no X1 listener — it is driven by the SMF over PFCP.
- Each tasked network function matches events/traffic against the target
  (by SUPI, PEI, or GPSI) using a local task store — no external lookup at
  interception time.
- **xIRI** is delivered over **X2** to the configured **MDF2**; **xCC** over
  **X3** to the configured **MDF3** (both ETSI TS 103 221-2, mutual TLS).
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
   from the SBI certificates.
2. An external **ADMF** (to task the NFs over X1) and **MDF2**/**MDF3** (to
   receive xIRI/xCC). Note their addresses.
3. The **LI-enabled NF images** deployed.

The MDF2/MDF3 delivery endpoints are taken from the NF's own configuration (one
MDF2 per AMF/SMF, one MDF3 per UPF); per-task destination provisioning over X1 is
not used in this release.

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
    "mdf3": "mdf3.li.example:9001",      // X3 delivery destination (MDF3 host:port)
    "x3_sockaddr": "/tmp/li_x3",         // must match the datapath's LI_X3_SOCKET_PATH (see below)
    "cert": "/etc/li/certs/tls.crt",     // X0-pre-provisioned LI certificate
    "key": "/etc/li/certs/tls.key",      //   its private key
    "ca_cert": "/etc/li/certs/ca.crt",   //   the LI CA trust anchor
    "ne_id": "upf-1",                    // this NE's identifier (for X1 issue reports)
    "admf_url": "https://admf.li.example/X1/NE",  // optional: NE→ADMF fault reporting
    "admf_id": "admf-1"                  // optional
  }
}
```

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

### Configuration reference

| AMF/SMF (`configuration.li`) | UPF (`li`) | Meaning | Required |
|---|---|---|---|
| `x1Listen` | — | X1 listener bind address (ADMF → NF) | AMF/SMF: yes |
| `mdf2` | `mdf3` | xIRI (X2) / xCC (X3) delivery destination, `host:port` | yes |
| `neId` | `ne_id` | This network element's identifier | yes |
| `cert` / `key` / `caCert` | `cert` / `key` / `ca_cert` | LI PKI credential file paths | yes |
| `admfUrl` | `admf_url` | ADMF X1 endpoint for NE-initiated fault reports | optional |
| `admfId` | `admf_id` | Responsible ADMF identifier | optional |
| `keepaliveTimeout` | — | Purge-all-tasking window (Go duration, e.g. `30s`) | AMF/SMF: optional |
| — | `x3_sockaddr` | Datapath X3 tee socket (match `LI_X3_SOCKET_PATH`) | UPF: yes |

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
independent ETSI TS 103 221 implementation, useful as an interop reference) or
**OpenLI** (which ingests X2/X3 and mediates through to an emulated LEA). Point
the NFs' `mdf2`/`mdf3`/`admfUrl` at the simulator's endpoints and provision a
task over its X1 client.

## Standards

- ETSI TS 103 221-1 — X1 (task provisioning)
- ETSI TS 103 221-2 — X2/X3 (xIRI/xCC delivery framing)
- 3GPP TS 33.127 — LI architecture; 3GPP TS 33.128 — stage-3 procedures / xIRI records
- ETSI TS 104 000 — X0 (credential pre-provisioning)
