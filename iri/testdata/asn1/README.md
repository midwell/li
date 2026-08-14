<!--
SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
SPDX-License-Identifier: Apache-2.0
-->

# Vendored TS 33.128 ASN.1 module

`TS33128Payloads.asn` is the machine-readable payload module published as an attachment to
3GPP TS 33.128. `asn1_drift_test.go` parses it to enumerate the fields each xIRI record
defines, so that a field the module declares and this project never populates fails a test
rather than going unnoticed.

## Provenance

| | |
|---|---|
| Specification | 3GPP TS 33.128 **V18.16.0** |
| Module header | `{… threeGPP(4) ts33128(19) r18(18) version15(15)}` |
| Attachment archive | `33128-ig0.zip` |
| SHA-256 | `e41ab9258f8ea3296a28dcfefd0c93254093475ca87f2caf291c814e4039a965` |

Fetch the archive from
`https://www.3gpp.org/ftp/Specs/archive/33_series/33.128/33128-ig0.zip` and take
`TS33128Payloads.asn` from it. Note that `www.3gpp.org` serves 403 to automated clients;
`curl` with a browser `User-Agent` works.

The digest above is what makes a re-fetch checkable. If it changes, the module changed, and
`asn1_drift_test.go` is the thing that will tell you what that meant.

## Licensing

The module is a 3GPP work and carries `LicenseRef-3GPP` in a `.license` sidecar rather than
a header — a header would alter the file and break the digest. The same arrangement covers
the 3GPP schema vendored under `x1/testdata/schemas/`; see `LICENSES/LicenseRef-3GPP.txt`
for the notice and the republication exception the vendoring rests on.

## What this module is not

It is not the authority on which fields are **mandatory**. The module marks nearly every
field `OPTIONAL`; the M/C/O markers live in the payload tables of TS 33.128 clause 6.2,
which are prose. A record can omit a field the tables mark M and still decode cleanly
against this module — which is exactly what `CONFORMANCE.md` records having happened. Use
this module to enumerate fields, and the payload tables to judge them.
