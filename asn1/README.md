<!--
SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
SPDX-License-Identifier: Apache-2.0
-->

# asn1 (vendored)

This package is a vendored copy of [`github.com/PromonLogicalis/asn1`](https://github.com/PromonLogicalis/asn1)
(MIT, © 2016 PromonLogicalis — see `LICENSE`), a BER/DER ASN.1 codec with
`CHOICE` support. It is bundled inside the `li` module rather than imported as
an external dependency, which is also what SD-Core does with the `aper` PER
codec now that it lives inside `github.com/omec-project/ngap` — though note that
`aper` was a standalone module of its own until September 2025, so the precedent
is for a protocol codec being folded into *its consumer*, not into a general
utility module.

It is used by `li/iri` to encode 3GPP TS 33.128 xIRI records (the standard
library `encoding/asn1` is DER-only and cannot represent `CHOICE`).

**The vendoring is permanent, not a staging step.** Upstream was archived by its
owner on 2019-03-13 and is read-only; its last commit was the day before, and it
has open issues and pull requests that can no longer be merged. The patches below
are each written to be *upstreamable in principle* — self-contained, and useful to
any consumer of the original — but there is nowhere to send them and has not been
since 2019. Treat this directory as code this project now owns and maintains,
including the security fix in patch 4.

## Local modifications

1. `encode.go` carries the main patch (marked `LOCAL PATCH (omec/li)`): the
upstream encoder panics when a struct field is a nil `interface{}` (it unwraps
to an invalid `reflect.Value` and then calls `reflect.Value.Type` on it). The
patch treats an invalid value as *absent* — omitting it when the field is
`optional`/has a default, and returning a clear error for a missing mandatory
field. This makes absent optional `CHOICE` fields (pervasive in TS 33.128)
encode correctly, mirroring how `aper` treats a nil pointer as an absent
`OPTIONAL`. Self-contained enough to have been upstreamed, had upstream not
been archived.

2. `options.go` fixes a pre-existing upstream `go vet` error — two
   `syntaxError("…'%s'…")` calls were missing their argument; the option name
   (`args[0]`) is now passed, matching the sibling calls. Needed for the module
   to pass `go vet`/`go test`.

3. `decode.go` (`getRawValuesFromBytes`, marked `LOCAL PATCH (omec/li)`): the
   upstream loop calls `decodeRawValue` on an empty reader and returns EOF, so
   an empty SEQUENCE fails to decode. An empty SEQUENCE is valid when every
   member is OPTIONAL and absent (e.g. TS 33.128 `Location`), so the patch
   stops when the data is exhausted and decodes it into the zero value. Also
   ours to keep.

4. `raw.go` (`decodeRawValue`, marked `LOCAL PATCH (omec/li) 4/4`): the upstream
   decoder does `make([]byte, length)` straight from the wire length field with
   no bound, so a crafted definite-length element triggers a multi-gigabyte
   allocation (OOM) or a `makeslice` panic — a remote DoS for any caller that
   decodes peer-supplied BER (e.g. an MDF/receiver). The patch rejects any
   element longer than `maxElementLength` (16 MiB, far above any real xIRI/X2/X3
   element) before allocating. **This one matters most for an archived
   dependency: nobody else is going to fix it.**
