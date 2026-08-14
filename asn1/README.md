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

5. `types.go` (`encodeOctetString`, `decodeOctetString`): both guards read
   `if !(kind == Array || kind == Slice) && value.Type().Elem().Kind() == Uint8`,
   which contradicts the "Invalid type or element type" comment directly above
   them and is wrong in both directions. Because `&&` does not short circuit on a
   true first operand, a kind that is neither array nor slice reached
   `Type().Elem()`, which `reflect` panics on for a type with no element type — so
   handing the codec a plain `int` crashed it instead of returning `wrongType`.
   And an array or slice short circuited the check away entirely, so one whose
   elements are not bytes was accepted and then panicked later on a type
   assertion. Both now test the kind first and use `||`, and
   `octetstring_test.go` covers each shape on both the encode and decode paths.

6. Housekeeping, no behaviour change: `io/ioutil` replaced with `io` (deprecated
   since Go 1.19), a comparison to a bool constant simplified, the discarded
   error from the recursive `applyOptions` call in `encode.go` checked, naked
   returns made explicit, and the test files' unchecked `AddChoice` errors
   handled. This directory is no longer excluded from the linters: it is code
   this project owns, so it meets the same standard as the rest, and keeping an
   exception meant CI's separate staticcheck job disagreed with a local
   `golangci-lint` run — which is how patch 5 stayed hidden.

7. `encode.go`/`decode.go`/`options.go` (marked `LOCAL PATCH (omec/li) 7/8`):
   **`SEQUENCE OF CHOICE`**. Upstream's `encodeSlice`, `decodeSlice` and
   `decodeArray` each recurse into their elements with an empty options string, so a
   `choice` declared on the field never reaches the elements — and `applyOptions`
   then tries to resolve it against the *slice* type, which has no registered
   alternative (`invalid Go type '[]interface {}' for choice '…'`). The patch adds an
   internal `elemChoice` option and a `splitElementChoice` helper that moves a
   `choice` down to the elements when the field's **declared** type is a non-byte
   slice or array, and threads element options through the slice/array codecs on both
   paths. The declared type is what disambiguates the two readings: `Field []any` with
   a `choice` is a `SEQUENCE OF CHOICE`, while `Field any` holding a slice is a plain
   CHOICE that happens to have a slice-typed alternative. A byte slice or array is
   left alone — it is an `OCTET STRING`. An element whose tag matches no registered
   alternative fails the decode rather than being skipped, because a silently
   shortened list is indistinguishable from a genuinely short one. TS 33.128 needs
   this for `UEEndpointAddress` and for the `UserIdentifiers` subtree.

8. `types.go` (`encodeOctetString`, `decodeOctetString`, marked
   `LOCAL PATCH (omec/li) 8/8`): the guards fixed in patch 5 accept any array or
   slice whose element kind is `uint8`, which includes **named** types such as
   `type IPv4Address []byte` — how TS 33.128 CHOICE alternatives are modelled. The
   bodies did not: encode asserted the value to `[]byte`, decode assigned a plain
   `[]byte` back and the array path asserted the destination to `[]byte`. All three
   panicked on a shape the guard admitted (`interface conversion: interface {} is
   asn1.namedBytes, not []uint8`). They now read and write through `reflect`
   (`Value.Bytes`, `reflect.Copy`, `Convert`), so a named byte slice or array
   round-trips. Found while adding patch 7, since a CHOICE of address types is
   exactly this shape. `octetstring_test.go` covers both paths for named slices and
   named arrays.

   **Extended after an audit of this patch against its own guard.** The guard tests
   the element's *kind*, so it also admits a named **element** type
   (`type b uint8; type X []b`) — and the decode bodies still could not handle that:
   `reflect.Copy` and `Value.Convert` both require identical element types, and each
   panicked. The same defect the patch was written to fix, surviving inside the fix.
   Decode now assigns element by element for that shape, keeping the bulk copy for
   `[]byte` and `type X []byte`; refusing the shape instead was rejected because
   `encodeOctetString` accepts it, and a value this codec can write and cannot read
   back is worse than a slow path. Latent rather than live — every named byte type
   in `li/iri` is `[]byte` — and found by enumerating what the guard admits against
   what the body handles, not by anything failing.
