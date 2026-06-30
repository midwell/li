# asn1 (vendored)

This package is a vendored copy of [`github.com/PromonLogicalis/asn1`](https://github.com/PromonLogicalis/asn1)
(MIT, © 2016 PromonLogicalis — see `LICENSE`), a BER/DER ASN.1 codec with
`CHOICE` support. It is bundled inside the `li` module rather than imported as
an external dependency, following the same pattern SD-Core uses for the `aper`
PER codec, which lives inside `github.com/omec-project/ngap`.

It is used by `li/iri` to encode 3GPP TS 33.128 xIRI records (the standard
library `encoding/asn1` is DER-only and cannot represent `CHOICE`).

## Local modifications

1. `encode.go` carries the main patch (marked `LOCAL PATCH (omec/li)`): the
upstream encoder panics when a struct field is a nil `interface{}` (it unwraps
to an invalid `reflect.Value` and then calls `reflect.Value.Type` on it). The
patch treats an invalid value as *absent* — omitting it when the field is
`optional`/has a default, and returning a clear error for a missing mandatory
field. This makes absent optional `CHOICE` fields (pervasive in TS 33.128)
encode correctly, mirroring how `aper` treats a nil pointer as an absent
`OPTIONAL`. The same fix is suitable to upstream to PromonLogicalis.

2. `options.go` fixes a pre-existing upstream `go vet` error — two
   `syntaxError("…'%s'…")` calls were missing their argument; the option name
   (`args[0]`) is now passed, matching the sibling calls. Needed for the module
   to pass `go vet`/`go test`. Also upstreamable.

3. `decode.go` (`getRawValuesFromBytes`, marked `LOCAL PATCH (omec/li)`): the
   upstream loop calls `decodeRawValue` on an empty reader and returns EOF, so
   an empty SEQUENCE fails to decode. An empty SEQUENCE is valid when every
   member is OPTIONAL and absent (e.g. TS 33.128 `Location`), so the patch
   stops when the data is exhausted and decodes it into the zero value. Also
   upstreamable.
