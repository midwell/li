<!--
SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
SPDX-License-Identifier: Apache-2.0
-->

# ASN.1 decoding: none is shipped, and what one must carry

This module **encodes** TS 33.128 xIRI records and does not decode them. None of its packages
contains a DER or BER decoder; the only parsing of an encoding is in tests, over this module's
own output, through the standard library. This note records why, and records the bounds the
decoder that
used to be here carried, so that a parse path added later — here, or in a mediation-side tool
built against this module — starts from them instead of rediscovering them from the same
failures.

## Why there is no decoder

Until `li v0.9.9` the xIRI encoder was a vendored reflective BER codec in `asn1/`, which also
decoded. That package was replaced by explicit emitters over the standard library's
`encoding/asn1` (`iri/emit.go`), and its decoder was dropped rather than ported, because
nothing needed it:

- **No production caller.** The only decode calls outside that package's own tests were
  round-trip tests in `iri`. `x1` parses XML, and imports `encoding/asn1` only for an OID
  constant. `x2x3` parses the ETSI TS 103 221-2 framing header by hand. Neither parses an
  ASN.1 encoding.
- **The round trips were the weaker test.** A round trip still passes when encode and decode
  change together, which is exactly the failure that corrupts a receiver while looking healthy
  from inside the element. The encoder is pinned instead by byte fixtures
  (`iri/testdata/golden.txt`, every record in more than one form) and by a check that derives
  each emitted tag from the declarations (`iri/emit_tags_test.go`).
- **A parser nobody calls is still an attack surface somebody maintains.** Its hardening had
  to be kept correct with no caller to show when it was not.

An element here is the point of interception. The mediation function that receives xIRI is a
third-party system, so decoding it is not this module's job.

## What would have to be true to add one back

A decoder belongs here when something here parses xIRI a peer sent: an X2 receiver, a
mediation-side tool built against this module, or a test that cannot be expressed against
fixtures. Its input is then peer-supplied, and it SHALL carry every bound below, each with a
test that shows it is load-bearing. The test has to assert that the refusal *names the bound*.
An unbounded decoder also fails on most of these inputs, by running off the end of the
message, so a test that asserts only that an error was returned passes against the defect.

## The bounds, and the defect each prevents

They were established in the vendored decoder's `raw.go` and `types.go`, where they can be read
at `li v0.9.9`. They apply to any BER parse of the TS33128Payloads structures, and to the
X2/X3 element framing around them.

| Bound | Value | The defect without it |
|---|---|---|
| Declared-length ceiling (`maxElementLength`) | 16 MiB (`16 << 20`), checked **before** allocating | The decoder allocated `make([]byte, length)` straight from the wire's length field. A crafted length forced a multi-gigabyte allocation or a `makeslice` panic: a remote denial of service from one small message. |
| Cumulative budget through indefinite length (`indefiniteBudget`) | 16 MiB, the same ceiling, **across the whole construct** | The indefinite-length form has no declared length, and the decoder buffered until an end-of-contents marker arrived, so an unterminated construct grew the buffer without limit. The ceiling above was bypassed simply by choosing the other length form. Bounding each nested element separately does not close it, because a sender reaches any total by nesting. |
| Nesting depth through indefinite length (`maxIndefiniteDepth`) | 64 | End-of-contents detection recursed once per nested indefinite construct, with the depth the sender's to choose. A message of two bytes per level exhausted the decoding goroutine's stack, which on a delivery or signalling goroutine takes the network function with it. Real records nest a handful deep. |
| A child's declared length inside an indefinite construct | the same 16 MiB ceiling, before the child is read | As the first row, reached from inside the second. |
| Primitives with no contents octets | refused | X.690 requires a BOOLEAN to have one contents octet and an INTEGER at least one. The decoder indexed a BOOLEAN's first octet without checking it existed, and sign-extended an empty INTEGER into a confident zero: a panic in one case, and a wrong value with no error in the other, which is worse. |

The first three were one hardening effort, recorded as the vendored package's local patch 4
and extended on 2026-08-19 when the indefinite-length path was found to bypass it. The
requirement they satisfy is in the `li-iri-reporting` specification: *a codec rejects
malformed input rather than failing on it*, for every length form as well as every length.
