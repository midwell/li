// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package iri

import (
	"fmt"
	"reflect"
)

// The record definitions in this package carry their ASN.1 restrictions in comments —
// `OCTET STRING (SIZE(4))`, `INTEGER (0..255)`, `NumericString(6..15)` — and nothing checked
// them. `EncodeXIRI` ran a validation that covered two endpoint-list cases and no constraint
// at all, so a record whose values violate their own definitions encoded cleanly and went out.
//
// **The consequence is the unattributable-record failure arriving through the payload instead
// of the header.** This element believes it delivered; a conformant mediation function
// discards what it cannot validate; and because delivery succeeded, no fault is raised on
// either side. The evidence that nothing would catch it was in this package's own test suite:
// `records_test.go` encoded a seven-byte `UEPolicy` against a definition its own type comment
// records as `SIZE(16..65540)`.
//
// So the checks go on the *path* every record crosses rather than beside each builder. A check
// written beside one call site is not inherited by the next, and the next one is added by
// somebody who does not know the check exists — which is the same mistake, in the same file,
// that left the constraints unchecked in the first place.
//
// They are keyed by **type** rather than by field name, because a named type is inherited and
// a field name is not: a record added later that reuses `UEPolicy` or `PDUSessionID` gets the
// check without anybody remembering to add it, and a leaf that grows a new named type is
// visibly missing from the table below rather than silently unchecked.
//
// **Which is also the limit, stated rather than implied.** A leaf declared as a bare `[]byte`
// or `int` field — `SliceDifferentiator`, the `FTEID` addresses, `ServiceType` — carries its
// restriction only in a comment, and this table cannot reach it without keying on field
// names, which the next record to spell a field differently would silently escape. Giving
// those leaves named types is how they join the table; it is a mechanical change to iri.go and
// is not made here, because it would touch every builder in three network functions in a
// change whose subject is the checking rather than the naming.

// octetSize is an OCTET STRING's permitted length range, inclusive. A single permitted length
// is expressed as min == max.
type octetSize struct {
	min, max int
}

// intRange is an INTEGER's permitted value range, inclusive.
type intRange struct {
	min, max int64
}

// utf8Size is a UTF8String's permitted length range in characters, inclusive.
type utf8Size struct {
	min, max int
}

// octetConstraints, intConstraints and utf8Constraints are the restrictions the type
// definitions in iri.go record in their comments, in the one place that checks them.
//
// There is no NumericString table, and that is the limit above rather than an omission: the
// identity leaves those constraints belong to (IMSI, IMEI, MSISDN) are bare `string` fields,
// and their values come from the task — where `li/x1` validates them on the decode path
// before they reach a record.
//
// Every entry names the clause it comes from by naming the type: the comment beside each type
// declaration in iri.go is the source, and the two are meant to be read together.
var (
	octetConstraints = map[reflect.Type]octetSize{
		// The UEEndpointAddress CHOICE arms, which every record describing a session's
		// endpoint carries.
		reflect.TypeOf(IPv4Address(nil)): {4, 4},
		reflect.TypeOf(IPv6Address(nil)): {16, 16},
		reflect.TypeOf(MACAddress(nil)):  {6, 6},
		reflect.TypeOf(UEPolicy(nil)):    {16, 65540},
	}

	intConstraints = map[reflect.Type]intRange{
		reflect.TypeOf(PDUSessionID(0)): {0, 255},
		reflect.TypeOf(FiveGMMCause(0)): {0, 255},
		reflect.TypeOf(FiveGSMCause(0)): {0, 255},
		reflect.TypeOf(AMFUENGAPID(0)):  {0, 1099511627775},
		reflect.TypeOf(RANUENGAPID(0)):  {0, 4294967295},
	}

	utf8Constraints = map[reflect.Type]utf8Size{
		reflect.TypeOf(LCSCorrelationID("")): {1, 255},
	}

	// enumConstraints are the ENUMERATED types whose permitted values this module declares.
	//
	// Separate from intConstraints because the refusal has to say something different: an
	// integer outside its range is a value too large, and an enumeration outside its set is a
	// value that *means nothing* — no conformant receiver can interpret it, and there is no
	// nearest legal value it could have intended.
	//
	// The bounds are read from the constants each type declares in iri.go rather than from
	// the specification, so this table cannot drift from the enumeration it guards: a value
	// added there and not here shows up as a refusal of a value the module itself defines,
	// which is a failure that gets fixed, rather than as silent admission of one it does not.
	//
	// Reachable from peer input, which is why it matters. The AMF builds a handover record by
	// casting the NGAP cause value and handover type straight out of the message the gNB sent
	// (see handoverCause), so a RAN that is non-conformant — or is not the RAN it claims to
	// be — decides what this element encodes. Unchecked, the record goes out structurally
	// well-formed, a conformant mediation function discards what it cannot validate, and the
	// element believes it delivered.
	enumConstraints = map[reflect.Type]intRange{
		reflect.TypeOf(AMFRegistrationType(0)):    {1, 7},
		reflect.TypeOf(AMFRegistrationResult(0)):  {1, 3},
		reflect.TypeOf(AMFDirection(0)):           {1, 2},
		reflect.TypeOf(AccessType(0)):             {1, 3},
		reflect.TypeOf(PDUSessionType(0)):         {1, 5},
		reflect.TypeOf(FiveGSMRequestType(0)):     {1, 7},
		reflect.TypeOf(AMFFailedProcedureType(0)): {1, 3},
		reflect.TypeOf(SMFFailedProcedureType(0)): {1, 3},
		reflect.TypeOf(Initiator(0)):              {1, 3},
		reflect.TypeOf(HandoverType(0)):           {1, 4},

		// The five HandoverCause arms are bounded below and **not above**, and the asymmetry
		// is deliberate rather than an omission.
		//
		// Each mirrors an NGAP Cause group from TS 38.413 clause 9.3.1.2, "numbered from 1 in
		// the order the module lists them" — so zero and below are outside every one of them,
		// whichever group is in play, and that is checkable here. The upper bound is the
		// number of values in a specific group of a specific release of a specification this
		// module does not restate, and writing a number here from memory would be inventing a
		// constraint: a bound that is wrong in the tight direction refuses records the
		// specification permits, which on this interface means losing product that should
		// have been delivered.
		//
		// So the lower bound is enforced and the upper one is an evidence gap, recorded as
		// such in the change that added this table rather than closed by a guess. Closing it
		// means transcribing the five groups' value counts from TS 38.413 against the release
		// this project targets, and pinning them to that citation.
		reflect.TypeOf(CauseRadioNetwork(0)): {1, maxInt64},
		reflect.TypeOf(CauseTransport(0)):    {1, maxInt64},
		reflect.TypeOf(CauseNas(0)):          {1, maxInt64},
		reflect.TypeOf(CauseProtocol(0)):     {1, maxInt64},
		reflect.TypeOf(CauseMisc(0)):         {1, maxInt64},
	}
)

// maxInt64 stands for "this module states no upper bound", so an entry that bounds only one
// end says so in the table rather than by being absent from it.
const maxInt64 = int64(^uint64(0) >> 1)

// validateConstraints walks a record and refuses any value that violates the restriction its
// own type carries.
//
// A reflective walk rather than a check per record, for the reason the file comment gives:
// what must not be possible is adding a record that skips the check. It runs once per record
// on the X2 path, which is per signalling event and not per packet.
func validateConstraints(event any) error {
	return walkConstrained(reflect.ValueOf(event), reflect.TypeOf(event).String())
}

// walkConstrained descends v, applying whatever constraint its type carries and then
// recursing into its members. path names where a failure was found, so a refusal says which
// field of which record rather than only that something was wrong.
func walkConstrained(v reflect.Value, path string) error {
	if !v.IsValid() {
		return nil
	}

	if err := constraintOf(v, path); err != nil {
		return err
	}

	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return nil
		}

		return walkConstrained(v.Elem(), path)

	case reflect.Struct:
		t := v.Type()
		for i := range v.NumField() {
			if !t.Field(i).IsExported() {
				continue
			}
			if err := walkConstrained(v.Field(i), path+"."+t.Field(i).Name); err != nil {
				return err
			}
		}

	case reflect.Slice, reflect.Array:
		// A byte slice is a leaf: its constraint is its length, already applied above, and
		// descending into it would check each octet as an integer.
		if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8 {
			return nil
		}
		for i := range v.Len() {
			if err := walkConstrained(v.Index(i), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}

	return nil
}

// constraintOf applies the restriction v's own type carries, if it has one.
func constraintOf(v reflect.Value, path string) error {
	t := v.Type()

	if c, ok := octetConstraints[t]; ok {
		n := v.Len()
		// An absent OPTIONAL octet string is a nil slice, which the codec omits — so a
		// length of zero is "not present" rather than "present and too short". A field that
		// is mandatory and absent is the codec's to refuse, not this.
		if n == 0 {
			return nil
		}
		if n < c.min || n > c.max {
			return fmt.Errorf("iri: %s is %d octets, and %s is defined as SIZE(%d..%d)",
				path, n, t.Name(), c.min, c.max)
		}
	}

	if c, ok := intConstraints[t]; ok {
		n := v.Int()
		if n < c.min || n > c.max {
			return fmt.Errorf("iri: %s is %d, and %s is defined as INTEGER (%d..%d)",
				path, n, t.Name(), c.min, c.max)
		}
	}

	if c, ok := enumConstraints[t]; ok {
		n := v.Int()
		// Zero is "not present", not "present and meaningless" — the same rule the octet
		// strings above take, for the same reason. Every enumeration here is numbered from
		// one, so an unset field of an optional member reads as zero and the codec omits it;
		// refusing that would refuse every record that legitimately leaves the member out. A
		// member that is mandatory and absent is the codec's to refuse, and it does.
		//
		// It costs the guard exactly one value, and not one that carries the risk: what this
		// check is for is a value a peer chose — an NGAP cause or handover type cast straight
		// out of a gNB's message — and those are numbered from one when present.
		if n == 0 {
			return nil
		}
		if n < c.min || n > c.max {
			if c.max == maxInt64 {
				return fmt.Errorf("iri: %s is %d, and %s is an ENUMERATED numbered from %d",
					path, n, t.Name(), c.min)
			}

			return fmt.Errorf("iri: %s is %d, and %s is an ENUMERATED with values %d..%d",
				path, n, t.Name(), c.min, c.max)
		}
	}

	if c, ok := utf8Constraints[t]; ok {
		s := v.String()
		if s == "" {
			return nil
		}
		if n := len([]rune(s)); n < c.min || n > c.max {
			return fmt.Errorf("iri: %s is %d characters, and %s is defined as UTF8String (SIZE(%d..%d))",
				path, n, t.Name(), c.min, c.max)
		}
	}

	return nil
}
