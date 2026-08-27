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
// **Every leaf with a restriction now has a name, and the sweep that established that found
// more than the three the previous version of this paragraph named.** It listed
// `SliceDifferentiator`, the `FTEID` addresses and `ServiceType`; naming those and then reading
// every field of every emitted record turned up `SliceServiceType`, `TEID` and all six members
// of `FiveGGUTI` in the same condition — restriction in a comment, nothing keyed on it. The
// `FiveGGUTI` ones are in every record that carries a GUTI. A list of examples is not a survey,
// and the reason this one read as complete is that it had been written from the leaves somebody
// had noticed.
//
// So what remains outside is stated as a property rather than as a list: a restriction on a
// leaf whose Go declaration is a bare `[]byte`, `int` or `string` field is not enforced, and
// there are no such leaves left among the records this project emits. A field added as a bare
// type is the way back in, which is what `TestEveryRestrictedLeafIsNamed` exists to refuse.

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

		// The SNSSAI and service-accept leaves the module declares inline, so this package
		// names them. Both are single permitted lengths, and a single length is the case a
		// check catches most often: a builder handed three octets of slice differentiator
		// where it meant to send the SST has nothing else to trip over.
		reflect.TypeOf(SliceDifferentiator(nil)): {3, 3},
		reflect.TypeOf(ServiceType(nil)):         {1, 1},

		// The tracking-area code of a TAI. homeNetworkPublicKeyID and schemeOutput are
		// OCTET STRINGs the module leaves unconstrained, so they are deliberately absent.
		reflect.TypeOf(TAC(nil)): {2, 3},
	}

	intConstraints = map[reflect.Type]intRange{
		reflect.TypeOf(PDUSessionID(0)): {0, 255},
		reflect.TypeOf(FiveGMMCause(0)): {0, 255},
		reflect.TypeOf(FiveGSMCause(0)): {0, 255},
		reflect.TypeOf(AMFUENGAPID(0)):  {0, 1099511627775},
		reflect.TypeOf(RANUENGAPID(0)):  {0, 4294967295},

		reflect.TypeOf(SliceServiceType(0)): {0, 255},
		reflect.TypeOf(TEID(0)):             {0, 4294967295},

		// The FiveGGUTI members. Each is a named type in the module with a range of its own,
		// and each comes from this element's configuration and context — so no task validation
		// stands between a misconfigured PLMN or a truncated AMF identifier and a record.
		reflect.TypeOf(AMFRegionID(0)): {0, 255},
		reflect.TypeOf(AMFSetID(0)):    {0, 1023},
		reflect.TypeOf(AMFPointer(0)):  {0, 63},
		reflect.TypeOf(FiveGTMSI(0)):   {0, 4294967295},

		// The SUCI members with a range. These arrive from a NAS message the UE sent, so
		// unlike the identity leaves nothing in li/x1 has looked at them before they reach
		// a record — a malformed SUCI is a wrong target identity, which is the failure this
		// table exists to make loud.
		reflect.TypeOf(RoutingIndicator(0)):       {0, 9999},
		reflect.TypeOf(ProtectionSchemeID(0)):     {0, 15},
		reflect.TypeOf(SUPIType(0)):               {0, 7},
		reflect.TypeOf(RoutingIndicatorLength(0)): {1, 4},
	}

	utf8Constraints = map[reflect.Type]utf8Size{
		reflect.TypeOf(LCSCorrelationID("")): {1, 255},

		// The network identifier of a stand-alone non-public network, carried by TAI and
		// SMFServingNetwork. homeNetworkIdentifier is a UTF8String the module leaves
		// unconstrained and is deliberately absent.
		reflect.TypeOf(NID("")): {11, 11},
	}

	// numericConstraints are the NumericString leaves, whose restriction is a length *and* an
	// alphabet: `NumericString` admits digits and space, and TS 33.128 uses it for values that
	// are digits throughout.
	//
	// The alphabet is the half worth having. A length check on an MCC would pass "abc", and a
	// PLMN read from configuration is exactly where a non-digit arrives — whereas the identity
	// leaves this table does not cover (IMSI, IMEI, MSISDN) get their values from a task, which
	// `li/x1` validates on the decode path before they reach a record. That distinction is why
	// these two are here and those are not.
	numericConstraints = map[reflect.Type]utf8Size{
		reflect.TypeOf(MCC("")): {3, 3},
		reflect.TypeOf(MNC("")): {2, 3},
	}

	// mandatoryEnums are the enumerated types for which zero is *wrong* rather than absent.
	//
	// The check below exempts zero everywhere else, and correctly: an unset optional member
	// reads as zero in Go and the codec omits it, so refusing zero would refuse every record
	// that legitimately leaves one out.
	//
	// **That exemption is what let two defects reach a mediation function.** Both were an
	// element casting a neighbouring protocol's value straight into a record: `handoverCause`
	// emitted as NGAP's `unspecified(0)`, and `handoverType` emitted as NGAP's `intra5gs(0)`.
	// A mandatory member emitted as zero is indistinguishable, to this check, from an optional
	// one omitted — so the one value that proved the mapping was missing was the one value the
	// check was told to ignore.
	//
	// The second was found by *decoding a delivered record* against the published module, which
	// refused it outright: `handoverType` is mandatory, so a zero is not a wrong value but an
	// unreadable record, and every intra-5GS handover record was discarded on receipt.
	//
	// A type belongs here when it is mandatory in every record this package emits that
	// carries it, so zero can only mean the element wrote a value its own definition does not
	// have. Being wrong in this direction costs a record the receiver would have refused
	// anyway; being wrong in the other costs every record that omits an optional member, which
	// is why the default stays the exemption and entries are added deliberately.
	//
	// **And the rule above had never been run.** Two entries, added once per defect, were the
	// whole of it. Sweeping the module for every ENUMERATED numbered from one that sits in a
	// field a record cannot omit found nine more — six here and three that this map cannot
	// express, in mandatoryEnumFields below. The sweep is now
	// TestEveryMandatoryEnumeratedFieldRefusesZero, so the list cannot fall behind the record
	// definitions the way it already had.
	mandatoryEnums = map[reflect.Type]bool{
		reflect.TypeOf(HandoverType(0)): true,

		// The HandoverCause arms. A cause is mandatory in both records that carry one, and the
		// mapping that produces it cannot yield zero — so a zero here is the mapping having
		// been bypassed, which is precisely the defect this guard exists to notice.
		reflect.TypeOf(CauseRadioNetwork(0)): true,
		reflect.TypeOf(CauseTransport(0)):    true,
		reflect.TypeOf(CauseNas(0)):          true,
		reflect.TypeOf(CauseProtocol(0)):     true,
		reflect.TypeOf(CauseMisc(0)):         true,

		// The six the sweep found that are mandatory in every record this package emits that
		// carries them, so the type is exactly the right key: a record added later that reuses
		// one inherits the guard without anybody remembering it. Each names the record and the
		// module's lowest defined value.
		//
		// AMFDirection ::= ENUMERATED { networkInitiated(1), uEInitiated(2) } —
		// AMFDeregistration/deregistrationDirection.
		reflect.TypeOf(AMFDirection(0)): true,
		// AMFRegistrationResult, lowest threeGPPAccess(1) — AMFRegistration and
		// AMFStartOfInterceptionWithRegisteredUE, mandatory in both. The module also gives it
		// to AMFUEConfigurationUpdate as OPTIONAL, which this package does not emit; modelling
		// that record moves this entry to mandatoryEnumFields, and the sweep says so.
		reflect.TypeOf(AMFRegistrationResult(0)): true,
		// AMFFailedProcedureType, lowest registration(1) —
		// AMFUnsuccessfulProcedure/failedProcedureType.
		reflect.TypeOf(AMFFailedProcedureType(0)): true,
		// SMFFailedProcedureType, lowest pDUSessionEstablishment(1) —
		// SMFUnsuccessfulProcedure/failedProcedureType.
		reflect.TypeOf(SMFFailedProcedureType(0)): true,
		// PDUSessionType, lowest iPv4(1) — SMFPDUSessionEstablishment and
		// SMFStartOfInterceptionWithEstablishedPDUSession. This is the one of the six built by
		// a raw cast from another protocol's enumeration, which is the construct that produced
		// both handover defects; the correspondence is asserted in smf/lawfulintercept.
		reflect.TypeOf(PDUSessionType(0)): true,
		// Initiator, lowest uE(1) — SMFUnsuccessfulProcedure/initiator.
		reflect.TypeOf(Initiator(0)): true,
	}

	// mandatoryEnumFields are the enumerated fields for which zero is wrong that mandatoryEnums
	// cannot express, keyed by the record and the field rather than by the type.
	//
	// **The type-keyed map is not a weaker version of this one — it is the stronger one where it
	// applies**, for the reason the file comment gives: a named type is inherited and a field
	// name is not, so a record added later that reuses `PDUSessionType` gets the guard without
	// anybody remembering it. What it cannot express is a type the module makes mandatory in one
	// record and OPTIONAL in another.
	//
	// That distinction matters because validateConstraints runs *before* ctx.Encode. It walks
	// the whole record and sees an unset optional member as zero, before the codec would have
	// omitted it — so a type in mandatoryEnums refuses zero in every record carrying that type,
	// including one where zero is how absence is spelled. `AccessType` is optional in four SMF
	// records and mandatory in one; guarding it by type would refuse those four their absence,
	// which trades one silent defect for another.
	//
	// The existing map had been adequate without anyone noticing its limit because the two
	// defects that created it — `handoverType` and the `Cause` arms — happen to be the two cases
	// it can express.
	//
	// Derived from the module and asserted against it by
	// TestEveryMandatoryEnumeratedFieldRefusesZero, in both directions: an entry naming a field
	// the module marks OPTIONAL fails, and so does a mandatory field named by neither map.
	mandatoryEnumFields = map[string]bool{
		// AccessType, lowest threeGPPAccess(1). Mandatory in AMFDeregistration (table
		// 6.2.2.2.3-1, cardinality 1) and OPTIONAL in the four SMF records that carry it.
		//
		// This is the one of the three where zero is a *reachable* value rather than a
		// hypothetical: amf/lawfulintercept's DeregistrationScope returns 0 for a NAS access
		// type it does not recognise, and each of its two callers is expected to notice and
		// substitute the arrival access. A caller written without that check emits a
		// mandatory zero, and the guard is what makes that a refusal here rather than a
		// discard at the far end.
		"AMFDeregistration.AccessType": true,

		// FiveGSMRequestType, lowest initialRequest(1). Mandatory in the three session
		// records and OPTIONAL in SMFUnsuccessfulProcedure, where the SMF reports it when it
		// knows the request type and omits it otherwise.
		//
		// SMFPDUSessionModification is a module-versus-payload-table discrepancy, recorded in
		// CONFORMANCE.md: `TS33128Payloads.asn` gives requestType no OPTIONAL, and table
		// 6.2.3-2 marks only gTPTunnelInfo M. The module is what a receiver validates
		// against, so the module is what this follows.
		"SMFPDUSessionEstablishment.RequestType":                      true,
		"SMFPDUSessionModification.RequestType":                       true,
		"SMFStartOfInterceptionWithEstablishedPDUSession.RequestType": true,

		// AMFRegistrationType, lowest initial(1). Mandatory in AMFRegistration and OPTIONAL in
		// AMFStartOfInterceptionWithRegisteredUE — where the AMF may be activating interception
		// for a UE whose registration it never saw, so it has no registration type to report.
		"AMFRegistration.RegistrationType": true,
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

		// The five HandoverCause arms, bounded from the module rather than from memory.
		//
		// Each mirrors an NGAP Cause group, and the two number the same concepts differently —
		// so the values here are TS 33.128's, transcribed from
		// `testdata/asn1/TS33128Payloads.asn` and asserted against it by
		// TestCauseBoundsMatchTheModule. An element that reads a cause from NGAP is
		// responsible for mapping it into this vocabulary before building the record; see
		// causevalues.go, which names the values it maps to.
		//
		// `CauseRadioNetwork` admits one value the module does not define. Its enumeration
		// runs 1..52 with 28 absent, and a range check cannot express the hole; a set per
		// group would, and earns its complexity for exactly one group. The looser bound costs
		// nothing in practice, because no mapping entry yields 28 — asserted where the mapping
		// lives, so the claim is checked rather than assumed.
		reflect.TypeOf(CauseRadioNetwork(0)): {1, 52},
		reflect.TypeOf(CauseTransport(0)):    {1, 2},
		reflect.TypeOf(CauseNas(0)):          {1, 4},
		reflect.TypeOf(CauseProtocol(0)):     {1, 7},
		reflect.TypeOf(CauseMisc(0)):         {1, 6},
	}
)

// validateConstraints walks a record and refuses any value that violates the restriction its
// own type carries.
//
// A reflective walk rather than a check per record, for the reason the file comment gives:
// what must not be possible is adding a record that skips the check. It runs once per record
// on the X2 path, which is per signalling event and not per packet.
func validateConstraints(event any) error {
	return walkConstrained(reflect.ValueOf(event), reflect.TypeOf(event).String(), false)
}

// walkConstrained descends v, applying whatever constraint its type carries and then
// recursing into its members. path names where a failure was found, so a refusal says which
// field of which record rather than only that something was wrong.
//
// zeroForbidden is what the parent struct decided about *this* field: mandatoryEnumFields
// keyed by the enclosing type's name and the field's, for the enumerations whose meaning
// depends on which record carries them. It is a parameter rather than a lookup inside
// constraintOf because a value does not know which field it came from — which is the same
// reason the type-keyed tables cannot express these three.
func walkConstrained(v reflect.Value, path string, zeroForbidden bool) error {
	if !v.IsValid() {
		return nil
	}

	if err := constraintOf(v, path, zeroForbidden); err != nil {
		return err
	}

	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return nil
		}

		// The flag carries through: a pointer expresses presence, so what the field said
		// about its value still applies to the value behind it.
		return walkConstrained(v.Elem(), path, zeroForbidden)

	case reflect.Struct:
		t := v.Type()
		for i := range v.NumField() {
			if !t.Field(i).IsExported() {
				continue
			}
			name := t.Field(i).Name
			if err := walkConstrained(v.Field(i), path+"."+name,
				mandatoryEnumFields[t.Name()+"."+name]); err != nil {
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
			if err := walkConstrained(v.Index(i), fmt.Sprintf("%s[%d]", path, i),
				zeroForbidden); err != nil {
				return err
			}
		}
	}

	return nil
}

// constraintOf applies the restriction v's own type carries, if it has one. zeroForbidden is
// the enclosing field's verdict on zero; see walkConstrained.
func constraintOf(v reflect.Value, path string, zeroForbidden bool) error {
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
		// **Except where the member is mandatory wherever it appears**, in which case zero
		// cannot be an omission and the exemption was hiding the one value that mattered. The
		// paragraph beside mandatoryEnums says what that cost: two defects, one of which made
		// every intra-5GS handover record undecodable, and neither of which this check could
		// see. The comment that used to stand here claimed the exemption cost "exactly one
		// value, and not one that carries the risk" — the risk was exactly that value, because
		// a peer's enumeration numbered from zero puts its *first* member there.
		//
		// Two maps rather than one because the exception has two shapes: a type mandatory
		// wherever it appears, and a field mandatory in this record and optional in the next.
		// See mandatoryEnumFields for why the second cannot be folded into the first.
		if n == 0 && !mandatoryEnums[t] && !zeroForbidden {
			return nil
		}
		if n < c.min || n > c.max {
			return fmt.Errorf("iri: %s is %d, and %s is an ENUMERATED with values %d..%d",
				path, n, t.Name(), c.min, c.max)
		}
	}

	if c, ok := numericConstraints[t]; ok {
		s := v.String()
		// Empty is absence, as everywhere else in this function: a mandatory member that is
		// absent is the codec's to refuse.
		if s != "" {
			if n := len([]rune(s)); n < c.min || n > c.max {
				return fmt.Errorf("iri: %s is %d characters, and %s is defined as NumericString (SIZE(%d..%d))",
					path, n, t.Name(), c.min, c.max)
			}
			for _, r := range s {
				if (r < '0' || r > '9') && r != ' ' {
					return fmt.Errorf("iri: %s contains %q, and %s is defined as NumericString, "+
						"whose alphabet is the digits and space", path, r, t.Name())
				}
			}
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
