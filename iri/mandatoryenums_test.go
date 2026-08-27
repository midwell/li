// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package iri

import (
	"encoding/hex"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The zero exemption in constraintOf is right for optional members and wrong for mandatory
// ones, and the map that expressed the exception held two entries — `HandoverType` and the five
// `Cause` arms — each added the day a defect proved it missing. The rule beside the map said
// what belonged there; nothing had run it.
//
// This is the sweep, and it is a test rather than a one-time audit for the reason both prior
// entries exist: a record type added later, or a field that becomes mandatory later, would join
// the exemption silently. The source of truth is the published module. A check that derived the
// answer from `iri.go` would agree with the guard by construction, because the guard is keyed on
// the same Go types.
//
// **Scoped to the records this package emits**, via goldenSamples — the same scope
// CONFORMANCE.md uses, and complete over it because TestGoldenCoversEveryRecord pins the sample
// set to the registered xIRIEvent alternatives. The module defines 171 ENUMERATEDs numbered
// from one, nearly all of them for services this element is not a POI for; sweeping those would
// produce a list of exclusions nobody could act on, which is the failure mode the leaf scan's
// `unrestrictedBareFields` was written to avoid.

// unguardedMandatoryEnums are the record fields this sweep flags and this package deliberately
// does not guard, each with the reason — the shape `unrestrictedBareFields` uses, and for the
// same reason: "there is nothing to guard here" and "nobody guarded it" are indistinguishable
// from the code.
//
// Keyed `Record.field` with the module's own spelling of both.
//
// Empty, and the emptiness is a result rather than a placeholder: every module-mandatory
// enumerated field of every emitted record is now guarded, by type where the type is exactly
// the right key and by record-and-field where it is not. The map stays so the next exclusion
// has an established place to be written down, and so writing one is a deliberate act — the
// same reason asn1_drift_test.go keeps `knownConditionalDefects` after emptying it.
var unguardedMandatoryEnums = map[string]string{}

// asn1Enum is one ENUMERATED the module declares, with the lowest value it defines.
type asn1Enum struct {
	name   string
	lowest int64
}

var (
	reEnumStart  = regexp.MustCompile(`^(\w+)\s*::=\s*ENUMERATED\s*$`)
	reEnumValue  = regexp.MustCompile(`([A-Za-z][\w-]*)\s*\((\d+)\)`)
	reSeqOpen    = regexp.MustCompile(`^(\w+)\s*::=\s*SEQUENCE\s*$`)
	reTypedField = regexp.MustCompile(`^(\w+)\s*\[(\d+)\]\s*(\w+)(.*)$`)
)

// enumsNumberedFromOne returns every ENUMERATED the module declares whose lowest value is at
// least one — the types for which zero is not a member, so a zero in a field of that type is
// either an absent optional member or a value the enumeration does not have.
func enumsNumberedFromOne(t *testing.T) map[string]asn1Enum {
	t.Helper()

	out := map[string]asn1Enum{}
	var current string
	var lowest int64
	var seen bool

	flush := func() {
		if current != "" && seen && lowest >= 1 {
			out[current] = asn1Enum{name: current, lowest: lowest}
		}
		current, lowest, seen = "", 0, false
	}

	for _, line := range asn1Lines(t) {
		if m := reEnumStart.FindStringSubmatch(line); m != nil {
			flush()
			current = m[1]

			continue
		}
		if current == "" {
			continue
		}
		if line == "}" {
			flush()

			continue
		}
		for _, m := range reEnumValue.FindAllStringSubmatch(line, -1) {
			v, err := strconv.ParseInt(m[2], 10, 64)
			if err != nil {
				t.Fatalf("%s: %q is not a number", current, m[2])
			}
			if !seen || v < lowest {
				lowest = v
			}
			seen = true
		}
	}
	flush()

	if len(out) == 0 {
		t.Fatalf("parsed no ENUMERATED definitions from %s — the parser and the module disagree, "+
			"and the sweep below would then find nothing to guard", asn1ModulePath)
	}

	return out
}

// asn1TypedField is one field of a module SEQUENCE, with its declared type and whether the
// module marks it OPTIONAL.
type asn1TypedField struct {
	name     string
	tag      int
	typeName string
	optional bool
}

// sequenceFieldTypes returns every top-level SEQUENCE's fields with their declared types.
//
// parseASN1Sequences in asn1_drift_test.go reads the same file and keeps only names and tags,
// because what it audits is presence. This needs the type and the OPTIONAL marker, which is the
// whole of the question here, so it is a second parse of the same source rather than a widening
// of that one: the drift audit's shape is load-bearing for what it reports.
func sequenceFieldTypes(t *testing.T) map[string][]asn1TypedField {
	t.Helper()

	out := map[string][]asn1TypedField{}
	var current string
	for _, line := range asn1Lines(t) {
		if m := reSeqOpen.FindStringSubmatch(line); m != nil {
			current = m[1]
			out[current] = nil

			continue
		}
		if current == "" {
			continue
		}
		if line == "}" {
			current = ""

			continue
		}
		m := reTypedField.FindStringSubmatch(strings.TrimSuffix(line, ","))
		if m == nil {
			continue
		}
		tag, err := strconv.Atoi(m[2])
		if err != nil {
			t.Fatalf("record %s: unparsable tag %q", current, m[2])
		}
		out[current] = append(out[current], asn1TypedField{
			name:     m[1],
			tag:      tag,
			typeName: m[3],
			optional: strings.Contains(strings.ToUpper(m[4]), "OPTIONAL"),
		})
	}

	if len(out) == 0 {
		t.Fatalf("parsed no SEQUENCE definitions from %s — the parser and the module disagree", asn1ModulePath)
	}

	return out
}

// asn1Lines is the module with its comments stripped and its lines trimmed.
func asn1Lines(t *testing.T) []string {
	t.Helper()

	// A check that cannot run is not a check that passes, as the drift audit says: the module
	// is vendored beside this test so its absence is a failure and never a skip.
	src, err := os.ReadFile(asn1ModulePath)
	if err != nil {
		t.Fatalf("read %s: %v — this sweep's source of truth is the published module, and "+
			"without it nothing below is derived from anything", asn1ModulePath, err)
	}

	lines := strings.Split(string(src), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		out = append(out, strings.TrimSpace(line))
	}

	return out
}

// mandatoryEnumSite is one module-mandatory field of an emitted record whose type is an
// ENUMERATED numbered from one.
type mandatoryEnumSite struct {
	record   string // the module's record name, which is also the Go type's name
	field    string // the module's field name
	goField  string // the Go struct field, resolved by ASN.1 tag
	goType   reflect.Type
	typeName string // the module's type name
	lowest   int64
}

// key is how unguardedMandatoryEnums names a site: the module's own spelling of both halves.
func (s mandatoryEnumSite) key() string { return s.record + "." + s.field }

// goKey is how mandatoryEnumFields names a site: the Go names, because that is what the
// constraint walk has in hand when it reaches the field.
func (s mandatoryEnumSite) goKey() string { return s.record + "." + s.goField }

// mandatoryEnumSweep derives, from the module, every field of every emitted record that carries
// no OPTIONAL and whose type is an ENUMERATED numbered from one.
func mandatoryEnumSweep(t *testing.T) []mandatoryEnumSite {
	t.Helper()

	enums := enumsNumberedFromOne(t)
	sequences := sequenceFieldTypes(t)
	samples := goldenSamples()

	var out []mandatoryEnumSite
	for record, sample := range samples {
		fields, ok := sequences[record]
		if !ok {
			t.Errorf("record %s has no SEQUENCE in %s, so no field of it is being swept",
				record, asn1ModulePath)

			continue
		}
		goType := reflect.TypeOf(sample)
		modelled := modelledTags(t, goType)
		for _, f := range fields {
			if f.optional {
				continue
			}
			e, isEnum := enums[f.typeName]
			if !isEnum {
				continue
			}
			goField, isModelled := modelled[f.tag]
			if !isModelled {
				// The drift audit owns this direction: a mandatory field the module defines
				// and this package does not model is its finding, not this one. Saying so here
				// too would report one gap twice and leave the reader unsure which check is
				// the one to satisfy.
				continue
			}
			sf, ok := goType.FieldByName(goField)
			if !ok {
				t.Fatalf("%s/%s resolved to Go field %q, which %s does not have",
					record, f.name, goField, goType)
			}
			out = append(out, mandatoryEnumSite{
				record: record, field: f.name, goField: goField,
				goType: sf.Type, typeName: f.typeName, lowest: e.lowest,
			})
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })

	return out
}

// TestEveryMandatoryEnumeratedFieldRefusesZero is the sweep the rule beside mandatoryEnums
// described and nobody had run.
//
// For every field the module makes mandatory in a record this package emits, whose type is an
// ENUMERATED numbered from one: zero is a value the field's own definition does not define, and
// there is no absence for it to mean. So the guard must reach it — through mandatoryEnums where
// the type is mandatory in every emitted record that carries it, or through mandatoryEnumFields
// where it is not.
//
// A field that reaches neither is what `handoverType` was: emitted as zero, structurally
// well-formed, and refused outright by a receiver validating against this same module. Every
// intra-5GS handover record was discarded on receipt, and nothing on this side said so.
func TestEveryMandatoryEnumeratedFieldRefusesZero(t *testing.T) {
	sites := mandatoryEnumSweep(t)
	if len(sites) == 0 {
		t.Fatal("the sweep found no mandatory enumerated field in any emitted record, so it is " +
			"asserting nothing; the module or the parse has moved")
	}

	swept := map[string]bool{}
	for _, s := range sites {
		swept[s.key()] = true

		if why, excluded := unguardedMandatoryEnums[s.key()]; excluded {
			if why == "" {
				t.Errorf("%s is excluded from the zero guard with no reason recorded; an "+
					"exclusion nobody can read is indistinguishable from an omission", s.key())
			}

			continue
		}

		if !mandatoryEnums[s.goType] && !mandatoryEnumFields[s.goKey()] {
			t.Errorf("%s is %s, whose lowest defined value is %d, and the module does not mark "+
				"the field OPTIONAL — so a zero there is a value the enumeration does not have "+
				"in a field the record cannot omit, and a receiver validating against this "+
				"module refuses the whole record. Add %s to mandatoryEnums if it is mandatory in "+
				"every emitted record that carries it, or %q to mandatoryEnumFields if it is "+
				"not; if zero is somehow legitimate here, record why in unguardedMandatoryEnums",
				s.key(), s.typeName, s.lowest, s.goType.Name(), s.goKey())
		}
	}

	// A stale exclusion is the other direction of the same problem: it reads as a considered
	// decision about a field that has since been guarded, made mandatory nowhere, or removed —
	// and the next field of that name inherits an exemption nobody granted it.
	for key := range unguardedMandatoryEnums {
		if !swept[key] {
			t.Errorf("%s is recorded as an unguarded mandatory enumerated field and the sweep "+
				"no longer finds one; remove the entry rather than leaving an exemption lying "+
				"where a future field can find it", key)
		}
	}
}

// TestNoTypeKeyedGuardRefusesAnOptionalCarrier is the direction that keeps the type-keyed map
// honest, and the reason the six and the three are two mechanisms rather than one list.
//
// validateConstraints runs before ctx.Encode, so it walks the whole record and sees an unset
// optional member as zero — before the codec would have omitted it. A type in mandatoryEnums
// therefore refuses zero in *every* record carrying that type, including one where the member
// is optional and zero is how absence is spelled. `AccessType` is optional in four emitted
// records and mandatory in one; guarding it by type would refuse those four their absence,
// which trades one silent defect for another.
//
// So: a type-keyed entry is only correct while no emitted record carries that type optionally.
// `AMFRegistrationResult` is the entry this will catch first — the module gives it to
// AMFUEConfigurationUpdate as OPTIONAL, a record this package does not emit today.
func TestNoTypeKeyedGuardRefusesAnOptionalCarrier(t *testing.T) {
	enums := enumsNumberedFromOne(t)
	sequences := sequenceFieldTypes(t)

	for record, sample := range goldenSamples() {
		fields, ok := sequences[record]
		if !ok {
			continue
		}
		goType := reflect.TypeOf(sample)
		modelled := modelledTags(t, goType)
		for _, f := range fields {
			if !f.optional {
				continue
			}
			if _, isEnum := enums[f.typeName]; !isEnum {
				continue
			}
			goField, isModelled := modelled[f.tag]
			if !isModelled {
				continue
			}
			sf, ok := goType.FieldByName(goField)
			if !ok {
				continue
			}
			if mandatoryEnums[sf.Type] {
				t.Errorf("%s/%s is OPTIONAL in the module and %s is guarded by type, so this "+
					"record can no longer omit the member: the constraint walk sees an unset "+
					"optional field as zero, before the codec would have omitted it. Move %s "+
					"out of mandatoryEnums and into mandatoryEnumFields at its mandatory sites",
					record, f.name, sf.Type.Name(), sf.Type.Name())
			}
		}
	}
}

// TestEveryZeroGuardHasBoundsToRunUnder is the present-but-dead check.
//
// constraintOf consults both guard maps *inside* the enumConstraints block, so a guarded type
// with no entry there is never looked at: the map says the field is
// guarded, the walk never reaches the guard, and the record goes out exactly as before. That is
// the same failure as no guard at all, with the appearance of one — and `RATType` is a live
// example of an ENUMERATED this package declares and enumConstraints does not carry.
func TestEveryZeroGuardHasBoundsToRunUnder(t *testing.T) {
	for typ := range mandatoryEnums {
		if _, ok := enumConstraints[typ]; !ok {
			t.Errorf("%s is in mandatoryEnums and has no enumConstraints entry, so constraintOf "+
				"never consults the guard: the zero it is supposed to refuse is emitted exactly "+
				"as before, and the map claims otherwise", typ.Name())
		}
	}

	for key := range mandatoryEnumFields {
		record, field, ok := strings.Cut(key, ".")
		if !ok {
			t.Errorf("mandatoryEnumFields key %q is not Record.Field, so it matches nothing the "+
				"walk produces", key)

			continue
		}
		sample, isEmitted := goldenSamples()[record]
		if !isEmitted {
			t.Errorf("mandatoryEnumFields names record %s, which this package does not emit; a "+
				"guard on a record nothing builds is a guard that never runs", record)

			continue
		}
		sf, ok := reflect.TypeOf(sample).FieldByName(field)
		if !ok {
			t.Errorf("mandatoryEnumFields names %s and %s has no such field — the key is what "+
				"walkConstrained composes from the struct type and the field name, so a "+
				"misspelling is a guard that silently never fires", key, record)

			continue
		}
		if _, ok := enumConstraints[sf.Type]; !ok {
			t.Errorf("%s is guarded and its type %s has no enumConstraints entry, so constraintOf "+
				"never consults the guard", key, sf.Type.Name())
		}
	}
}

// TestTheEnumSweepIsNotVacuous guards the guard, as the leaf scan and the cause parse both do.
// A parser that silently matched nothing would report every field as guarded and read exactly
// like a passing conformance check.
func TestTheEnumSweepIsNotVacuous(t *testing.T) {
	enums := enumsNumberedFromOne(t)
	// TS 33.128 V18.16.0 declares 177 ENUMERATEDs, of which 171 are numbered from one. The
	// count is a tripwire on the parse, not a claim about the specification: if the module is
	// upgraded these move, and the sweep's results are then worth re-reading rather than
	// assumed.
	if len(enums) < 150 {
		t.Errorf("parsed %d ENUMERATEDs numbered from one; the module declares 171, so the "+
			"parse is now matching something other than the enumerations", len(enums))
	}
	for _, name := range []string{"HandoverType", "AccessType", "PDUSessionType", "Initiator"} {
		if _, ok := enums[name]; !ok {
			t.Errorf("%s is not among the parsed ENUMERATEDs and the module defines it", name)
		}
	}
	// Zero-based enumerations must be excluded, or the sweep would demand a guard on fields
	// where zero is a defined member. TS 33.128 has six.
	for _, name := range []string{"TargetIdentifierProvenance"} {
		if _, ok := enums[name]; ok {
			continue
		}
		t.Logf("%s is not numbered from one, as expected", name)
	}

	sites := mandatoryEnumSweep(t)
	// Fifteen, at the time of writing: the two `handoverType` fields already guarded, and the
	// thirteen this change is about — nine types across thirteen record fields.
	if len(sites) < 15 {
		t.Errorf("the sweep found %d mandatory enumerated fields across the emitted records; it "+
			"found fifteen when written, so it is now looking at something else", len(sites))
	}

	var found []string
	for _, s := range sites {
		found = append(found, fmt.Sprintf("%s:%s", s.key(), s.typeName))
	}
	t.Logf("mandatory enumerated fields swept:\n  %s", strings.Join(found, "\n  "))
}

// TestAZeroInEachMandatoryEnumeratedFieldIsRefused is the sweep's other half: the list being
// complete is worth nothing if the guard it names does not fire.
//
// One case per swept site, built by taking that record's golden sample — a fully populated,
// conformant record — and zeroing exactly the field under test. So the only thing wrong with
// each record is the one thing being asserted, and the refusal has to name that field rather
// than tripping over something else the fixture left out.
//
// The excluded sites are asserted in the other direction, and that assertion is the defect:
// a record whose mandatory enumerated field is zero still encodes, and goes out for a receiver
// to refuse. Group 3 flips these.
func TestAZeroInEachMandatoryEnumeratedFieldIsRefused(t *testing.T) {
	ctx := NewContext()

	for _, s := range mandatoryEnumSweep(t) {
		t.Run(s.key(), func(t *testing.T) {
			sample := goldenSamples()[s.record]

			// A copy, because goldenSamples returns values built fresh per call but the
			// nested slices are shared; only the top-level field is written here.
			v := reflect.New(reflect.TypeOf(sample)).Elem()
			v.Set(reflect.ValueOf(sample))
			f := v.FieldByName(s.goField)
			if f.Int() == 0 {
				t.Fatalf("the golden sample already carries zero in %s, so this case asserts "+
					"nothing; TestGoldenSamplesArePopulated should have caught that", s.key())
			}
			f.SetInt(0)

			_, err := EncodeXIRI(ctx, v.Interface())

			if why, excluded := unguardedMandatoryEnums[s.key()]; excluded {
				if err != nil {
					t.Errorf("%s is recorded as unguarded (%s) and a zero there was refused "+
						"(%v); the exclusion is stale", s.key(), why, err)
				}

				return
			}

			if err == nil {
				t.Fatalf("a record carrying zero in %s — a value %s does not define, in a field "+
					"the module does not let the record omit — was encoded. A receiver "+
					"validating against the published module refuses the whole record, and "+
					"nothing on this side says so", s.key(), s.typeName)
			}
			// The refusal has to name the field, not merely the type: two records carry
			// pDUSessionType and an agency's fault report has to say which one.
			want := s.record + "." + s.goField
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal is %q, want it to name %s", err, want)
			}
		})
	}
}

// TestAnUnsetOptionalEnumeratedFieldStillEncodes is the point of keying the rule by record and
// field rather than by type, and it has to be a test rather than a comment.
//
// The wrong fix for the three mixed carriers is to add them to mandatoryEnums. It looks
// identical from the map — one more line, same shape as the six — and it silently refuses every
// record that omits an optional `accessType`, `requestType` or `registrationType`. That is not a
// smaller version of the defect this change closes; it is a larger one, because it costs records
// on the ordinary path rather than on a path nobody has walked.
//
// Derived rather than listed: every optional field of every emitted record whose type is an
// ENUMERATED numbered from one, unset, must still encode *and* must be absent from the DER —
// asserted as a strictly shorter encoding, since an omitted member takes its tag with it.
func TestAnUnsetOptionalEnumeratedFieldStillEncodes(t *testing.T) {
	ctx := NewContext()
	enums := enumsNumberedFromOne(t)
	sequences := sequenceFieldTypes(t)

	cases := 0
	for record, sample := range goldenSamples() {
		fields, ok := sequences[record]
		if !ok {
			continue
		}
		goType := reflect.TypeOf(sample)
		modelled := modelledTags(t, goType)
		for _, f := range fields {
			if !f.optional {
				continue
			}
			if _, isEnum := enums[f.typeName]; !isEnum {
				continue
			}
			goField, isModelled := modelled[f.tag]
			if !isModelled {
				continue
			}
			sf, ok := goType.FieldByName(goField)
			if !ok || sf.Type.Kind() != reflect.Int {
				continue
			}

			cases++
			t.Run(record+"."+f.name, func(t *testing.T) {
				populated := encodeGolden(t, sample)

				v := reflect.New(goType).Elem()
				v.Set(reflect.ValueOf(sample))
				field := v.FieldByName(goField)
				if field.Int() == 0 {
					t.Fatalf("the golden sample already leaves %s.%s unset, so this case asserts "+
						"nothing", record, goField)
				}
				field.SetInt(0)

				der, err := EncodeXIRI(ctx, v.Interface())
				if err != nil {
					t.Fatalf("a record leaving its OPTIONAL %s unset was refused: %v — zero is "+
						"how an unset optional enumerated member is spelled, and refusing it "+
						"refuses every record that legitimately omits one. If %s was just added "+
						"to mandatoryEnums, it belongs in mandatoryEnumFields at its mandatory "+
						"sites instead", f.name, err, sf.Type.Name())
				}
				if got := hex.EncodeToString(der); len(got) >= len(populated) {
					t.Errorf("%s.%s unset encoded to %d hex digits and the populated record to "+
						"%d; an omitted member takes its tag with it, so this one was emitted as "+
						"a zero the enumeration does not define rather than left out",
						record, f.name, len(got), len(populated))
				}
			})
		}
	}

	// The three mixed carriers account for six of these; a run that found none would pass
	// without exercising the distinction the mechanism exists for.
	if cases < 6 {
		t.Errorf("found %d optional enumerated fields to unset across the emitted records; there "+
			"were eleven when this was written, so the scan is now looking at something else", cases)
	}
}
