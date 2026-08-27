// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package iri

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// updateGolden regenerates testdata/golden.txt. Run:
//
//	go test ./iri/ -run TestGoldenEncodings -update-golden
//
// The fixtures exist so that a change to the shared li/asn1 codec has to prove
// it did not disturb the records it does not intend to touch. The codec sits
// under every record type on the X2 path, so "only uEEndpoint changes" is a
// claim to be measured, not asserted. A round-trip test cannot make that claim:
// it still passes when encode and decode change together, which is exactly the
// failure that would corrupt a receiver while looking healthy from in here.
var updateGolden = flag.Bool("update-golden", false, "regenerate testdata/golden.txt")

const goldenPath = "testdata/golden.txt"

// goldenSamples is one fully-populated value per alternative registered in the
// xiriEvent CHOICE. Keep it exhaustive: TestGoldenCoversEveryRecord fails if a
// record type is registered without a sample here, so a record added later
// cannot silently escape the comparison.
//
// Values are fixed, never generated, so the encoding is reproducible.
func goldenSamples() map[string]any {
	guti := FiveGGUTI{MCC: "262", MNC: "01", AMFRegionID: 200, AMFSetID: 1, AMFPointer: 0, FiveGTMSI: 3735928559}
	loc := Location{LocationInfo: LocationInfo{CurrentLocation: true}}
	fteid := FTEID{TEID: 0x01020304, IPv4Address: []byte{10, 20, 30, 40}}
	tunnelInfo := GTPTunnelInfo{FiveGSGTPTunnels: FiveGSGTPTunnels{ULNGUUPTunnelInformation: fteid}}
	snssai := SNSSAI{SliceServiceType: 1, SliceDifferentiator: []byte{0x00, 0x00, 0x7B}}
	ids := Identifiers(IMSI("262019876543210"), IMEISV("3534250000000151"), MSISDN("4915123456789"))
	// The conditional identity members added for CONFORMANCE.md findings 2 and 3.
	// riLen is carried explicitly because the routing indicator "0123" has four
	// meaningful digits and the INTEGER 123 has three — the case the module's
	// routingIndicatorLength exists for.
	riLen := RoutingIndicatorLength(4)
	suci := SUCI{
		MCC: "262", MNC: "01",
		RoutingIndicator:       123,
		ProtectionSchemeID:     1,
		HomeNetworkPublicKeyID: []byte{0x1B},
		SchemeOutput:           []byte{0xDE, 0xAD, 0xBE, 0xEF},
		RoutingIndicatorLength: &riLen,
	}
	taiList := TAIList{{PLMNID: PLMNID{MCC: "262", MNC: "01"}, TAC: TAC{0x00, 0x2A}}}
	servingNet := SMFServingNetwork{PLMNID: PLMNID{MCC: "262", MNC: "01"}}
	amfID := AMFID{AMFRegionID: 200, AMFSetID: 1, AMFPointer: 3}
	// false is the point: it is the ordinary value, and the value the encoder could
	// not express before li/asn1 gained pointer support.
	supiAuthenticated := SUPIUnauthenticatedIndication(false)

	return map[string]any{
		"AMFRegistration": AMFRegistration{
			RegistrationType:   RegTypeInitial,
			RegistrationResult: RegResult3GPPAccess,
			SUPI:               IMSI("262019876543210"),
			PEI:                IMEI("35342500000001"),
			GPSI:               MSISDN("4915123456789"),
			GUTI:               guti,
			SUCI:               suci,
			FiveGSTAIList:      taiList,
			RATType:            RATNR,
		},
		"AMFDeregistration": AMFDeregistration{
			DeregistrationDirection: DirUEInitiated,
			AccessType:              AccessThreeGPP,
			SUPI:                    IMSI("262019876543210"),
			PEI:                     IMEI("35342500000001"),
			GPSI:                    MSISDN("4915123456789"),
			GUTI:                    guti,
			SUCI:                    suci,
		},
		"AMFLocationUpdate": AMFLocationUpdate{
			SUPI:     IMSI("262019876543210"),
			PEI:      IMEI("35342500000001"),
			GPSI:     MSISDN("4915123456789"),
			GUTI:     guti,
			Location: loc,
			SUCI:     suci,
		},
		"AMFStartOfInterceptionWithRegisteredUE": AMFStartOfInterceptionWithRegisteredUE{
			RegistrationResult: RegResult3GPPAccess,
			RegistrationType:   RegTypeInitial,
			SUPI:               IMSI("262019876543210"),
			PEI:                IMEI("35342500000001"),
			GPSI:               MSISDN("4915123456789"),
			GUTI:               guti,
			SUCI:               suci,
			FiveGSTAIList:      taiList,
		},
		"AMFUnsuccessfulProcedure": AMFUnsuccessfulProcedure{
			FailedProcedureType: FailedRegistration,
			FailureCause:        FiveGMMCause(11),
			SUPI:                IMSI("262019876543210"),
			PEI:                 IMEI("35342500000001"),
			GPSI:                MSISDN("4915123456789"),
			GUTI:                guti,
			Location:            loc,
			SUCI:                suci,
		},
		"AMFIdentifierAssociation": AMFIdentifierAssociation{
			SUPI:          IMSI("262019876543210"),
			PEI:           IMEI("35342500000001"),
			GPSI:          MSISDN("4915123456789"),
			GUTI:          guti,
			Location:      loc,
			SUCI:          suci,
			FiveGSTAIList: taiList,
		},
		"AMFIdentifierDeassociation": AMFIdentifierDeassociation{
			SUPI: IMSI("262019876543210"),
			GUTI: guti,
			SUCI: suci,
			PEI:  IMEISV("3534250000000151"),
			GPSI: MSISDN("4915123456789"),
		},
		// The three records below gain gTPTunnelInfo, which the TS 33.128 payload
		// tables mark mandatory and which was omitted. Their encodings therefore
		// change, and expectedUnchanged no longer names them.
		"SMFPDUSessionEstablishment": SMFPDUSessionEstablishment{
			SUPI:                IMSI("262019876543210"),
			PEI:                 IMEI("35342500000001"),
			GPSI:                MSISDN("4915123456789"),
			PDUSessionID:        5,
			GTPTunnelID:         fteid,
			PDUSessionType:      PDUSessionTypeIPv4,
			SNSSAI:              snssai,
			UEEndpoint:          UEEndpoint(net.IPv4(10, 45, 0, 7)),
			DNN:                 DNN("internet"),
			RequestType:         SMRequestInitial,
			AccessType:          AccessThreeGPP,
			GTPTunnelInfo:       tunnelInfo,
			SUPIUnauthenticated: &supiAuthenticated,
			AMFID:               amfID,
			RATType:             RATNR,
			ServingNetwork:      servingNet,
		},
		"SMFPDUSessionModification": SMFPDUSessionModification{
			SUPI:                IMSI("262019876543210"),
			PEI:                 IMEI("35342500000001"),
			GPSI:                MSISDN("4915123456789"),
			SNSSAI:              snssai,
			RequestType:         SMRequestModification,
			AccessType:          AccessThreeGPP,
			PDUSessionID:        5,
			GTPTunnelInfo:       tunnelInfo,
			SUPIUnauthenticated: &supiAuthenticated,
			RATType:             RATNR,
			UEEndpoint:          UEEndpoint(net.IPv4(10, 45, 0, 7)),
			ServingNetwork:      servingNet,
		},
		"SMFPDUSessionRelease": SMFPDUSessionRelease{
			SUPI:           IMSI("262019876543210"),
			PEI:            IMEI("35342500000001"),
			GPSI:           MSISDN("4915123456789"),
			PDUSessionID:   5,
			UplinkVolume:   123456,
			DownlinkVolume: 654321,
		},
		"SMFStartOfInterceptionWithEstablishedPDUSession": SMFStartOfInterceptionWithEstablishedPDUSession{
			SUPI:                IMSI("262019876543210"),
			PEI:                 IMEI("35342500000001"),
			GPSI:                MSISDN("4915123456789"),
			PDUSessionID:        5,
			GTPTunnelID:         fteid,
			PDUSessionType:      PDUSessionTypeIPv4,
			SNSSAI:              snssai,
			UEEndpoint:          UEEndpoint(net.ParseIP("10.45.0.2")),
			DNN:                 DNN("internet"),
			RequestType:         SMRequestExisting,
			AccessType:          AccessThreeGPP,
			GTPTunnelInfo:       tunnelInfo,
			SUPIUnauthenticated: &supiAuthenticated,
			AMFID:               amfID,
			RATType:             RATNR,
			ServingNetwork:      servingNet,
		},
		"SMFUnsuccessfulProcedure": SMFUnsuccessfulProcedure{
			FailedProcedureType: SMFFailedPDUSessionEstablishment,
			FailureCause:        FiveGSMCause(26),
			Initiator:           InitiatorNetwork,
			SUPI:                IMSI("262019876543210"),
			PEI:                 IMEISV("3534250000000151"),
			GPSI:                MSISDN("4915123456789"),
			PDUSessionID:        5,
			UEEndpoint:          UEEndpoint(net.IPv4(10, 45, 0, 7)),
			DNN:                 DNN("internet"),
			RequestType:         SMRequestInitial,
			AccessType:          AccessThreeGPP,
			SUPIUnauthenticated: &supiAuthenticated,
			AMFID:               amfID,
			RATType:             RATNR,
		},
		"AMFUEServiceAccept": AMFUEServiceAccept{
			UserIdentifiers:        ids,
			ServiceMessageIdentity: ServiceAcceptIdentity{0x4E},
			ServiceType:            []byte{0x01},
			FiveGTMSI:              3735928559,
		},
		"AMFUEPolicyTransfer": AMFUEPolicyTransfer{
			SUPI: IMSI("262019876543210"),
			PEI:  IMEISV("3534250000000151"),
			GPSI: MSISDN("4915123456789"),
			GUTI: guti,
			// Sixteen octets: SIZE(16..65540). A three-octet value encoded cleanly and
			// produced a golden vector no conformant receiver would accept.
			UEPolicy: UEPolicy{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			},
			SUCI: suci,
		},
		"AMFPositioningInfoTransfer": AMFPositioningInfoTransfer{
			SUPI:             IMSI("262019876543210"),
			PEI:              IMEISV("3534250000000151"),
			GPSI:             MSISDN("4915123456789"),
			GUTI:             guti,
			NRPPaMessage:     []byte{0xAA, 0xBB},
			LPPMessage:       []byte{0xCC},
			LCSCorrelationID: LCSCorrelationID("corr-1"),
			SUCI:             suci,
		},
		"AMFRANHandoverCommand": AMFRANHandoverCommand{
			UserIdentifiers:         ids,
			AMFUENGAPID:             7,
			RANUENGAPID:             9,
			HandoverType:            HandoverIntra5GS,
			TargetToSourceContainer: RANTargetToSourceContainer{0xDE, 0xAD},
		},
		"AMFRANHandoverRequest": AMFRANHandoverRequest{
			UserIdentifiers:               ids,
			AMFUENGAPID:                   7,
			RANUENGAPID:                   9,
			HandoverType:                  HandoverIntra5GS,
			HandoverCause:                 CauseRadioNetwork(17),
			PDUSessionResourceInformation: PDUSessionResourceInformation{PDUSessionID: 5},
			TargetToSourceContainer:       RANTargetToSourceContainer{0xDE, 0xAD},
			SourceToTargetContainer:       RANSourceToTargetContainer{0xBE, 0xEF},
		},
	}
}

// expectedUnchanged names the records whose encoding this change must not alter.
// Everything in goldenSamples that is not listed here is expected to change, and
// TestGoldenEncodings reports it as such rather than failing.
//
// **Reset this list at the start of each change.** It is a statement about one
// change's intended blast radius, not a standing property, and a stale list is
// worse than none — it silently blesses whatever the previous change expected.
//
// For fix-li-mandatory-enum-zero-exemption it is **every record**, and that is the
// whole of the claim: this change refuses records, and must not alter one that was
// already valid. A moved vector here means a new zero guard is firing on a
// conformant record — a delivered record turned into an undelivered one, which is
// the risk the change's own design names.
//
// The previous list was four records, for a change that deliberately moved thirteen.
// That distinction is the reason this list is rewritten rather than appended to.
var expectedUnchanged = map[string]bool{
	"AMFRegistration":                                 true,
	"AMFDeregistration":                               true,
	"AMFLocationUpdate":                               true,
	"AMFStartOfInterceptionWithRegisteredUE":          true,
	"AMFUnsuccessfulProcedure":                        true,
	"AMFIdentifierAssociation":                        true,
	"AMFIdentifierDeassociation":                      true,
	"AMFRANHandoverCommand":                           true,
	"AMFRANHandoverRequest":                           true,
	"AMFUEPolicyTransfer":                             true,
	"AMFUEServiceAccept":                              true,
	"AMFPositioningInfoTransfer":                      true,
	"SMFPDUSessionEstablishment":                      true,
	"SMFPDUSessionModification":                       true,
	"SMFPDUSessionRelease":                            true,
	"SMFStartOfInterceptionWithEstablishedPDUSession": true,
	"SMFUnsuccessfulProcedure":                        true,
}

// TestGoldenSamplesArePopulated is what keeps this file's claim true.
//
// The samples are the inertness baseline for the shared li/asn1 codec: a change
// there has to show which records it altered, and a record can only show that for
// the fields its sample actually carries. A modelled field left unset is absent
// from the comparison, and on the wire it is indistinguishable from a field the
// record does not have — so the baseline reports an inertness it never measured.
//
// That is not hypothetical. Three samples were incomplete when this test was
// written, two of them (uEEndpoint on SMFPDUSessionEstablishment and on
// SMFUnsuccessfulProcedure) for fields the SMF populates in production. The
// comment above goldenSamples already said "one fully-populated value per
// alternative", which is exactly why nobody checked: a reader looking for whether
// the property was recorded found that it was.
//
// Top-level record fields only. Nested members legitimately carry zero — a GUTI's
// aMFPointer of 0 is a value, not an omission — and the tag-level presence this
// baseline pins is decided at the top level.
func TestGoldenSamplesArePopulated(t *testing.T) {
	for name, sample := range goldenSamples() {
		v := reflect.ValueOf(sample)
		if v.Kind() != reflect.Struct {
			continue
		}
		for i := range v.NumField() {
			f := v.Type().Field(i)
			if _, tagged := f.Tag.Lookup("asn1"); !tagged {
				continue
			}
			if v.Field(i).IsZero() {
				t.Errorf("%s/%s is modelled but the golden sample leaves it unset, so a codec "+
					"change touching it would not appear in the comparison. Populate it with a "+
					"distinguishable value and regenerate.", name, f.Name)
			}
		}
	}
}

func encodeGolden(t *testing.T, event any) string {
	t.Helper()
	der, err := EncodeXIRI(NewContext(), event)
	if err != nil {
		t.Fatalf("EncodeXIRI(%T): %v", event, err)
	}
	return hex.EncodeToString(der)
}

func readGolden(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(goldenPath)
	if err != nil {
		t.Fatalf("open %s: %v (regenerate with -update-golden)", goldenPath, err)
	}
	defer f.Close() //nolint:errcheck // test

	got := map[string]string{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, encoded, ok := strings.Cut(line, " ")
		if !ok {
			t.Fatalf("malformed line in %s: %q", goldenPath, line)
		}
		got[name] = encoded
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read %s: %v", goldenPath, err)
	}
	return got
}

func writeGolden(t *testing.T, encodings map[string]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(goldenPath), 0o750); err != nil {
		t.Fatalf("mkdir testdata: %v", err)
	}
	names := make([]string, 0, len(encodings))
	for name := range encodings {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	// The generated file is checked in, so it needs its own licensing information
	// or `reuse lint` fails the build. It is written here rather than in a
	// `.license` sidecar precisely because this function rewrites the file: a
	// sidecar would outlive a regeneration that dropped the tags from the file it
	// describes, which is how the tags went missing in the first place.
	// REUSE-IgnoreStart -- these tags describe the generated file, not this one;
	// without the guard `reuse lint` reads the string literal's trailing escape as
	// part of the licence expression and rejects it.
	b.WriteString("# SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB\n")
	b.WriteString("# SPDX-License-Identifier: Apache-2.0\n")
	// REUSE-IgnoreEnd
	b.WriteString("#\n")
	b.WriteString("# DER encodings of every xIRI record type, one per line: <RecordName> <hex>.\n")
	b.WriteString("# Regenerate with: go test ./iri/ -run TestGoldenEncodings -update-golden\n")
	b.WriteString("# These pin the output of the shared li/asn1 codec so a codec change has to\n")
	b.WriteString("# show which records it altered. Do not edit by hand.\n")
	for _, name := range names {
		fmt.Fprintf(&b, "%s %s\n", name, encodings[name])
	}
	if err := os.WriteFile(goldenPath, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write %s: %v", goldenPath, err)
	}
}

// TestGoldenEncodings pins the DER of every record type. A codec change that
// alters a record not named in expectedUnchanged fails here.
func TestGoldenEncodings(t *testing.T) {
	samples := goldenSamples()

	encodings := make(map[string]string, len(samples))
	for name, event := range samples {
		encodings[name] = encodeGolden(t, event)
	}

	if *updateGolden {
		writeGolden(t, encodings)
		t.Logf("regenerated %s with %d records", goldenPath, len(encodings))
		return
	}

	want := readGolden(t)
	for name, got := range encodings {
		expected, ok := want[name]
		if !ok {
			t.Errorf("%s: no fixture recorded; regenerate with -update-golden", name)
			continue
		}
		switch {
		case got == expected:
			// unchanged, as required for expectedUnchanged and permitted otherwise
		case expectedUnchanged[name]:
			t.Errorf("%s: encoding changed but must not\n got  %s\n want %s", name, got, expected)
		default:
			t.Logf("%s: encoding changed, which this change expects", name)
		}
	}
	for name := range want {
		if _, ok := encodings[name]; !ok {
			t.Errorf("%s: fixture recorded but no sample builds it", name)
		}
	}
}

// registeredRecordCount is the number of alternatives in NewContext's xiriEvent
// CHOICE. Adding a record type means adding a golden sample and bumping this.
//
// It is a count rather than a walk of the registry because asn1.Context keeps its
// choice entries unexported, and widening that API to let a test introspect it
// would be a change to the vendored codec for no runtime benefit.
const registeredRecordCount = 17

// TestGoldenCoversEveryRecord checks the golden set against the registry in both
// directions it can: every sample must actually be a registered xiriEvent
// alternative (EncodeXIRI fails otherwise), and the sample count must match the
// number registered, so a record added without a sample shows up here.
func TestGoldenCoversEveryRecord(t *testing.T) {
	samples := goldenSamples()
	if len(samples) != registeredRecordCount {
		t.Errorf("golden samples = %d, registered xiriEvent alternatives = %d — "+
			"add a sample for the new record (and bump registeredRecordCount)",
			len(samples), registeredRecordCount)
	}
	for name, event := range samples {
		if _, err := EncodeXIRI(NewContext(), event); err != nil {
			t.Errorf("%s: sample is not an encodable xiriEvent alternative: %v", name, err)
		}
	}
}
