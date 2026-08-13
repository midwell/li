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
	snssai := SNSSAI{SliceServiceType: 1, SliceDifferentiator: []byte{0x00, 0x00, 0x7B}}

	return map[string]any{
		"AMFRegistration": AMFRegistration{
			RegistrationType:   RegTypeInitial,
			RegistrationResult: RegResult3GPPAccess,
			SUPI:               IMSI("262019876543210"),
			PEI:                IMEI("35342500000001"),
			GPSI:               MSISDN("4915123456789"),
			GUTI:               guti,
		},
		"AMFDeregistration": AMFDeregistration{
			DeregistrationDirection: DirUEInitiated,
			AccessType:              AccessThreeGPP,
			SUPI:                    IMSI("262019876543210"),
			PEI:                     IMEI("35342500000001"),
			GPSI:                    MSISDN("4915123456789"),
			GUTI:                    guti,
		},
		"AMFLocationUpdate": AMFLocationUpdate{
			SUPI:     IMSI("262019876543210"),
			PEI:      IMEI("35342500000001"),
			GPSI:     MSISDN("4915123456789"),
			GUTI:     guti,
			Location: loc,
		},
		"AMFStartOfInterceptionWithRegisteredUE": AMFStartOfInterceptionWithRegisteredUE{
			RegistrationResult: RegResult3GPPAccess,
			RegistrationType:   RegTypeInitial,
			SUPI:               IMSI("262019876543210"),
			PEI:                IMEI("35342500000001"),
			GPSI:               MSISDN("4915123456789"),
			GUTI:               guti,
		},
		"AMFUnsuccessfulProcedure": AMFUnsuccessfulProcedure{
			FailedProcedureType: FailedRegistration,
			FailureCause:        FiveGMMCause(11),
			SUPI:                IMSI("262019876543210"),
			PEI:                 IMEI("35342500000001"),
			GPSI:                MSISDN("4915123456789"),
			GUTI:                guti,
			Location:            loc,
		},
		"AMFIdentifierAssociation": AMFIdentifierAssociation{
			SUPI:     IMSI("262019876543210"),
			PEI:      IMEI("35342500000001"),
			GPSI:     MSISDN("4915123456789"),
			GUTI:     guti,
			Location: loc,
		},
		"AMFIdentifierDeassociation": AMFIdentifierDeassociation{
			SUPI: IMSI("262019876543210"),
			GUTI: guti,
		},
		// SMFPDUSessionEstablishment gains an OPTIONAL uEEndpoint in this change.
		// This sample deliberately leaves it unset, so the record must still encode
		// byte-identically: an added optional that nobody populates changes nothing.
		"SMFPDUSessionEstablishment": SMFPDUSessionEstablishment{
			SUPI:           IMSI("262019876543210"),
			PEI:            IMEI("35342500000001"),
			GPSI:           MSISDN("4915123456789"),
			PDUSessionID:   5,
			GTPTunnelID:    fteid,
			PDUSessionType: PDUSessionTypeIPv4,
			SNSSAI:         snssai,
			DNN:            DNN("internet"),
			RequestType:    SMRequestInitial,
			AccessType:     AccessThreeGPP,
		},
		"SMFPDUSessionModification": SMFPDUSessionModification{
			SUPI:         IMSI("262019876543210"),
			PEI:          IMEI("35342500000001"),
			GPSI:         MSISDN("4915123456789"),
			SNSSAI:       snssai,
			RequestType:  SMRequestModification,
			AccessType:   AccessThreeGPP,
			PDUSessionID: 5,
		},
		"SMFPDUSessionRelease": SMFPDUSessionRelease{
			SUPI:           IMSI("262019876543210"),
			PEI:            IMEI("35342500000001"),
			GPSI:           MSISDN("4915123456789"),
			PDUSessionID:   5,
			UplinkVolume:   123456,
			DownlinkVolume: 654321,
		},
		// The one record expected to change: its mandatory uEEndpoint was emitted as
		// an empty SEQUENCE before this change and now carries the UE's address.
		"SMFStartOfInterceptionWithEstablishedPDUSession": SMFStartOfInterceptionWithEstablishedPDUSession{
			SUPI:           IMSI("262019876543210"),
			PEI:            IMEI("35342500000001"),
			GPSI:           MSISDN("4915123456789"),
			PDUSessionID:   5,
			GTPTunnelID:    fteid,
			PDUSessionType: PDUSessionTypeIPv4,
			SNSSAI:         snssai,
			UEEndpoint:     UEEndpoint(net.ParseIP("10.45.0.2")),
			DNN:            DNN("internet"),
			RequestType:    SMRequestExisting,
			AccessType:     AccessThreeGPP,
		},
	}
}

// expectedUnchanged names the records whose encoding this change must not alter.
// Everything in goldenSamples that is not listed here is expected to change, and
// TestGoldenEncodings reports it as such rather than failing.
var expectedUnchanged = map[string]bool{
	"AMFRegistration":                        true,
	"AMFDeregistration":                      true,
	"AMFLocationUpdate":                      true,
	"AMFStartOfInterceptionWithRegisteredUE": true,
	"AMFUnsuccessfulProcedure":               true,
	"AMFIdentifierAssociation":               true,
	"AMFIdentifierDeassociation":             true,
	"SMFPDUSessionEstablishment":             true,
	"SMFPDUSessionModification":              true,
	"SMFPDUSessionRelease":                   true,
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
const registeredRecordCount = 11

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
