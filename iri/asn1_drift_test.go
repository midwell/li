// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package iri

import (
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// This is the TS 33.128 counterpart of the X1 schema drift audit: it compiles
// each record's field list from the published ASN.1 module and fails when the
// module defines a field this package neither models nor declares as absent on
// purpose.
//
// What it can and cannot establish, because the difference is the whole reason
// it exists:
//
//   - It CAN tell you that the module defines a field and we never populate it.
//     That is the silent half — a mediation function receives a record that
//     decodes cleanly and carries less than it should.
//   - It CANNOT tell you whether that field is mandatory. The module marks very
//     nearly everything OPTIONAL; the M/C/O markers live in the payload tables of
//     TS 33.128 clause 6.2, which are prose and are not machine-readable. So a
//     record can omit a field the tables mark M and decode perfectly against this
//     module — which has happened, and is recorded in CONFORMANCE.md.
//
// The judgement therefore stays with the reader: this test enumerates, the
// payload tables decide, and declaredAbsent records what was decided.

const asn1ModulePath = "testdata/asn1/TS33128Payloads.asn"

// declaredAbsent lists, per record, the module-defined fields this package does
// not model, each with the reason. The rule is the same anti-rot rule the X1
// audit uses: a field missing from this map fails the test, AND a field listed
// here that has since been modelled also fails, so the list cannot quietly rot
// into a description of a state that no longer holds.
//
// Every entry carries the field's M/C/O marker, the payload table it came from,
// and a verdict on whether this project meets the condition:
//
//	MET        the network function holds the data and does not report it — a
//	           finding, listed in CONFORMANCE.md
//	NOT HELD   the network function does not hold the datum
//	N/A        the condition cannot arise; the feature is not implemented here
//	DEFERRED   the datum exists but the subtree is deliberately not modelled
//	BLOCKED    the codec cannot express the value
//	DEPRECATED the specification no longer uses the field
//	UNTRACED   a similarly named field exists in the context and the mapping was
//	           not followed through — the one verdict that is an admission rather
//	           than a conclusion, and deliberately visible as such
var declaredAbsent = map[string]map[string]string{
	"AMFDeregistration": {
		"additionalUserIdentifiers":    "C, table 6.2.2.2.3-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"cause":                        "C, table 6.2.2.2.3-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"location":                     "C, table 6.2.2.2.3-1: DEFERRED: li/iri.Location models only locationInfo.currentLocation; the userLocation subtree the table asks for is a documented deferral, so the reportable content does not exist yet",
		"reRegRequiredIndicator":       "C, table 6.2.2.2.3-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"sUCI":                         "C, table 6.2.2.2.3-1: MET (finding): the AMF holds AmfUe.Suci, but its LI identity snapshot (UeIdentity) does not carry it, so the POI cannot report it",
		"switchOffIndicator":           "C, table 6.2.2.2.3-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"unavailabilityPeriodDuration": "C, table 6.2.2.2.3-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
	},
	"AMFIdentifierAssociation": {
		"additionalUserIdentifiers": "C, table 6.2.2.2.7-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"fiveGSTAIList":             "C, table 6.2.2.2.7-1: MET (finding): the AMF holds the UE's TAI list",
		"sUCI":                      "C, table 6.2.2.2.7-1: MET (finding): the AMF holds AmfUe.Suci, but its LI identity snapshot (UeIdentity) does not carry it, so the POI cannot report it",
	},
	"AMFIdentifierDeassociation": {
		"additionalUserIdentifiers": "C, table 6.2.2.2.7-2: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"gPSI":                      "C, table 6.2.2.2.7-2: MET (finding): the AMF holds the GPSI and reports it in every other record it emits",
		"location":                  "C, table 6.2.2.2.7-2: DEFERRED: li/iri.Location models only locationInfo.currentLocation; the userLocation subtree the table asks for is a documented deferral, so the reportable content does not exist yet",
		"pEI":                       "C, table 6.2.2.2.7-2: MET (finding): the AMF holds the PEI and reports it in every other record it emits",
		"sUCI":                      "C, table 6.2.2.2.7-2: MET (finding): the AMF holds AmfUe.Suci, but its LI identity snapshot (UeIdentity) does not carry it, so the POI cannot report it",
	},
	"AMFLocationUpdate": {
		"additionalUserIdentifiers":     "C, table 6.2.2.2.4-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"deprecatedOldGUTI":             "C, table 6.2.2.2.4-1: DEPRECATED: the specification records it as no longer used",
		"deprecatedSMSOverNASIndicator": "C, table 6.2.2.2.4-1: DEPRECATED: the specification records it as no longer used",
		"sUCI":                          "C, table 6.2.2.2.4-1: MET (finding): the AMF holds AmfUe.Suci, but its LI identity snapshot (UeIdentity) does not carry it, so the POI cannot report it",
		"uEAreaIndication":              "C, table 6.2.2.2.4-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
	},
	"AMFPositioningInfoTransfer": {
		"additionalUserIdentifiers": "C, table 6.2.2.2.8-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"sUCI":                      "C, table 6.2.2.2.8-1: MET (finding): the AMF holds AmfUe.Suci, but its LI identity snapshot (UeIdentity) does not carry it, so the POI cannot report it",
	},
	"AMFRANHandoverRequest": {
		"locationReportingRequestType": "C, table 6.2.2.2.9.3-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"mobilityRestrictionList":      "C, table 6.2.2.2.9.3-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"nPNAccessInformation":         "C, table 6.2.2.2.9.3-1: N/A: non-public network access is not implemented",
	},
	"AMFRegistration": {
		"additionalUserIdentifiers":       "C, table 6.2.2.2.2-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"alternativeNSSAI":                "C, table 6.2.2.2.2-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"eMM5GRegStatus":                  "C, table 6.2.2.2.2-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"equivalentPLMNList":              "C, table 6.2.2.2.2-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"establishmentCauseNon3GPPAccess": "C, table 6.2.2.2.2-1: N/A: requires non-3GPP access (N3IWF/TNGF/TWIF), which this deployment does not provide",
		"fiveGMMCapability":               "C, table 6.2.2.2.2-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"fiveGSTAIList":                   "C, table 6.2.2.2.2-1: MET (finding): the AMF holds the UE's TAI list",
		"fiveGSUpdateType":                "C, table 6.2.2.2.2-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"initialRANUEContextSetup":        "C, table 6.2.2.2.2-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"location":                        "C, table 6.2.2.2.2-1: DEFERRED: li/iri.Location models only locationInfo.currentLocation; the userLocation subtree the table asks for is a documented deferral, so the reportable content does not exist yet",
		"mACRestIndicator":                "C, table 6.2.2.2.2-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"mUSIMUERequestType":              "C, table 6.2.2.2.2-1: N/A: multi-USIM is not implemented",
		"nASTransportInitialInformation":  "C, table 6.2.2.2.2-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"nGInformation":                   "C, table 6.2.2.2.2-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"non3GPPAccessEndpoint":           "C, table 6.2.2.2.2-1: N/A: requires non-3GPP access (N3IWF/TNGF/TWIF), which this deployment does not provide",
		"nonIMEISVPEI":                    "C, table 6.2.2.2.2-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"oldGUTI":                         "C, table 6.2.2.2.2-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"pagingRestrictionIndicator":      "C, table 6.2.2.2.2-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"rATType":                         "C, table 6.2.2.2.2-1: MET (finding): the SMF holds SMContext.RatType, set from the CreateSMContext request",
		"rRCEstablishmentCause":           "C, table 6.2.2.2.2-1: UNTRACED: the AMF holds RAN-supplied UE context; whether the establishment cause survives to the POI was not traced",
		"sMSOverNasIndicator":             "C, table 6.2.2.2.2-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"sORTransparentContainer":         "C, table 6.2.2.2.2-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"sUCI":                            "C, table 6.2.2.2.2-1: MET (finding): the AMF holds AmfUe.Suci, but its LI identity snapshot (UeIdentity) does not carry it, so the POI cannot report it",
		"slice":                           "C, table 6.2.2.2.2-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"uEAreaIndication":                "C, table 6.2.2.2.2-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"unavailabilityPeriodDuration":    "C, table 6.2.2.2.2-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
	},
	"AMFStartOfInterceptionWithRegisteredUE": {
		"additionalUserIdentifiers":    "C, table 6.2.2.2.5-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"eMM5GRegStatus":               "C, table 6.2.2.2.5-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"fiveGSTAIList":                "C, table 6.2.2.2.5-1: MET (finding): the AMF holds the UE's TAI list",
		"fiveGSUpdateType":             "C, table 6.2.2.2.5-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"location":                     "C, table 6.2.2.2.5-1: DEFERRED: li/iri.Location models only locationInfo.currentLocation; the userLocation subtree the table asks for is a documented deferral, so the reportable content does not exist yet",
		"non3GPPAccessEndpoint":        "C, table 6.2.2.2.5-1: N/A: requires non-3GPP access (N3IWF/TNGF/TWIF), which this deployment does not provide",
		"oldGUTI":                      "C, table 6.2.2.2.5-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"sMSOverNASIndicator":          "C, table 6.2.2.2.5-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"sORTransparentContainer":      "C, table 6.2.2.2.5-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"sUCI":                         "C, table 6.2.2.2.5-1: MET (finding): the AMF holds AmfUe.Suci, but its LI identity snapshot (UeIdentity) does not carry it, so the POI cannot report it",
		"slice":                        "C, table 6.2.2.2.5-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"timeOfRegistration":           "C, table 6.2.2.2.5-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"uEAreaIndication":             "C, table 6.2.2.2.5-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"uEPolicy":                     "C, table 6.2.2.2.5-1: UNTRACED: the AMF holds policy association state; whether it carries the MANAGE UE POLICY COMMAND payload was not traced",
		"unavailabilityPeriodDuration": "C, table 6.2.2.2.5-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
	},
	"AMFUEPolicyTransfer": {
		"sUCI": "C, table 6.2.2.2.12-1: MET (finding): the AMF holds AmfUe.Suci, but its LI identity snapshot (UeIdentity) does not carry it, so the POI cannot report it",
	},
	"AMFUEServiceAccept": {
		"deprecatedUERequestType": "O, table 6.2.2.2.13-1: DEPRECATED: the specification records it as no longer used",
		"forbiddenTAIList":        "C, table 6.2.2.2.13-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"pDUSessionStatus":        "C, table 6.2.2.2.13-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"pagingRestriction":       "C, table 6.2.2.2.13-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"uERequestType":           "C, table 6.2.2.2.13-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"uplinkDataStatus":        "C, table 6.2.2.2.13-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
	},
	"AMFUnsuccessfulProcedure": {
		"additionalUserIdentifiers": "C, table 6.2.2.2.6-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"alternativeNSSAI":          "C, table 6.2.2.2.6-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"requestedSlice":            "C, table 6.2.2.2.6-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"sUCI":                      "C, table 6.2.2.2.6-1: MET (finding): the AMF holds AmfUe.Suci, but its LI identity snapshot (UeIdentity) does not carry it, so the POI cannot report it",
	},
	"SMFPDUSessionEstablishment": {
		"aMFID":                         "C, table 6.2.3-1: MET (finding): the SMF holds SMContext.ServingNfId, the AMF serving the session",
		"alternativeNSSAI":              "C, table 6.2.3-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"ePS5GSComboInfo":               "C, table 6.2.3-1: N/A: reports an EPS/5GS interworking case; this project implements no N26 interworking or SGW/PGW role",
		"ePSPDNConnectionEstablishment": "C, table 6.2.3-1: N/A: reports an EPS/5GS interworking case; this project implements no N26 interworking or SGW/PGW role",
		"gEOSatelliteID":                "C, table 6.2.3-1: N/A: satellite backhaul is not implemented",
		"hSMFURI":                       "C, table 6.2.3-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"handoverState":                 "C, table 6.2.3-1: UNTRACED: a similarly named field exists in the SMF context; the mapping was not traced",
		"location":                      "C, table 6.2.3-1: DEFERRED: li/iri.Location models only locationInfo.currentLocation; the userLocation subtree the table asks for is a documented deferral, so the reportable content does not exist yet",
		"non3GPPAccessEndpoint":         "C, table 6.2.3-1: N/A: requires non-3GPP access (N3IWF/TNGF/TWIF), which this deployment does not provide",
		"oldPDUSessionID":               "C, table 6.2.3-1: UNTRACED: a similarly named field exists in the SMF context; the mapping was not traced",
		"pCCRules":                      "C, table 6.2.3-1: UNTRACED: the SMF holds SmPolicyData; whether it carries the PCC rule set in the reported form was not traced",
		"rATType":                       "C, table 6.2.3-1: MET (finding): the SMF holds SMContext.RatType, set from the CreateSMContext request",
		"sMPDUDNRequest":                "C, table 6.2.3-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"sUPIUnauthenticated":           "C, table 6.2.3-1: BLOCKED: the meaningful value is false, which li/asn1 cannot encode for an OPTIONAL field — see CONFORMANCE.md finding 2",
		"satelliteBackhaulCategory":     "C, table 6.2.3-1: N/A: satellite backhaul is not implemented",
		"selectedDNN":                   "C, table 6.2.3-1: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"servingNetwork":                "C, table 6.2.3-1: MET (finding): the SMF holds SMContext.ServingNetwork",
		"uEEPSPDNConnection":            "C, table 6.2.3-1: N/A: reports an EPS/5GS interworking case; this project implements no N26 interworking or SGW/PGW role",
	},
	"SMFPDUSessionModification": {
		"alternativeNSSAI":             "C, table 6.2.3-2: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"ePS5GSComboInfo":              "C, table 6.2.3-2: N/A: reports an EPS/5GS interworking case; this project implements no N26 interworking or SGW/PGW role",
		"ePSPDNConnectionModification": "C, table 6.2.3-2: N/A: reports an EPS/5GS interworking case; this project implements no N26 interworking or SGW/PGW role",
		"gEOSatelliteID":               "C, table 6.2.3-2: N/A: satellite backhaul is not implemented",
		"handoverState":                "C, table 6.2.3-2: UNTRACED: a similarly named field exists in the SMF context; the mapping was not traced",
		"location":                     "C, table 6.2.3-2: DEFERRED: li/iri.Location models only locationInfo.currentLocation; the userLocation subtree the table asks for is a documented deferral, so the reportable content does not exist yet",
		"non3GPPAccessEndpoint":        "C, table 6.2.3-2: N/A: requires non-3GPP access (N3IWF/TNGF/TWIF), which this deployment does not provide",
		"pCCRules":                     "C, table 6.2.3-2: UNTRACED: the SMF holds SmPolicyData; whether it carries the PCC rule set in the reported form was not traced",
		"pFDDataForApp":                "C, table 6.2.3-2: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"rATType":                      "C, table 6.2.3-2: MET (finding): the SMF holds SMContext.RatType, set from the CreateSMContext request",
		"sUPIUnauthenticated":          "C, table 6.2.3-2: BLOCKED: the meaningful value is false, which li/asn1 cannot encode for an OPTIONAL field — see CONFORMANCE.md finding 2",
		"satelliteBackhaulCategory":    "C, table 6.2.3-2: N/A: satellite backhaul is not implemented",
		"servingNetwork":               "C, table 6.2.3-2: MET (finding): the SMF holds SMContext.ServingNetwork",
		"uEEndpoint":                   "C, table 6.2.3-2: MET (finding): the SMF holds SMContext.PDUAddress and already reports it in the session records",
		"uPPathChange":                 "C, table 6.2.3-2: NOT HELD: the network function does not hold this datum, so the condition is not met",
	},
	"SMFPDUSessionRelease": {
		"alternativeNSSAI":        "C, table 6.2.3-3: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"cause":                   "C, table 6.2.3-3: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"ePS5GSComboInfo":         "C, table 6.2.3-3: N/A: reports an EPS/5GS interworking case; this project implements no N26 interworking or SGW/PGW role",
		"ePSPDNConnectionRelease": "C, table 6.2.3-3: N/A: reports an EPS/5GS interworking case; this project implements no N26 interworking or SGW/PGW role",
		"fiveGMMCause":            "C, table 6.2.3-3: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"location":                "C, table 6.2.3-3: DEFERRED: li/iri.Location models only locationInfo.currentLocation; the userLocation subtree the table asks for is a documented deferral, so the reportable content does not exist yet",
		"nGAPCause":               "C, table 6.2.3-3: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"pCCRuleIDs":              "C, table 6.2.3-3: UNTRACED: as pCCRules",
		"timeOfFirstPacket":       "C, table 6.2.3-3: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"timeOfLastPacket":        "C, table 6.2.3-3: NOT HELD: the network function does not hold this datum, so the condition is not met",
	},
	"SMFStartOfInterceptionWithEstablishedPDUSession": {
		"aMFID":           "C, table 6.2.3-4: MET (finding): the SMF holds SMContext.ServingNfId, the AMF serving the session",
		"ePS5GSComboInfo": "C, table 6.2.3-4: N/A: reports an EPS/5GS interworking case; this project implements no N26 interworking or SGW/PGW role",
		"ePSStartOfInterceptionWithEstablishedPDNConnection": "C, table 6.2.3-4: N/A: reports an EPS/5GS interworking case; this project implements no N26 interworking or SGW/PGW role",
		"gEOSatelliteID":             "C, table 6.2.3-4: N/A: satellite backhaul is not implemented",
		"hSMFURI":                    "C, table 6.2.3-4: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"location":                   "C, table 6.2.3-4: DEFERRED: li/iri.Location models only locationInfo.currentLocation; the userLocation subtree the table asks for is a documented deferral, so the reportable content does not exist yet",
		"non3GPPAccessEndpoint":      "C, table 6.2.3-4: N/A: requires non-3GPP access (N3IWF/TNGF/TWIF), which this deployment does not provide",
		"pCCRules":                   "C, table 6.2.3-4: UNTRACED: the SMF holds SmPolicyData; whether it carries the PCC rule set in the reported form was not traced",
		"pFDDataForApps":             "C, table 6.2.3-4: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"rATType":                    "C, table 6.2.3-4: MET (finding): the SMF holds SMContext.RatType, set from the CreateSMContext request",
		"sMPDUDNRequest":             "C, table 6.2.3-4: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"sUPIUnauthenticated":        "C, table 6.2.3-4: BLOCKED: the meaningful value is false, which li/asn1 cannot encode for an OPTIONAL field — see CONFORMANCE.md finding 2",
		"satelliteBackhaulCategory":  "C, table 6.2.3-4: N/A: satellite backhaul is not implemented",
		"servingNetwork":             "C, table 6.2.3-4: MET (finding): the SMF holds SMContext.ServingNetwork",
		"timeOfSessionEstablishment": "C, table 6.2.3-4: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"uEEPSPDNConnection":         "C, table 6.2.3-4: N/A: reports an EPS/5GS interworking case; this project implements no N26 interworking or SGW/PGW role",
	},
	"SMFUnsuccessfulProcedure": {
		"aMFID":                       "C, table 6.2.3-5: MET (finding): the SMF holds SMContext.ServingNfId, the AMF serving the session",
		"alternativeNSSAI":            "C, table 6.2.3-5: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"ePSPDNUnsuccessfulProcedure": "C, table 6.2.3-5: N/A: reports an EPS/5GS interworking case; this project implements no N26 interworking or SGW/PGW role",
		"hSMFURI":                     "C, table 6.2.3-5: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"location":                    "C, table 6.2.3-5: DEFERRED: li/iri.Location models only locationInfo.currentLocation; the userLocation subtree the table asks for is a documented deferral, so the reportable content does not exist yet",
		"non3GPPAccessEndpoint":       "C, table 6.2.3-5: N/A: requires non-3GPP access (N3IWF/TNGF/TWIF), which this deployment does not provide",
		"rATType":                     "C, table 6.2.3-5: MET (finding): the SMF holds SMContext.RatType, set from the CreateSMContext request",
		"requestedSlice":              "C, table 6.2.3-5: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"sMPDUDNRequest":              "C, table 6.2.3-5: NOT HELD: the network function does not hold this datum, so the condition is not met",
		"sUPIUnauthenticated":         "C, table 6.2.3-5: BLOCKED: the meaningful value is false, which li/asn1 cannot encode for an OPTIONAL field — see CONFORMANCE.md finding 2",
	},
}

// asn1Field is one field of a SEQUENCE in the published module.
type asn1Field struct {
	name string
	tag  int
}

var (
	reSeqStart = regexp.MustCompile(`^(\w+)\s*::=\s*SEQUENCE\s*$`)
	reField    = regexp.MustCompile(`^\s*(\w+)\s*\[(\d+)\]`)
)

// parseASN1Sequences returns the fields of every top-level SEQUENCE in the
// module, keyed by type name.
func parseASN1Sequences(t *testing.T) map[string][]asn1Field {
	t.Helper()
	// A check that cannot run is not a check that passes: the module is vendored
	// beside this test precisely so its absence is a failure and never a skip.
	src, err := os.ReadFile(asn1ModulePath)
	if err != nil {
		t.Fatalf("read %s: %v — the vendored TS 33.128 module is what this audit "+
			"compares against; without it no record is being checked at all", asn1ModulePath, err)
	}

	out := map[string][]asn1Field{}
	var current string
	for _, line := range strings.Split(string(src), "\n") {
		trimmed := strings.TrimSpace(line)
		if idx := strings.Index(trimmed, "--"); idx >= 0 { // strip ASN.1 comments
			trimmed = strings.TrimSpace(trimmed[:idx])
		}
		if m := reSeqStart.FindStringSubmatch(trimmed); m != nil {
			current = m[1]
			out[current] = nil
			continue
		}
		if current == "" {
			continue
		}
		if trimmed == "}" {
			current = ""
			continue
		}
		if m := reField.FindStringSubmatch(trimmed); m != nil {
			tag, err := strconv.Atoi(m[2])
			if err != nil {
				t.Fatalf("record %s: unparsable tag %q", current, m[2])
			}
			out[current] = append(out[current], asn1Field{name: m[1], tag: tag})
		}
	}
	if len(out) == 0 {
		t.Fatalf("parsed no SEQUENCE definitions from %s — the parser and the module disagree", asn1ModulePath)
	}
	return out
}

// modelledTags returns the ASN.1 context tags the Go struct declares.
func modelledTags(t *testing.T, typ reflect.Type) map[int]string {
	t.Helper()
	tags := map[int]string{}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		opts := f.Tag.Get("asn1")
		for _, part := range strings.Split(opts, ",") {
			if !strings.HasPrefix(part, "tag:") {
				continue
			}
			n, err := strconv.Atoi(strings.TrimPrefix(part, "tag:"))
			if err != nil {
				t.Fatalf("%s.%s: unparsable asn1 tag %q", typ.Name(), f.Name, part)
			}
			tags[n] = f.Name
		}
	}
	return tags
}

// TestASN1RecordDrift fails when the published module defines a field for a
// record this project emits that the record neither models nor declares absent.
func TestASN1RecordDrift(t *testing.T) {
	module := parseASN1Sequences(t)

	var undeclared []string
	var staleDeclarations []string

	for name := range goldenSamples() {
		fields, ok := module[name]
		if !ok {
			t.Errorf("record %s has no SEQUENCE in %s — either the record name is wrong "+
				"or the module no longer defines it", name, asn1ModulePath)
			continue
		}
		modelled := modelledTags(t, reflect.TypeOf(goldenSamples()[name]))
		declared := declaredAbsent[name]

		for _, f := range fields {
			_, isModelled := modelled[f.tag]
			_, isDeclared := declared[f.name]
			switch {
			case isModelled && isDeclared:
				staleDeclarations = append(staleDeclarations, fmt.Sprintf(
					"%s/%s is declared absent but is now modelled — remove the declaration", name, f.name))
			case !isModelled && !isDeclared:
				undeclared = append(undeclared, fmt.Sprintf("%s/%s [%d]", name, f.name, f.tag))
			}
		}

		// A declaration naming a field the module no longer defines is also rot.
		for declaredName := range declared {
			found := false
			for _, f := range fields {
				if f.name == declaredName {
					found = true
					break
				}
			}
			if !found {
				staleDeclarations = append(staleDeclarations, fmt.Sprintf(
					"%s/%s is declared absent but the module does not define it", name, declaredName))
			}
		}
	}

	sort.Strings(undeclared)
	sort.Strings(staleDeclarations)

	for _, s := range staleDeclarations {
		t.Errorf("stale declaration: %s", s)
	}
	if len(undeclared) > 0 {
		t.Errorf("%d field(s) the published module defines that this package neither models "+
			"nor declares absent. Judge each against its payload table in TS 33.128 clause 6.2 "+
			"— the module marks nearly everything OPTIONAL, so this list says nothing about which "+
			"are mandatory — then record the verdict in declaredAbsent:\n  %s",
			len(undeclared), strings.Join(undeclared, "\n  "))
	}
}

// TestASN1DriftAuditDetectsAnOmission proves the audit above can fail. Without
// this, a parser that silently produced no fields would report every record as
// clean and read exactly like a passing conformance check.
func TestASN1DriftAuditDetectsAnOmission(t *testing.T) {
	module := parseASN1Sequences(t)

	fields, ok := module["SMFPDUSessionModification"]
	if !ok {
		t.Fatal("SMFPDUSessionModification is not defined in the vendored module")
	}
	byName := map[string]int{}
	for _, f := range fields {
		byName[f.name] = f.tag
	}

	modelled := modelledTags(t, reflect.TypeOf(SMFPDUSessionModification{}))

	// gTPTunnelInfo is marked M in payload table 6.2.3-2 and OPTIONAL in the
	// module, which is why no decoder caught its absence. It is modelled now, and
	// this asserts it stays that way: for this record it is the *only* mandatory
	// field, so losing it again would leave the record satisfying none of its
	// mandatory set while still decoding cleanly.
	tag, ok := byName["gTPTunnelInfo"]
	if !ok {
		t.Fatal("the module no longer defines SMFPDUSessionModification/gTPTunnelInfo")
	}
	if _, present := modelled[tag]; !present {
		t.Error("SMFPDUSessionModification no longer models gTPTunnelInfo, which table 6.2.3-2 marks mandatory")
	}

	// sUPIUnauthenticated is still absent, so it stands in as the proof that the
	// audit can see an omission at all. When it is implemented, this assertion
	// fails and should be repointed at whatever is unmodelled then — a sentinel
	// that has nothing left to detect is worse than none.
	tag, ok = byName["sUPIUnauthenticated"]
	if !ok {
		t.Fatal("the module no longer defines SMFPDUSessionModification/sUPIUnauthenticated")
	}
	if _, present := modelled[tag]; present {
		t.Error("sUPIUnauthenticated is now modelled: repoint this sentinel at a field that is not, " +
			"and update CONFORMANCE.md, which records it as a finding")
	}
	if _, declared := declaredAbsent["SMFPDUSessionModification"]["sUPIUnauthenticated"]; !declared {
		t.Error("sUPIUnauthenticated is neither modelled nor declared absent, which the audit above " +
			"should already have caught — this test and that one disagree")
	}
}
