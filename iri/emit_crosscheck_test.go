// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package iri

// TEMPORARY: compares the explicit emitter against the vendored codec while both
// exist. Deleted with li/asn1; the golden fixtures carry the comparison after that.

import (
	"encoding/hex"
	"fmt"
	"net"
	"reflect"
	"testing"
)

func oldEncode(event any) ([]byte, error) {
	return NewContext().Encode(XIRIPayload{OID: xIRIPayloadOID, Event: event})
}

func crossCheck(t *testing.T, name string, event any) {
	t.Helper()
	want, werr := oldEncode(event)
	got, gerr := encodePayload(event)
	if (werr != nil) != (gerr != nil) {
		t.Errorf("%s: old err=%v, new err=%v", name, werr, gerr)
		return
	}
	if werr == nil && hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Errorf("%s:\n new %x\n old %x", name, got, want)
	}
}

// mutations yields every golden form, and every form with one field — at any depth —
// set to its zero value.
func mutations(t *testing.T) map[string]any {
	t.Helper()
	out := map[string]any{}
	for name, sample := range goldenForms() {
		out[name] = sample
		v := reflect.ValueOf(sample)
		for i := range v.NumField() {
			cp := reflect.New(v.Type()).Elem()
			cp.Set(v)
			cp.Field(i).SetZero()
			out[name+"-"+v.Type().Field(i).Name] = cp.Interface()
		}
	}
	for _, n := range nestedOptionals {
		for name, sample := range goldenSamples() {
			v := reflect.New(reflect.TypeOf(sample)).Elem()
			v.Set(reflect.ValueOf(sample))
			if blankFirst(v, n.typ, n.field) {
				out[name+"-"+n.typ.Name()+"."+n.field] = v.Interface()
			}
		}
	}
	return out
}

func TestCrossCheckEmitterAgainstVendoredCodec(t *testing.T) {
	cases := mutations(t)
	for name, ev := range cases {
		crossCheck(t, name, ev)
	}
	t.Logf("%d cases", len(cases))
}

func TestCrossCheckAlternatives(t *testing.T) {
	ids := func(v ...any) UserIdentifiers { return UserIdentifiers{FiveGS: FiveGSSubscriberIDs{IDs: v}} }
	guti := FiveGGUTI{MCC: "262", MNC: "01", AMFRegionID: 1, AMFSetID: 1, FiveGTMSI: 1}
	f := false
	tr := true
	cases := map[string]any{}
	for _, s := range []any{IMSI("1"), NAI("a@b"), IMSI(""), MSISDN("1"), nil, "plain"} {
		cases[fmt.Sprintf("supi %T%v", s, s)] = AMFIdentifierDeassociation{SUPI: s, GUTI: guti}
		cases[fmt.Sprintf("pei %T%v", s, s)] = AMFIdentifierDeassociation{SUPI: IMSI("1"), PEI: s, GUTI: guti}
		cases[fmt.Sprintf("gpsi %T%v", s, s)] = AMFIdentifierDeassociation{SUPI: IMSI("1"), GPSI: s, GUTI: guti}
	}
	for _, s := range []any{IMEI("1"), IMEISV("2"), IMEI("")} {
		cases["pei "+fmt.Sprintf("%T%v", s, s)] = AMFIdentifierDeassociation{SUPI: IMSI("1"), PEI: s, GUTI: guti}
	}
	cases["gpsi nai"] = AMFIdentifierDeassociation{SUPI: IMSI("1"), GPSI: NAI("x"), GUTI: guti}
	for i, c := range []any{FiveGMMCause(0), FiveGMMCause(300), FiveGSMCause(26), nil, CauseMisc(1)} {
		cases["amfcause"+string(rune('a'+i))] = AMFUnsuccessfulProcedure{FailedProcedureType: 1, FailureCause: c}
	}
	for i, c := range []any{CauseRadioNetwork(1), CauseTransport(2), CauseNas(0), CauseProtocol(4), CauseMisc(5), nil, FiveGMMCause(1)} {
		cases["hocause"+string(rune('a'+i))] = AMFRANHandoverRequest{
			UserIdentifiers: ids(SubscriberSUPI{Value: IMSI("1")}), AMFUENGAPID: 1, RANUENGAPID: 2, HandoverType: 1,
			HandoverCause: c, TargetToSourceContainer: []byte{1}, SourceToTargetContainer: []byte{2},
		}
	}
	for i, s := range []any{ServiceRequestIdentity{1}, ServiceAcceptIdentity{2}, ServiceAcceptIdentity(nil), nil, []byte{1}} {
		cases["smi"+string(rune('a'+i))] = AMFUEServiceAccept{ServiceMessageIdentity: s, ServiceType: []byte{}}
	}
	for i, u := range []UserIdentifiers{
		ids(SubscriberSUPI{Value: NAI("n")}, SubscriberPEI{Value: IMEI("1")}, SubscriberGPSI{Value: NAI("g")}),
		ids(SubscriberGPSI{Value: MSISDN("1")}, SubscriberSUPI{Value: IMSI("2")}),
		ids(SubscriberPEI{Value: IMEISV("1")}),
		ids(), ids(nil), ids(IMSI("1")), ids(SubscriberSUPI{}),
		{FiveGS: FiveGSSubscriberIDs{IDs: []any{}}},
	} {
		cases["uid"+string(rune('a'+i))] = AMFRANHandoverCommand{UserIdentifiers: u, TargetToSourceContainer: []byte{}}
	}
	for i, ep := range [][]any{
		UEEndpoint(net.ParseIP("10.0.0.1")), UEEndpoint(net.ParseIP("2001:db8::1")),
		{MACAddress{1, 2, 3, 4, 5, 6}}, {IPv4Address{1, 2, 3, 4}, IPv6Address(net.ParseIP("::1"))},
		{IPv4Address(nil)}, {nil}, {[]byte{1}}, {}, nil,
	} {
		cases["ep-est"+string(rune('a'+i))] = SMFPDUSessionEstablishment{PDUSessionID: 1, UEEndpoint: ep, DNN: "d", RequestType: 1}
		cases["ep-mod"+string(rune('a'+i))] = SMFPDUSessionModification{UEEndpoint: ep, RequestType: 1}
		cases["ep-soi"+string(rune('a'+i))] = SMFStartOfInterceptionWithEstablishedPDUSession{UEEndpoint: ep}
		cases["ep-unsucc"+string(rune('a'+i))] = SMFUnsuccessfulProcedure{UEEndpoint: ep}
	}
	for i, p := range []*SUPIUnauthenticatedIndication{nil, (*SUPIUnauthenticatedIndication)(&f), (*SUPIUnauthenticatedIndication)(&tr)} {
		cases["unauth"+string(rune('a'+i))] = SMFUnsuccessfulProcedure{SUPIUnauthenticated: p}
	}
	zero := RoutingIndicatorLength(0)
	st := SUPIType(7)
	cases["suci-ptr"] = AMFRegistration{SUPI: IMSI("1"), SUCI: SUCI{RoutingIndicatorLength: &zero, SUPIType: &st}}
	cases["suci-emptybytes"] = AMFRegistration{SUPI: IMSI("1"), SUCI: SUCI{HomeNetworkPublicKeyID: []byte{}}}
	cases["tai-empty"] = AMFRegistration{SUPI: IMSI("1"), FiveGSTAIList: TAIList{}}
	cases["tai-zero"] = AMFRegistration{SUPI: IMSI("1"), FiveGSTAIList: TAIList{{}}}
	cases["loc-false"] = AMFUnsuccessfulProcedure{FailureCause: FiveGMMCause(1), Location: Location{LocationInfo: LocationInfo{CurrentLocation: false}}}
	cases["negative"] = SMFPDUSessionRelease{SUPI: IMSI("1"), UplinkVolume: -1, DownlinkVolume: -129}
	cases["big"] = AMFRANHandoverCommand{AMFUENGAPID: 1099511627775, RANUENGAPID: 4294967295}
	cases["bigpolicy"] = AMFUEPolicyTransfer{SUPI: IMSI("1"), UEPolicy: make(UEPolicy, 70000)}
	cases["badutf8"] = AMFPositioningInfoTransfer{SUPI: NAI("\xff\xfe"), LCSCorrelationID: "\xc3"}
	cases["nil event"] = nil
	cases["pointer-free event"] = AMFRegistration{}
	cases["unregistered event"] = XIRIPayload{}

	for name, ev := range cases {
		crossCheck(t, name, ev)
	}
}
