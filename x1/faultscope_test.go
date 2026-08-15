// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x1

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
)

// collectingADMF records every report an element sends it.
type collectingADMF struct {
	srv *httptest.Server

	mu     sync.Mutex
	bodies []string
}

func newCollectingADMF(t *testing.T) *collectingADMF {
	t.Helper()

	a := &collectingADMF{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test handler
		a.mu.Lock()
		a.bodies = append(a.bodies, string(body))
		a.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(a.srv.Close)

	return a
}

func (a *collectingADMF) reports() []string {
	a.mu.Lock()
	defer a.mu.Unlock()

	return append([]string(nil), a.bodies...)
}

// counting returns how many recorded reports contain each of the given substrings.
func (a *collectingADMF) counting(substrings ...string) map[string]int {
	out := make(map[string]int, len(substrings))
	for _, body := range a.reports() {
		for _, s := range substrings {
			if strings.Contains(body, s) {
				out[s]++
			}
		}
	}

	return out
}

// reachability is a delivery destination whose reachability a test controls. It is
// the shape both Pool.UnreachableAmong and the UPF's own unreachableDestinations
// answer from — a sender that knows whether it can currently reach its endpoint —
// so a watcher built against the count function works against either.
type reachability struct {
	mu          sync.Mutex
	unreachable map[string]bool
	inUse       []string
}

func newReachability(inUse ...string) *reachability {
	return &reachability{unreachable: make(map[string]bool), inUse: inUse}
}

func (r *reachability) set(addr string, down bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.unreachable[addr] = down
}

// count is the shape MDFUnreachableProbe already takes, and the shape the watcher
// takes for the same reason: it says how many, and cannot say which.
func (r *reachability) count() (unreachable, inUse int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, addr := range r.inUse {
		inUse++
		if r.unreachable[addr] {
			unreachable++
		}
	}

	return unreachable, inUse
}

// TestTheFaultChannelSaysNothingWhenAFaultEnds is the before-evidence for this
// change, and it is here rather than in a lab notebook because the claim it
// records — "an ADMF told a fault began is never told it ended" — is the whole
// premise. Inferring it from the absence of a grep hit is not the same as watching
// the channel stay silent.
//
// It also records the other half: what does reach the ADMF names no destination,
// so an element with several provisioned destinations reports that one of them is
// unreachable and cannot say which.
func TestTheFaultChannelSaysNothingWhenAFaultEnds(t *testing.T) {
	admf := newCollectingADMF(t)
	r := NewReporter(admf.srv.URL, "admfID", "neID", nil)

	// A destination fails, which is what the delivery sites notice today.
	if err := r.ReportNEIssue(NEIssueMDFUnreachable, "MDF3 X3 delivery failed"); err != nil {
		t.Fatalf("ReportNEIssue: %v", err)
	}
	// ... and recovers. There is no call for this, which is the finding.
	// Nothing in the module emits FaultCleared.

	got := admf.counting("mdfUnreachable", neIssueFaultCleared, "10.0.2.5")

	if got["mdfUnreachable"] != 1 {
		t.Fatalf("the failure itself was reported %d times, want 1", got["mdfUnreachable"])
	}
	if got[neIssueFaultCleared] != 0 {
		t.Errorf("something already emits %s; this change's premise needs re-checking", neIssueFaultCleared)
	}
	// The report is network-element scoped: it names the condition and not the
	// destination, so an ADMF holding several cannot act on it.
	for _, body := range admf.reports() {
		if strings.Contains(body, "ReportDestinationIssueRequest") {
			t.Error("a destination-scoped report already exists; this change's premise needs re-checking")
		}
	}
}

// TestTheThrottleCannotDistinguishTwoDestinations pins the second half of why the
// existing record cannot serve. It is keyed by issue type alone, so two
// destinations failing inside one window are one report — and which one survives
// is whichever failed first.
//
// This is not a defect in the throttle: one issue type was the right key while
// every report was network-element scoped. It becomes wrong the moment a report
// names a destination, which is what makes re-keying part of this change rather
// than a tidy-up.
func TestTheThrottleCannotDistinguishTwoDestinations(t *testing.T) {
	admf := newCollectingADMF(t)
	r := NewReporter(admf.srv.URL, "admfID", "neID", nil)

	for range 2 {
		if err := r.ReportNEIssue(NEIssueMDFUnreachable, "MDF3 X3 delivery failed"); err != nil {
			t.Fatalf("ReportNEIssue: %v", err)
		}
	}

	if n := admf.counting("mdfUnreachable")["mdfUnreachable"]; n != 1 {
		t.Errorf("two reports of one issue type produced %d messages, want 1 — the throttle keys on type alone", n)
	}
}

// TestReachabilityIsReObservableAndDoesNoIO is task 1.1, and it is the assertion
// the whole change rests on: a fault that cannot be re-observed cannot be observed
// to end, so there would be no clearing edge to report.
//
// Both suppliers answer the same shape — Pool.UnreachableAmong for the SMF and
// AMF, liShipper.unreachableDestinations for the UPF — from state each sender
// already holds, through x2x3.Reachability. That is what lets the watcher live
// here, parameterised by the count function, rather than being written per network
// function.
func TestReachabilityIsReObservableAndDoesNoIO(t *testing.T) {
	dests := newReachability("10.0.2.5:9000", "10.0.2.6:9000")

	if unreachable, inUse := dests.count(); unreachable != 0 || inUse != 2 {
		t.Fatalf("count() = (%d, %d), want (0, 2)", unreachable, inUse)
	}

	dests.set("10.0.2.5:9000", true)
	if unreachable, _ := dests.count(); unreachable != 1 {
		t.Errorf("a destination that went down is not observable: unreachable = %d, want 1", unreachable)
	}

	// The same question asked again gives the answer that holds now, which is what
	// makes an ending detectable at all.
	dests.set("10.0.2.5:9000", false)
	if unreachable, _ := dests.count(); unreachable != 0 {
		t.Errorf("a destination that recovered is not observable: unreachable = %d, want 0", unreachable)
	}

	// Cheap enough to sample on a timer. A supplier that grew a network call would
	// put delivery latency on a schedule inside the LI plane, which is the reason
	// MDFUnreachableProbe documents its own supplier as I/O-free.
	start := time.Now()
	for range 10000 {
		dests.count()
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("10000 samples took %v; the supplier is doing more than reading state it holds", elapsed)
	}
}

// TestCarryingTheIdentifierDidNotChangeDelivery is the assertion that matters most
// in this change, and it is about something the change did *not* do.
//
// Endpoints are deduplicated by address: two destination identifiers naming one
// address deliver one copy. Putting an identifier on the endpoint makes two
// entries distinguishable that must stay indistinguishable for delivery, and a
// second copy of a subject's traffic is exactly the failure that deduplication
// exists to prevent. So the identifier is carried for reporting and delivery keeps
// keying on address.
func TestCarryingTheIdentifierDidNotChangeDelivery(t *testing.T) {
	// One endpoint, provisioned twice under two identifiers — which is what an ADMF
	// does when two warrants go to one agency.
	task := types.InterceptTask{
		XID: "11111111-1111-4111-8111-111111111111",
		Deliveries: []types.DeliveryEndpoint{
			{Type: types.DeliveryX3, Address: "10.0.2.5:9000", DID: "33333333-3333-4333-8333-333333333333"},
			{Type: types.DeliveryX3, Address: "10.0.2.5:9000", DID: "44444444-4444-4444-8444-444444444444"},
		},
	}

	if addrs := task.DeliveryAddresses(types.DeliveryX3); len(addrs) != 1 {
		t.Errorf("one endpoint under two identifiers yields %d delivery addresses, want 1 — a subject's traffic would be copied twice", len(addrs))
	}

	// And both identifiers are still reachable, because a fault about that endpoint
	// concerns both destinations the provisioning function created.
	dids := task.DeliveryDIDs(types.DeliveryX3, "10.0.2.5:9000")
	if len(dids) != 2 {
		t.Fatalf("the endpoint resolves to %d destination identifiers, want 2", len(dids))
	}
}

// TestAProvisionedDestinationCarriesItsIdentifier: the identifier survives the
// boundary between provisioning and delivery, which is where it used to be dropped.
func TestAProvisionedDestinationCarriesItsIdentifier(t *testing.T) {
	srv := NewServer(store.New(), "neID", WithADMF("admfID"))

	mustAck(t, srv, createDestinationXML(didAgencyA, deliveryX2andX3, "10.0.60.122", tcpPort("42069"), ""))
	mustAck(t, srv, activateXMLWith(string(testXID), deliveryX2andX3, dIDs(didAgencyA), ""))

	task, ok := srv.store.Get(testXID)
	if !ok {
		t.Fatal("the task was not stored")
	}
	if len(task.Deliveries) != 2 {
		t.Fatalf("an X2andX3 destination expanded to %d endpoints, want 2", len(task.Deliveries))
	}
	for _, d := range task.Deliveries {
		if d.DID != didAgencyA {
			t.Errorf("%s endpoint carries DID %q, want %q — the identifier is dropped at the boundary between provisioning and delivery",
				d.Type, d.DID, didAgencyA)
		}
	}

	// One address serving both interfaces is still one address per interface, so
	// nothing is delivered twice.
	if addrs := task.DeliveryAddresses(types.DeliveryX3); len(addrs) != 1 {
		t.Errorf("X3 resolves to %d addresses, want 1", len(addrs))
	}
}

// TestAFaultIsReportedAtDestinationScopeAndThenCleared is the change, end to end at
// the reporter: a destination fails and the ADMF is told which one; it recovers and
// the ADMF is told that too.
func TestAFaultIsReportedAtDestinationScopeAndThenCleared(t *testing.T) {
	admf := newCollectingADMF(t)
	r := NewReporter(admf.srv.URL, "admfID", "neID", nil)

	dests := newReachability(endpointA)
	health := func() []DestinationHealth {
		unreachable, _ := dests.count()

		return []DestinationHealth{{DID: didAgencyA, Address: endpointA, Unreachable: unreachable > 0}}
	}
	w := NewDestinationWatcher(health, r, time.Millisecond)

	// Healthy: nothing to say, and in particular no recovery from a fault nobody was
	// told about.
	w.sample()
	if n := len(admf.reports()); n != 0 {
		t.Fatalf("a healthy element sent %d reports, want 0", n)
	}

	dests.set(endpointA, true)
	w.sample()

	reports := admf.reports()
	if len(reports) != 1 {
		t.Fatalf("an unreachable destination produced %d reports, want 1", len(reports))
	}
	for _, want := range []string{
		`xsi:type="ns1:ReportDestinationIssueRequest"`,
		"<ns1:dId>" + didAgencyA + "</ns1:dId>",
		"<ns1:destinationReportType>" + TaskReportNonTerminatingFault + "</ns1:destinationReportType>",
	} {
		if !strings.Contains(reports[0], want) {
			t.Errorf("the fault report is missing %q\n%s", want, reports[0])
		}
	}

	dests.set(endpointA, false)
	w.sample()

	reports = admf.reports()
	if len(reports) != 2 {
		t.Fatalf("recovery produced %d reports in all, want 2 — clause 5.3 requires a fault that clears to be reported as cleared", len(reports))
	}
	if !strings.Contains(reports[1], "<ns1:destinationReportType>"+TaskReportAllClear+"</ns1:destinationReportType>") {
		t.Errorf("the clearing report does not carry AllClear\n%s", reports[1])
	}
	if !strings.Contains(reports[1], "<ns1:dId>"+didAgencyA+"</ns1:dId>") {
		t.Errorf("the clearing report does not name the destination it clears\n%s", reports[1])
	}
}

// TestRecoveryIsNotThrottledAgainstTheFailure. A fault beginning and that same
// fault clearing are two events, not a repetition. An element that throttled the
// second against the first would report a fault it never retracts — worse than
// reporting neither, because the ADMF acts on the first.
func TestRecoveryIsNotThrottledAgainstTheFailure(t *testing.T) {
	admf := newCollectingADMF(t)
	r := NewReporter(admf.srv.URL, "admfID", "neID", nil)

	dests := newReachability(endpointA)
	health := func() []DestinationHealth {
		unreachable, _ := dests.count()

		return []DestinationHealth{{DID: didAgencyA, Address: endpointA, Unreachable: unreachable > 0}}
	}
	w := NewDestinationWatcher(health, r, time.Millisecond)

	// Fails and recovers well inside one throttle window.
	dests.set(endpointA, true)
	w.sample()
	dests.set(endpointA, false)
	w.sample()

	if got := admf.counting(TaskReportAllClear)[TaskReportAllClear]; got != 1 {
		t.Errorf("the clearing was reported %d times, want 1 — the throttle suppressed a state change", got)
	}

	// And the same fault recurring immediately is reported again rather than
	// suppressed as a repeat of the one just retracted.
	dests.set(endpointA, true)
	w.sample()
	if got := admf.counting(TaskReportNonTerminatingFault)[TaskReportNonTerminatingFault]; got != 2 {
		t.Errorf("a fault that recurred after being cleared was reported %d times, want 2", got)
	}
}

// TestAPersistingFaultIsReportedOncePerWindow: the throttle still does its job for
// a condition that simply continues, which is what it was for.
func TestAPersistingFaultIsReportedOncePerWindow(t *testing.T) {
	admf := newCollectingADMF(t)
	r := NewReporter(admf.srv.URL, "admfID", "neID", nil)

	health := func() []DestinationHealth {
		return []DestinationHealth{{DID: didAgencyA, Address: endpointA, Unreachable: true}}
	}
	w := NewDestinationWatcher(health, r, time.Millisecond)

	for range 20 {
		w.sample()
	}

	if n := len(admf.reports()); n != 1 {
		t.Errorf("twenty samples of one persisting fault produced %d reports, want 1", n)
	}
}

// TestTwoDestinationsAreReportedSeparately is what the re-keyed throttle buys, and
// what the before-evidence showed was impossible: two destinations failing inside
// one window used to be one report.
func TestTwoDestinationsAreReportedSeparately(t *testing.T) {
	admf := newCollectingADMF(t)
	r := NewReporter(admf.srv.URL, "admfID", "neID", nil)

	health := func() []DestinationHealth {
		return []DestinationHealth{
			{DID: didAgencyA, Address: endpointA, Unreachable: true},
			{DID: didAgencyB, Address: "10.0.60.123:42069", Unreachable: true},
		}
	}
	NewDestinationWatcher(health, r, time.Millisecond).sample()

	got := admf.counting(didAgencyA, didAgencyB)
	if got[didAgencyA] != 1 || got[didAgencyB] != 1 {
		t.Errorf("two destinations failing produced %d and %d reports, want one each", got[didAgencyA], got[didAgencyB])
	}
}

// TestOneEndpointUnderTwoIdentifiersReportsBoth. The provisioning function's unit
// of action is the destination it created; reporting per endpoint would require it
// to know how this element resolves them.
func TestOneEndpointUnderTwoIdentifiersReportsBoth(t *testing.T) {
	admf := newCollectingADMF(t)
	r := NewReporter(admf.srv.URL, "admfID", "neID", nil)

	task := types.InterceptTask{
		XID: testXID,
		Deliveries: []types.DeliveryEndpoint{
			{Type: types.DeliveryX3, Address: endpointA, DID: didAgencyA},
			{Type: types.DeliveryX3, Address: endpointA, DID: didAgencyB},
		},
	}
	health := func() []DestinationHealth {
		return DestinationHealthOf([]types.InterceptTask{task}, types.DeliveryX3,
			func(string) bool { return true })
	}
	NewDestinationWatcher(health, r, time.Millisecond).sample()

	got := admf.counting(didAgencyA, didAgencyB)
	if got[didAgencyA] != 1 || got[didAgencyB] != 1 {
		t.Errorf("one unreachable endpoint under two identifiers produced %d and %d reports, want one each",
			got[didAgencyA], got[didAgencyB])
	}
}

// TestAConfiguredEndpointIsNotReportedAtDestinationScope: an endpoint this element
// resolved from its own configuration has no identifier the ADMF assigned, so
// there is nothing destination-scoped to say about it.
func TestAConfiguredEndpointIsNotReportedAtDestinationScope(t *testing.T) {
	admf := newCollectingADMF(t)
	r := NewReporter(admf.srv.URL, "admfID", "neID", nil)

	health := func() []DestinationHealth {
		return []DestinationHealth{{Address: endpointA, Unreachable: true}}
	}
	NewDestinationWatcher(health, r, time.Millisecond).sample()

	if n := admf.counting("ReportDestinationIssueRequest")["ReportDestinationIssueRequest"]; n != 0 {
		t.Errorf("an endpoint with no provisioned identifier produced %d destination-scoped reports, want 0", n)
	}
	// It is reported, at the scope that can be named — see
	// TestAnEndpointWithNoIdentifierIsStillReported, which is the regression the
	// end-to-end suite caught when this asserted no report at all.
	if n := len(admf.reports()); n != 1 {
		t.Errorf("it produced %d reports in all, want 1 at element scope", n)
	}
}

// TestADestinationNamedByTwoTasksIsOneDestination. Reporting it once per task would
// tell the provisioning function about its own tasking rather than about its
// endpoint.
func TestADestinationNamedByTwoTasksIsOneDestination(t *testing.T) {
	shared := types.DeliveryEndpoint{Type: types.DeliveryX3, Address: endpointA, DID: didAgencyA}
	got := DestinationHealthOf([]types.InterceptTask{
		{XID: "11111111-1111-4111-8111-111111111111", Deliveries: []types.DeliveryEndpoint{shared}},
		{XID: "22222222-2222-4222-8222-222222222222", Deliveries: []types.DeliveryEndpoint{shared}},
	}, types.DeliveryX3, func(string) bool { return true })

	if len(got) != 1 {
		t.Errorf("one destination named by two tasks yielded %d entries, want 1: %+v", len(got), got)
	}
}

// TestTheWatcherStopsWithTheElementItBelongsTo. A background goroutine that
// outlives its element is the shape of a process that leaks one per restart.
func TestTheWatcherStopsWithTheElementItBelongsTo(t *testing.T) {
	// Buffered and signalled by a send rather than a close: this package declares its
	// own close() for XML rendering, which shadows the builtin.
	stop := make(chan struct{}, 1)
	done := make(chan struct{}, 1)

	w := NewDestinationWatcher(func() []DestinationHealth { return nil }, nil, time.Millisecond)
	go func() {
		defer func() { done <- struct{}{} }()
		w.Watch(stop)
	}()

	stop <- struct{}{}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watcher did not stop when its element did")
	}
}

// TestTheStatusAnswerStillNamesNoDestination is task 6.1, and it guards against the
// obvious next step rather than against a defect.
//
// The element can now name a destination in a report, so "the probe should name it
// too" reads as consistency. It is not: an element's own status says how much is
// wrong and never whose product is affected, and the probe takes counts precisely
// so that answering otherwise is impossible rather than merely discouraged. A
// destination-scoped report and a status answer address the same fact to different
// questions.
func TestTheStatusAnswerStillNamesNoDestination(t *testing.T) {
	probe := MDFUnreachableProbe(func() (int, int) { return 1, 2 })

	fault := probe()
	if fault == nil {
		t.Fatal("an unreachable destination is not reported in the status answer at all")
	}
	for _, secret := range []string{didAgencyA, didAgencyB, endpointA} {
		if strings.Contains(fault.ErrorDescription, secret) {
			t.Errorf("the status answer names %q: %s", secret, fault.ErrorDescription)
		}
	}
	if !strings.Contains(fault.ErrorDescription, "1 of 2") {
		t.Errorf("the status answer no longer says how many: %s", fault.ErrorDescription)
	}
}

// TestAnEndpointWithNoIdentifierIsStillReported is the regression the end-to-end
// suite caught and the unit tests did not, which is why it is here now.
//
// The first version of the watcher skipped an endpoint with no provisioned
// identifier, reasoning that there is nothing destination-scoped to say about one
// the ADMF did not create. True, and it does not follow that the element should say
// *nothing*: a delivery it cannot make is exactly what the network-element-level
// condition has always been for, and every task delivering to this element's
// configured default endpoint has no DID. Retiring the sites that used to push that
// report therefore lost it outright for the commonest configuration there is.
//
// The scope changes with what can be named. Whether the fault is reported at all
// does not.
func TestAnEndpointWithNoIdentifierIsStillReported(t *testing.T) {
	admf := newCollectingADMF(t)
	r := NewReporter(admf.srv.URL, "admfID", "neID", nil)

	dests := newReachability(endpointA)
	health := func() []DestinationHealth {
		unreachable, _ := dests.count()

		// No DID: the endpoint came from configuration, as a task naming no
		// destination is delivered to.
		return []DestinationHealth{{Address: endpointA, Unreachable: unreachable > 0}}
	}
	w := NewDestinationWatcher(health, r, time.Millisecond)

	dests.set(endpointA, true)
	w.sample()

	reports := admf.reports()
	if len(reports) != 1 {
		t.Fatalf("an unreachable configured endpoint produced %d reports, want 1 — the fault is reported by nobody", len(reports))
	}
	for _, want := range []string{
		`xsi:type="ns1:ReportNEIssueRequest"`,
		"<ns1:typeOfNeIssueMessage>" + neIssueFaultReport + "</ns1:typeOfNeIssueMessage>",
		NEIssueMDFUnreachable,
	} {
		if !strings.Contains(reports[0], want) {
			t.Errorf("the element-level report is missing %q\n%s", want, reports[0])
		}
	}
	// And it names no destination, because there is none to name.
	if strings.Contains(reports[0], "dId") {
		t.Errorf("an endpoint with no provisioned identifier was reported with one\n%s", reports[0])
	}

	// The ending too, at the same scope.
	dests.set(endpointA, false)
	w.sample()

	reports = admf.reports()
	if len(reports) != 2 {
		t.Fatalf("recovery produced %d reports in all, want 2", len(reports))
	}
	if !strings.Contains(reports[1], "<ns1:typeOfNeIssueMessage>"+neIssueFaultCleared+"</ns1:typeOfNeIssueMessage>") {
		t.Errorf("the clearing report is not a FaultCleared\n%s", reports[1])
	}
}
