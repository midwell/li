// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x1

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"net/http"
	"strconv"
	"text/template"
	"time"

	"github.com/omec-project/li/types"
)

// Requester is the requesting side of X1 — the role TS 103 221-1 calls the
// "ADMF". A Triggering Function uses it to task a triggered POI: TS 33.128
// clause 5.2.6 realises the LI_T3 triggering interface as TS 103 221-1 with "the
// CC-TF playing the role of the ADMF … and the triggered CC-POI playing the role
// of the NE", so triggering is an ordinary X1 exchange rather than a private
// protocol. Requests carry the requester's own identifier, which the NE
// authenticates against the certificate presented (clause 8.2.4) exactly as it
// would a real ADMF's — being the SMF is not authority in itself.
//
// It logs nothing: what is tasked, and that anything is tasked at all, must not
// reach general operator logs.
type Requester struct {
	neURL  string // the NE's X1 endpoint
	ourID  string // identifier this requester asserts (the TF's own)
	neID   string // the NE being addressed
	client *http.Client
	now    func() time.Time
}

// NewRequester returns a Requester that POSTs to a triggered POI's X1 endpoint
// over mutual TLS, asserting ourID and addressing neID.
func NewRequester(neURL, ourID, neID string, tlsConfig *tls.Config) *Requester {
	return &Requester{
		neURL: neURL,
		ourID: ourID,
		neID:  neID,
		client: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
			Timeout:   10 * time.Second,
		},
		now: func() time.Time { return time.Now().UTC() },
	}
}

// Trigger describes an LI_T3 task a Triggering Function installs at a triggered
// CC-POI (TS 33.128 table 6.2.3-6). Every field is mandatory there: without
// ProductID and CorrelationID the POI's product cannot be attributed to a warrant
// or joined to the signalling, and without the detection criteria it cannot
// isolate the session at all.
type Trigger struct {
	// XID identifies the trigger task itself and is allocated by the Triggering
	// Function. It is not the warrant's XID — that travels in ProductID.
	XID types.XID
	// ProductID is the warrant XID the POI must stamp on the PDUs it delivers.
	ProductID types.XID
	// CorrelationID is the value the POI must place in the correlation field of
	// those PDUs; it must equal the one the triggering POI used for the same
	// session's IRI.
	CorrelationID uint64
	// SEID and SEIDAddress are the packet detection criteria: the PFCP session
	// whose traffic is to be intercepted, and the address of the node that
	// allocated the SEID.
	SEID        uint64
	SEIDAddress string
	// DIDs reference destinations previously installed with CreateDestination.
	DIDs []string
}

// Destination is a delivery endpoint installed at an NE with CreateDestination
// (TS 103 221-1 clause 6.3.1). A trigger references it by DID rather than
// carrying an address, so a POI never needs a statically configured MDF.
type Destination struct {
	DID          string // UUIDv4
	FriendlyName string // optional
	DeliveryType string // X2Only | X3Only | X2andX3
	Address      string // IPv4 or IPv6 literal
	Port         uint16
}

// RequestError is an X1 error response. Callers can act on the code — e.g.
// TS 103 221-1 reserves 1030/1040 for an identity mismatch and 1080 for an
// unsupported request — rather than only logging text.
type RequestError struct {
	Code        int
	Description string
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("x1: request refused with code %d: %s", e.Code, e.Description)
}

// header is the set of fields common to every X1 request message.
type header struct {
	OurID, NeID, Timestamp, TxID, Type string
}

func (r *Requester) header(msgType string) header {
	return header{
		OurID:     r.ourID,
		NeID:      r.neID,
		Timestamp: x1Timestamp(r.now()),
		TxID:      newUUID(),
		Type:      msgType,
	}
}

// taskTemplate emits an ActivateTaskRequest or ModifyTaskRequest carrying LI_T3
// task details. Element order inside taskDetails follows the TS_103_221_01.xsd
// xs:sequence, which is normative: xId, targetIdentifiers, deliveryType,
// listOfDIDs, then correlationID and productID. The detection criteria ride in
// the 3GPP extension, whose elements are namespace-qualified because that schema
// sets elementFormDefault="qualified".
//
// deliveryType is fixed at X3Only: TS 33.128 table 6.2.3-6 requires it for this
// trigger, and a triggered CC-POI produces no IRI.
var taskTemplate = template.Must(template.New("x1task").Funcs(template.FuncMap{
	"esc": escapeXML,
}).Parse(`<?xml version="1.0" encoding="UTF-8"?>
<ns1:X1Request xmlns:ns1="http://uri.etsi.org/03221/X1/2017/10" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:ext="urn:3GPP:ns:li:3GPPX1Extensions:r18:v6">
  <ns1:x1RequestMessage xsi:type="ns1:{{.Header.Type}}">
    <ns1:admfIdentifier>{{esc .Header.OurID}}</ns1:admfIdentifier>
    <ns1:neIdentifier>{{esc .Header.NeID}}</ns1:neIdentifier>
    <ns1:messageTimestamp>{{esc .Header.Timestamp}}</ns1:messageTimestamp>
    <ns1:version>v1.6.1</ns1:version>
    <ns1:x1TransactionId>{{esc .Header.TxID}}</ns1:x1TransactionId>
    <ns1:taskDetails>
      <ns1:xId>{{esc .XID}}</ns1:xId>
      <ns1:targetIdentifiers>
        <ns1:targetIdentifier>
          <ns1:targetIdentifierExtension>
            <ns1:Owner>3GPP</ns1:Owner>
            <ext:UPFLIT3TargetIdentifierExtensions>
              <ext:UPFLIT3TargetIdentifier>
                <ext:FSEID>
                  <ext:SEID>{{.SEID}}</ext:SEID>
{{- if .SEIDAddress}}
                  <ext:IPv4Address>{{esc .SEIDAddress}}</ext:IPv4Address>
{{- end}}
                </ext:FSEID>
              </ext:UPFLIT3TargetIdentifier>
            </ext:UPFLIT3TargetIdentifierExtensions>
          </ns1:targetIdentifierExtension>
        </ns1:targetIdentifier>
      </ns1:targetIdentifiers>
      <ns1:deliveryType>X3Only</ns1:deliveryType>
      <ns1:listOfDIDs>
{{- range .DIDs}}
        <ns1:dId>{{esc .}}</ns1:dId>
{{- end}}
      </ns1:listOfDIDs>
      <ns1:correlationID>{{.CorrelationID}}</ns1:correlationID>
      <ns1:productID>{{esc .ProductID}}</ns1:productID>
    </ns1:taskDetails>
  </ns1:x1RequestMessage>
</ns1:X1Request>`))

// deactivateTemplate emits a DeactivateTaskRequest, which carries only the XID.
var deactivateTemplate = template.Must(template.New("x1deact").Funcs(template.FuncMap{
	"esc": escapeXML,
}).Parse(`<?xml version="1.0" encoding="UTF-8"?>
<ns1:X1Request xmlns:ns1="http://uri.etsi.org/03221/X1/2017/10" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <ns1:x1RequestMessage xsi:type="ns1:DeactivateTaskRequest">
    <ns1:admfIdentifier>{{esc .Header.OurID}}</ns1:admfIdentifier>
    <ns1:neIdentifier>{{esc .Header.NeID}}</ns1:neIdentifier>
    <ns1:messageTimestamp>{{esc .Header.Timestamp}}</ns1:messageTimestamp>
    <ns1:version>v1.6.1</ns1:version>
    <ns1:x1TransactionId>{{esc .Header.TxID}}</ns1:x1TransactionId>
    <ns1:xId>{{esc .XID}}</ns1:xId>
  </ns1:x1RequestMessage>
</ns1:X1Request>`))

// destinationTemplate emits a CreateDestinationRequest. destinationDetails
// follows its xs:sequence (dId, friendlyName?, deliveryType, deliveryAddress),
// and the address itself is a TS 103 280 IPAddressPort, whose namespace is
// likewise elementFormDefault="qualified".
var destinationTemplate = template.Must(template.New("x1dest").Funcs(template.FuncMap{
	"esc": escapeXML,
}).Parse(`<?xml version="1.0" encoding="UTF-8"?>
<ns1:X1Request xmlns:ns1="http://uri.etsi.org/03221/X1/2017/10" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:c="http://uri.etsi.org/03280/common/2017/07">
  <ns1:x1RequestMessage xsi:type="ns1:CreateDestinationRequest">
    <ns1:admfIdentifier>{{esc .Header.OurID}}</ns1:admfIdentifier>
    <ns1:neIdentifier>{{esc .Header.NeID}}</ns1:neIdentifier>
    <ns1:messageTimestamp>{{esc .Header.Timestamp}}</ns1:messageTimestamp>
    <ns1:version>v1.6.1</ns1:version>
    <ns1:x1TransactionId>{{esc .Header.TxID}}</ns1:x1TransactionId>
    <ns1:destinationDetails>
      <ns1:dId>{{esc .DID}}</ns1:dId>
{{- if .FriendlyName}}
      <ns1:friendlyName>{{esc .FriendlyName}}</ns1:friendlyName>
{{- end}}
      <ns1:deliveryType>{{esc .DeliveryType}}</ns1:deliveryType>
      <ns1:deliveryAddress>
        <ns1:ipAddressAndPort>
          <c:address>
            <c:{{.AddressElement}}>{{esc .Address}}</c:{{.AddressElement}}>
          </c:address>
          <c:port>{{.Port}}</c:port>
        </ns1:ipAddressAndPort>
      </ns1:deliveryAddress>
    </ns1:destinationDetails>
  </ns1:x1RequestMessage>
</ns1:X1Request>`))

// CreateDestination installs a delivery destination at the NE. It must succeed
// before a trigger referencing the DID is sent (TS 33.128 table 6.2.3-6:
// destinations "shall be configured … prior to first use").
func (r *Requester) CreateDestination(d Destination) error {
	if d.DID == "" || d.Address == "" || d.Port == 0 {
		return fmt.Errorf("x1: destination needs a DID, address and port")
	}
	if _, err := deliveryProducts(d.DeliveryType); err != nil {
		return fmt.Errorf("x1: destination: %w", err)
	}
	element := "IPv4Address"
	if isIPv6(d.Address) {
		element = "IPv6Address"
	}
	return r.send(destinationTemplate, struct {
		Header         header
		DID            string
		FriendlyName   string
		DeliveryType   string
		Address        string
		AddressElement string
		Port           uint16
	}{
		Header:         r.header("CreateDestinationRequest"),
		DID:            d.DID,
		FriendlyName:   d.FriendlyName,
		DeliveryType:   d.DeliveryType,
		Address:        d.Address,
		AddressElement: element,
		Port:           d.Port,
	})
}

// ActivateTask installs an LI_T3 trigger at the POI.
func (r *Requester) ActivateTask(t Trigger) error {
	return r.task("ActivateTaskRequest", t)
}

// ModifyTask updates an installed trigger — used when a session changes in a way
// that changes its detection criteria (TS 33.128 table 6.2.3-8).
func (r *Requester) ModifyTask(t Trigger) error {
	return r.task("ModifyTaskRequest", t)
}

func (r *Requester) task(msgType string, t Trigger) error {
	switch {
	case t.XID == "":
		return fmt.Errorf("x1: trigger needs an XID")
	case t.ProductID == "":
		// Without it the POI would label product with the trigger's XID, which
		// no MDF can attribute to the warrant.
		return fmt.Errorf("x1: trigger needs a ProductID (the warrant XID)")
	case t.CorrelationID == 0:
		// Zero is indistinguishable from "unset" and leaves the content
		// unjoinable to the session's IRI.
		return fmt.Errorf("x1: trigger needs a non-zero CorrelationID")
	case t.SEID == 0:
		return fmt.Errorf("x1: trigger needs a SEID to detect the session")
	case len(t.DIDs) == 0:
		return fmt.Errorf("x1: trigger needs at least one destination")
	}
	return r.send(taskTemplate, struct {
		Header        header
		XID           string
		ProductID     string
		CorrelationID string
		SEID          uint64
		SEIDAddress   string
		DIDs          []string
	}{
		Header:        r.header(msgType),
		XID:           string(t.XID),
		ProductID:     string(t.ProductID),
		CorrelationID: strconv.FormatUint(t.CorrelationID, 10),
		SEID:          t.SEID,
		SEIDAddress:   t.SEIDAddress,
		DIDs:          t.DIDs,
	})
}

// keepaliveTemplate emits a KeepaliveRequest. It carries only the common header:
// its purpose is to prove the requester is still there.
var keepaliveTemplate = template.Must(template.New("x1ka").Funcs(template.FuncMap{
	"esc": escapeXML,
}).Parse(`<?xml version="1.0" encoding="UTF-8"?>
<ns1:X1Request xmlns:ns1="http://uri.etsi.org/03221/X1/2017/10" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <ns1:x1RequestMessage xsi:type="ns1:KeepaliveRequest">
    <ns1:admfIdentifier>{{esc .Header.OurID}}</ns1:admfIdentifier>
    <ns1:neIdentifier>{{esc .Header.NeID}}</ns1:neIdentifier>
    <ns1:messageTimestamp>{{esc .Header.Timestamp}}</ns1:messageTimestamp>
    <ns1:version>v1.6.1</ns1:version>
    <ns1:x1TransactionId>{{esc .Header.TxID}}</ns1:x1TransactionId>
  </ns1:x1RequestMessage>
</ns1:X1Request>`))

// detailsTemplate emits a GetAllDetailsRequest, which carries only the header.
var detailsTemplate = template.Must(template.New("x1all").Funcs(template.FuncMap{
	"esc": escapeXML,
}).Parse(`<?xml version="1.0" encoding="UTF-8"?>
<ns1:X1Request xmlns:ns1="http://uri.etsi.org/03221/X1/2017/10" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <ns1:x1RequestMessage xsi:type="ns1:GetAllDetailsRequest">
    <ns1:admfIdentifier>{{esc .Header.OurID}}</ns1:admfIdentifier>
    <ns1:neIdentifier>{{esc .Header.NeID}}</ns1:neIdentifier>
    <ns1:messageTimestamp>{{esc .Header.Timestamp}}</ns1:messageTimestamp>
    <ns1:version>v1.6.1</ns1:version>
    <ns1:x1TransactionId>{{esc .Header.TxID}}</ns1:x1TransactionId>
  </ns1:x1RequestMessage>
</ns1:X1Request>`))

// TaskXIDs asks the NE what tasking it currently holds.
//
// A requester needs this after it has itself restarted: it comes back with no
// record of what it installed, while the NE still holds all of it, and tasking
// nobody can withdraw is exactly what must not exist. A liveness signal cannot
// substitute — a restarted requester is perfectly alive.
func (r *Requester) TaskXIDs() ([]types.XID, error) {
	var body bytes.Buffer
	if err := detailsTemplate.Execute(&body, struct{ Header header }{Header: r.header("GetAllDetailsRequest")}); err != nil {
		return nil, err
	}

	resp, err := r.postXML(&body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("x1: NE returned status %d", resp.StatusCode)
	}

	var out X1Response
	if err := xml.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("x1: malformed response: %w", err)
	}
	if len(out.Messages) == 0 {
		return nil, fmt.Errorf("x1: response carried no message")
	}

	m := out.Messages[0]
	if m.ErrorInformation != nil {
		return nil, &RequestError{Code: m.ErrorInformation.ErrorCode, Description: m.ErrorInformation.ErrorDescription}
	}

	reported := m.ReportedTasks()
	xids := make([]types.XID, 0, len(reported))
	for _, t := range reported {
		if t.TaskDetails.XID != "" {
			xids = append(xids, types.XID(t.TaskDetails.XID))
		}
	}

	return xids, nil
}

// Keepalive tells the NE this requester is still present.
//
// It is what makes the other side's fail-safe safe to enable: a POI that purges
// tasking when its requester goes quiet would otherwise purge whenever no new task
// happened to arrive, and a requester that never announces itself cannot be
// distinguished from one that has died. Tasking that outlives the party
// responsible for it is the failure this pair prevents.
func (r *Requester) Keepalive() error {
	return r.send(keepaliveTemplate, struct{ Header header }{Header: r.header("KeepaliveRequest")})
}

// DeactivateTask removes a trigger, ending interception at the POI. A Triggering
// Function sends it when the session ends (TS 33.128 clause 6.2.3.3.1) and when
// the warrant it derives from is withdrawn.
func (r *Requester) DeactivateTask(xid types.XID) error {
	if xid == "" {
		return fmt.Errorf("x1: deactivate needs an XID")
	}
	return r.send(deactivateTemplate, struct {
		Header header
		XID    string
	}{Header: r.header("DeactivateTaskRequest"), XID: string(xid)})
}

// send renders a request, POSTs it, and interprets the response. A response
// carrying errorInformation is returned as a *RequestError; anything the NE
// answers other than an acknowledgement is an error, so a caller cannot mistake
// a refusal for a successful tasking.
func (r *Requester) send(tmpl *template.Template, data any) error {
	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		return err
	}
	resp, err := r.postXML(&body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("x1: NE returned status %d", resp.StatusCode)
	}
	var out X1Response
	if err := xml.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("x1: malformed response: %w", err)
	}
	if len(out.Messages) == 0 {
		return fmt.Errorf("x1: response carried no message")
	}
	m := out.Messages[0]
	if m.ErrorInformation != nil {
		return &RequestError{Code: m.ErrorInformation.ErrorCode, Description: m.ErrorInformation.ErrorDescription}
	}
	if m.OK == "" {
		return fmt.Errorf("x1: response %q carried neither acknowledgement nor error", localType(m.Type))
	}
	return nil
}

// postXML sends an X1 request body to the NE and returns the response, which the
// caller must close. net/http's Post helper carries no context; these requests
// are bounded by the client's own timeout, but the linter is right that the shape
// should be explicit.
func (r *Requester) postXML(body *bytes.Buffer) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, r.neURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/xml")

	return r.client.Do(req)
}

// escapeXML escapes text for inclusion in an XML element body.
func escapeXML(s string) string {
	var b bytes.Buffer
	//nolint:errcheck // writing to a bytes.Buffer cannot fail
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// isIPv6 reports whether addr is an IPv6 literal, distinguishing the two
// TS 103 280 IPAddress arms without pulling in net parsing for a formatting
// decision. IPv4 literals contain no colon; IPv6 literals always do.
func isIPv6(addr string) bool {
	for i := 0; i < len(addr); i++ {
		if addr[i] == ':' {
			return true
		}
	}
	return false
}
