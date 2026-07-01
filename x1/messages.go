// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

// Package x1 implements the network-element (POI) side of the ETSI TS 103 221-1
// X1 interface: it receives task-provisioning requests from an ADMF/LIPF over
// HTTP (XML bodies) and applies them to the interception-task store. The NF is
// the X1 server; the ADMF is the client. Transport security (mutual TLS, X0
// credential pre-provisioning) is layered on separately.
package x1

import "encoding/xml"

// Namespace is the ETSI TS 103 221-1 X1 XML namespace. The message-type
// discriminator rides on the xsi:type attribute (XML-Schema-instance namespace).
const Namespace = "http://uri.etsi.org/03221/X1/2017/10"

// X1Request is the top-level X1 request envelope. It may carry one or more
// messages (TS 103 221-1 allows a batch); the common case is a single message.
type X1Request struct {
	XMLName  xml.Name           `xml:"http://uri.etsi.org/03221/X1/2017/10 X1Request"`
	Messages []X1RequestMessage `xml:"x1RequestMessage"`
}

// X1RequestMessage is one request. The xsi:type attribute selects the action
// (ActivateTaskRequest, ModifyTaskRequest, DeactivateTaskRequest, …); the
// action-specific payload is carried in TaskDetails (activate/modify) or XID
// (deactivate). The header fields are common to every message type.
type X1RequestMessage struct {
	Type             string       `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
	AdmfIdentifier   string       `xml:"admfIdentifier"`
	NeIdentifier     string       `xml:"neIdentifier"`
	MessageTimestamp string       `xml:"messageTimestamp"`
	Version          string       `xml:"version"`
	X1TransactionID  string       `xml:"x1TransactionId"`
	TaskDetails      *TaskDetails `xml:"taskDetails,omitempty"` // ActivateTask / ModifyTask
	XID              string       `xml:"xId,omitempty"`         // DeactivateTask
}

// TaskDetails describes the interception task being (de)provisioned.
type TaskDetails struct {
	XID               string             `xml:"xId"`
	TargetIdentifiers []TargetIdentifier `xml:"targetIdentifiers>targetIdentifier"`
	DeliveryType      string             `xml:"deliveryType"` // X2Only | X3Only | X2andX3
	ListOfDIDs        []string           `xml:"listOfDIDs>dId"`
}

// TargetIdentifier is a CHOICE of target-identifier kinds. Only the subset the
// 5G POIs match on is modeled; the rest of the TS 103 221-1 set is unmodeled
// (an unknown identifier yields an empty match and is rejected).
type TargetIdentifier struct {
	IMSI       string `xml:"imsi,omitempty"`
	SUPIIMSI   string `xml:"supiimsi,omitempty"`
	SUPINAI    string `xml:"supinai,omitempty"`
	PEIIMEI    string `xml:"peiImei,omitempty"`
	PEIIMEISV  string `xml:"peiImeisv,omitempty"`
	GPSIMSISDN string `xml:"gpsiMsisdn,omitempty"`
	E164Number string `xml:"e164Number,omitempty"`
}

// X1Response is the top-level X1 response envelope.
type X1Response struct {
	XMLName  xml.Name            `xml:"http://uri.etsi.org/03221/X1/2017/10 X1Response"`
	Messages []X1ResponseMessage `xml:"x1ResponseMessage"`
}

// X1ResponseMessage acknowledges one request message.
type X1ResponseMessage struct {
	Type             string   `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
	AdmfIdentifier   string   `xml:"admfIdentifier"`
	NeIdentifier     string   `xml:"neIdentifier"`
	MessageTimestamp string   `xml:"messageTimestamp"`
	Version          string   `xml:"version"`
	X1TransactionID  string   `xml:"x1TransactionId"`
	OK               string   `xml:"oK,omitempty"`
	ErrorInformation *X1Error `xml:"errorInformation,omitempty"`
}

// X1Error carries an error response (subset).
type X1Error struct {
	ErrorCode        int    `xml:"errorCode"`
	ErrorDescription string `xml:"errorDescription"`
}
