// SPDX-FileCopyrightText: 2016 PromonLogicalis
// SPDX-License-Identifier: MIT

package asn1_test

import (
	"log"
	"reflect"

	"github.com/omec-project/li/asn1"
)

func Example() {
	ctx := asn1.NewContext()

	// Use BER for encoding and decoding.
	ctx.SetDer(false, false)

	// Add a CHOICE
	if err := ctx.AddChoice("value", []asn1.Choice{
		{
			Type:    reflect.TypeOf(""),
			Options: "tag:0",
		},
		{
			Type:    reflect.TypeOf(int(0)),
			Options: "tag:1",
		},
	}); err != nil {
		log.Fatal(err)
	}

	type Message struct {
		Id    int
		Value interface{} `asn1:"choice:value"`
	}

	// Encode
	msg := Message{
		Id:    1000,
		Value: "this is a value",
	}
	data, err := ctx.Encode(msg)
	if err != nil {
		log.Fatal(err)
	}

	// Decode
	decodedMsg := Message{}
	_, err = ctx.Decode(data, &decodedMsg)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("%+v\n", decodedMsg)
}
