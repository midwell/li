// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x2x3

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// selfSignedServer returns a self-signed server certificate for 127.0.0.1.
// (Mutual-auth behavior is covered by the mtls package; here we exercise the
// transport, so the client uses InsecureSkipVerify.)
func selfSignedServer(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mdf-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// readPDU reads one self-delimiting X2/X3 PDU from a stream, the way an MDF would.
func readPDU(conn net.Conn) (*PDU, error) {
	var lenHdr [12]byte // version(2)+type(2)+headerLen(4)+payloadLen(4)
	if _, err := io.ReadFull(conn, lenHdr[:]); err != nil {
		return nil, err
	}
	headerLen := binary.BigEndian.Uint32(lenHdr[4:8])
	payloadLen := binary.BigEndian.Uint32(lenHdr[8:12])
	rest := make([]byte, int(headerLen)+int(payloadLen)-len(lenHdr))
	if _, err := io.ReadFull(conn, rest); err != nil {
		return nil, err
	}
	p, _, err := Unmarshal(append(lenHdr[:], rest...))
	return p, err
}

func TestClientSendAndRedial(t *testing.T) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSignedServer(t)}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	received := make(chan *PDU, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for {
					p, err := readPDU(c)
					if err != nil {
						return
					}
					received <- p
				}
			}(conn)
		}
	}()

	client := NewClient(ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	defer client.Close()

	pdu := &PDU{Type: PDUTypeX2, PayloadFormat: PayloadFormat3GPP33128, Payload: []byte("xiri-payload")}

	recv := func(what string) *PDU {
		select {
		case p := <-received:
			return p
		case <-time.After(3 * time.Second):
			t.Fatalf("timeout waiting for %s", what)
			return nil
		}
	}

	// First send: lazy connect.
	if err := client.Send(pdu); err != nil {
		t.Fatalf("first Send: %v", err)
	}
	if got := recv("first PDU"); got.Type != PDUTypeX2 || !bytes.Equal(got.Payload, pdu.Payload) {
		t.Errorf("first PDU = %+v", got)
	}

	// Second send: reuses the open connection.
	if err := client.Send(pdu); err != nil {
		t.Fatalf("second Send: %v", err)
	}
	recv("second PDU (connection reuse)")

	// Close then send again: the client must redial.
	client.Close()
	if err := client.Send(pdu); err != nil {
		t.Fatalf("Send after Close (redial): %v", err)
	}
	recv("third PDU (redial)")
}

func TestSendMarshalError(t *testing.T) {
	// GTP-U is not allowed on an X2 PDU — Marshal fails, Send surfaces it before dialing.
	c := NewClient("127.0.0.1:1", &tls.Config{})
	if err := c.Send(&PDU{Type: PDUTypeX2, PayloadFormat: PayloadFormatGTPU}); err == nil {
		t.Error("Send accepted an invalid PDU")
	}
}

// TestSendBatchReportsMarshalFailure: a PDU that cannot be framed is intercept
// product lost. The batch around it is still delivered, but the loss must be
// returned rather than swallowed — an AsyncSender turns that error into the ADMF
// fault report that is this plane's only way of saying anything (design D11).
func TestSendBatchReportsMarshalFailure(t *testing.T) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSignedServer(t)}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	received := make(chan *PDU, 4)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			p, err := readPDU(conn)
			if err != nil {
				return
			}
			received <- p
		}
	}()

	client := NewClient(ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	defer client.Close()

	good := &PDU{Type: PDUTypeX3, PayloadFormat: PayloadFormatIPv4, Payload: []byte{0x45, 0x00}}
	// SIP is an X2-only payload format, so this one cannot be framed as X3.
	bad := &PDU{Type: PDUTypeX3, PayloadFormat: PayloadFormatSIP, Payload: []byte("INVITE")}

	if err := client.SendBatch([]*PDU{good, bad, good}); err == nil {
		t.Fatal("SendBatch discarded an unframeable PDU without reporting it")
	}

	// The rest of the batch must still have been delivered.
	for i := range 2 {
		select {
		case <-received:
		case <-time.After(3 * time.Second):
			t.Fatalf("timeout waiting for framable PDU %d of 2", i+1)
		}
	}
}
