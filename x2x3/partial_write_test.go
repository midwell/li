// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x2x3

import (
	"bytes"
	"crypto/tls"
	"errors"
	"sync"
	"testing"
	"time"
)

// halfOpenMDF accepts one connection, reads a bounded number of bytes and then stops
// reading, so a write large enough to fill the socket buffer fails part-way. The
// second connection reads everything, which is what the retry lands on.
//
// It records what each connection received, because that is the only place the
// property can be asserted: what the destination got, not what the client attempted.
type halfOpenMDF struct {
	addr string

	mu       sync.Mutex
	streams  [][]byte
	accepted int
}

func newHalfOpenMDF(t *testing.T, cert tls.Certificate, stallAfter int) *halfOpenMDF {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() }) //nolint:errcheck // test cleanup

	m := &halfOpenMDF{addr: ln.Addr().String()}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			m.mu.Lock()
			m.accepted++
			first := m.accepted == 1
			m.streams = append(m.streams, nil)
			idx := len(m.streams) - 1
			m.mu.Unlock()

			go func() {
				defer conn.Close() //nolint:errcheck // test

				buf := make([]byte, 4096)
				read := 0
				for {
					if first && read >= stallAfter {
						// Stop reading and hold the connection open: the client's
						// write fills the socket buffer and trips its deadline.
						time.Sleep(30 * time.Second)

						return
					}
					if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
						return
					}
					n, err := conn.Read(buf)
					if n > 0 {
						read += n
						m.mu.Lock()
						m.streams[idx] = append(m.streams[idx], buf[:n]...)
						m.mu.Unlock()
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()

	return m
}

func (m *halfOpenMDF) received() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()

	var all []byte
	for _, s := range m.streams {
		all = append(all, s...)
	}

	return all
}

// TestARetryDoesNotRedeliverWhatThePeerAlreadyHas is the delivery-integrity property,
// asserted on what the destination received rather than on what the client attempted.
//
// PDUs are self-delimiting and concatenated, so a batch shares one write and a write can
// end in the middle of one. Retrying the whole buffer sends the leading complete PDUs a
// second time — and because the retry follows a reconnection, they arrive on a fresh
// stream where nothing marks them as repeats. Duplicate product under one warrant is
// exactly what deduplicating destinations by address exists to prevent, reached from the
// delivery mechanism instead of the destination list.
//
// Sequence numbers are assigned at framing, so a careful mediation function could
// recognise the duplicates. That is a property of the peer and not something this
// element may rely on.
func TestARetryDoesNotRedeliverWhatThePeerAlreadyHas(t *testing.T) {
	cert := selfSignedServer(t)

	// Big enough that three of them cannot share one socket buffer, so the first write
	// stalls part-way through the batch.
	payload := bytes.Repeat([]byte{0xAB}, 400*1024)
	pdus := []*PDU{
		{Type: PDUTypeX2, PayloadFormat: PayloadFormat3GPP33128, Payload: payload},
		{Type: PDUTypeX2, PayloadFormat: PayloadFormat3GPP33128, Payload: payload},
		{Type: PDUTypeX2, PayloadFormat: PayloadFormat3GPP33128, Payload: payload},
	}

	mdf := newHalfOpenMDF(t, cert, 64*1024)

	c := NewClient(mdf.addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // test peer
		KeepaliveConfig{Disabled: true})
	c.writeTimeout = 2 * time.Second
	t.Cleanup(func() { c.Close() }) //nolint:errcheck // test cleanup

	//nolint:errcheck // a partially-written unit is dropped and reported; that is the contract
	_ = c.SendBatch(pdus)

	// Let the retry's write land at the second connection.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mdf.mu.Lock()
		done := mdf.accepted >= 2
		mdf.mu.Unlock()
		if done {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond)

	got := mdf.received()

	// One marshalled PDU is the unit of duplication, so count how many whole copies of
	// one arrived. Three were offered; the destination must never see more than three,
	// and a retry that restarted the buffer sends four or five.
	one, err := pdus[0].Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(got, one); n > len(pdus) {
		t.Errorf("the destination received %d copies of a product unit for %d offered: "+
			"the retry resent what the peer already had", n, len(pdus))
	}
	if len(got) > len(one)*len(pdus) {
		t.Errorf("the destination received %d bytes for %d offered; the retry did not resume "+
			"at a product-unit boundary", len(got), len(one)*len(pdus))
	}
}

// TestADroppedUnitDoesNotReportTheDestinationUnreachable keeps the two conditions
// separate, which is the whole reason the delivery-lost reports exist alongside the
// reachability probe.
//
// A partial write that costs one product unit leaves a destination that took the rest of
// the batch: it is up, and it is being delivered to. Recording that as unreachability
// makes the destination watcher report a fault about a working mediation function — and
// then retract it on the next successful send — which is exactly the conflation
// AsyncSender.Unreachable's own documentation refuses for a full queue. The loss is a
// loss; the destination is fine.
func TestADroppedUnitDoesNotReportTheDestinationUnreachable(t *testing.T) {
	cert := selfSignedServer(t)

	payload := bytes.Repeat([]byte{0xCD}, 400*1024)
	pdus := []*PDU{
		{Type: PDUTypeX2, PayloadFormat: PayloadFormat3GPP33128, Payload: payload},
		{Type: PDUTypeX2, PayloadFormat: PayloadFormat3GPP33128, Payload: payload},
		{Type: PDUTypeX2, PayloadFormat: PayloadFormat3GPP33128, Payload: payload},
	}

	mdf := newHalfOpenMDF(t, cert, 64*1024)

	c := NewClient(mdf.addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // test peer
		KeepaliveConfig{Disabled: true})
	c.writeTimeout = 2 * time.Second
	t.Cleanup(func() { c.Close() }) //nolint:errcheck // test cleanup

	err := c.SendBatch(pdus)
	if err == nil {
		t.Skip("this peer took the whole batch, so no unit was dropped and there is nothing to assert")
	}
	if !errors.Is(err, ErrUnitDropped) {
		t.Skipf("the write failed for another reason (%v); this case needs a dropped unit", err)
	}

	if c.Unreachable() {
		t.Error("a destination that took the rest of the batch is reported unreachable: the watcher " +
			"will raise a fault about a working mediation function, and the loss that actually " +
			"happened is reported as the wrong condition")
	}
}
