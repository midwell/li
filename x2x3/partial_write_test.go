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

// newHalfOpenMDF is a mediation function that accepts a connection and then stops reading
// after stallAfter bytes, so a delivery lands in part and no further.
//
// stallEvery makes every connection stall rather than only the first, so the retry the
// client makes on a fresh connection fails too. It is what distinguishes a unit that is
// recovered from one that is lost.
func newHalfOpenMDF(t *testing.T, cert tls.Certificate, stallAfter int, stallEvery ...bool) *halfOpenMDF {
	t.Helper()

	always := len(stallEvery) > 0 && stallEvery[0]

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
			first := always || m.accepted == 1
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

// pausingMDF reads a bounded number of bytes, stops reading for long enough that the
// client's write deadline trips, and then reads everything that follows — on that
// connection and on the one the client dials to retry.
//
// **Resuming the read is what makes the property observable.** A peer that stalls forever
// leaves the bytes the kernel accepted unread, so nothing can distinguish a unit that was
// sent and never read from one that was never sent — which is the difference under test.
// Once it drains, every byte this element wrote is counted, on both streams.
type pausingMDF struct {
	addr string

	mu      sync.Mutex
	streams [][]byte
}

func newPausingMDF(t *testing.T, cert tls.Certificate, readBeforePause int, pause time.Duration) *pausingMDF {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() }) //nolint:errcheck // test cleanup

	m := &pausingMDF{addr: ln.Addr().String()}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			m.mu.Lock()
			first := len(m.streams) == 0
			m.streams = append(m.streams, nil)
			idx := len(m.streams) - 1
			m.mu.Unlock()

			go func() {
				defer conn.Close() //nolint:errcheck // test

				buf := make([]byte, 32*1024)
				read := 0
				paused := false
				for {
					if first && !paused && read >= readBeforePause {
						paused = true
						time.Sleep(pause)
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

func (m *pausingMDF) all() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []byte
	for _, s := range m.streams {
		out = append(out, s...)
	}

	return out
}

// TestAPartiallyWrittenUnitIsResentWhole is what a partial write costs once the retry goes
// out on a fresh connection: nothing.
//
// The unit used to be skipped, on the reasoning that a receiver reading the head of a
// stream would take the tail of a unit as the start of one. That is true of resuming
// mid-unit on the same stream and false of the connection the retry actually uses: a TCP
// connection is its own stream, and this one begins at a frame boundary, so a whole unit
// sent on it cannot be read as anybody's tail. Nor can it duplicate — a unit the kernel did
// not accept in full is one the peer cannot have received in full, because a write reports
// what it took and never more.
//
// The two properties together are the whole claim, and each unit carries its own fill byte
// so both are countable: every unit offered reaches the destination, and none reaches it
// twice.
func TestAPartiallyWrittenUnitIsResentWhole(t *testing.T) {
	cert := selfSignedServer(t)

	pdus := make([]*PDU, 0, 4)
	for i := range 4 {
		pdus = append(pdus, &PDU{
			Type:          PDUTypeX2,
			PayloadFormat: PayloadFormat3GPP33128,
			Payload:       bytes.Repeat([]byte{byte(0xA0 + i)}, 512*1024),
		})
	}

	// The peer reads a little, pauses past the write deadline, and then drains.
	mdf := newPausingMDF(t, cert, 32*1024, 3*time.Second)

	c := NewClient(mdf.addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // test peer
		KeepaliveConfig{Disabled: true})
	c.writeTimeout = time.Second
	t.Cleanup(func() { c.Close() }) //nolint:errcheck // test cleanup

	if err := c.SendBatch(pdus); err != nil {
		t.Fatalf("SendBatch after a recoverable partial write returned %v, want nil", err)
	}

	// Wait for both streams to drain.
	marshalled := make([][]byte, len(pdus))
	total := 0
	for i, p := range pdus {
		b, err := p.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		marshalled[i] = b
		total += len(b)
	}

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && len(mdf.all()) < total {
		time.Sleep(50 * time.Millisecond)
	}

	got := mdf.all()
	for i, one := range marshalled {
		switch n := bytes.Count(got, one); {
		case n == 0:
			t.Errorf("product unit %d never reached the destination whole: the unit the write "+
				"stopped inside was skipped rather than resent from its own start, so an xIRI the "+
				"element produced was silently lost to a mediation function that is working", i)
		case n > 1:
			t.Errorf("product unit %d reached the destination %d times: the retry resent something "+
				"the peer already had, which is duplicate product under one warrant", i, n)
		}
	}
}

// TestADroppedUnitIsTheOneThatCouldNotBeResent is the surviving drop, and it is the case
// the drop report exists for: this element has one reconnect, it spent it, and the resend
// did not land either.
//
// Earlier units did land, so what is true is exactly what ErrUnitDropped says — delivery
// succeeded except for a product unit — and the destination is not called unreachable over
// it, because it took the rest. That distinction is the whole reason the delivery-lost
// reports exist alongside the reachability probe: recording this as unreachability would
// have the destination watcher raise a fault about a mediation function that is working and
// retract it on the next successful send, while the loss that actually happened is reported
// as the wrong condition.
func TestADroppedUnitIsTheOneThatCouldNotBeResent(t *testing.T) {
	cert := selfSignedServer(t)

	payload := bytes.Repeat([]byte{0xCD}, 400*1024)
	pdus := []*PDU{
		{Type: PDUTypeX2, PayloadFormat: PayloadFormat3GPP33128, Payload: payload},
		{Type: PDUTypeX2, PayloadFormat: PayloadFormat3GPP33128, Payload: payload},
		{Type: PDUTypeX2, PayloadFormat: PayloadFormat3GPP33128, Payload: payload},
	}

	// Every connection stalls, so the resend fails as the first write did.
	mdf := newHalfOpenMDF(t, cert, 64*1024, true)

	c := NewClient(mdf.addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // test peer
		KeepaliveConfig{Disabled: true})
	c.writeTimeout = 2 * time.Second
	t.Cleanup(func() { c.Close() }) //nolint:errcheck // test cleanup

	err := c.SendBatch(pdus)
	if err == nil {
		t.Skip("this peer took the whole batch on both connections, so no unit was dropped")
	}
	if !errors.Is(err, ErrUnitDropped) {
		t.Skipf("the write failed before any whole unit landed (%v); this case needs a partial "+
			"success, which depends on the socket buffers this machine gives the batch", err)
	}

	if c.Unreachable() {
		t.Error("a destination that took the rest of the batch is reported unreachable: the watcher " +
			"will raise a fault about a working mediation function, and the loss that actually " +
			"happened is reported as the wrong condition")
	}
}
