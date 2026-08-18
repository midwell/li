// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x2x3

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// The keepalive mechanism of ETSI TS 103 221-2 clause 6.2.4: what a Keepalive PDU
// looks like, how it is numbered, and — from KeepaliveConfig down — the timers, the
// read path and the TIME_P2 disconnect that operate it.
//
// The connection half is written as methods on Client because Client owns the
// connection: it dials it, writes to it, drops it and redials it. A timer that lived
// anywhere else could only ask Client to do those things, and would have to be told
// when the connection underneath it had been replaced.
//
// Clause 5.1 defines the PDU exactly: "A set of mandatory header fields, where the
// Version, PDU Type and Header Length fields are populated as specified and all
// other mandatory fields are set to zero", plus "A Sequence Number - see
// clause 5.3.9", and its NOTE draws the consequence that there is no payload.
//
// Zero means zero, and that is the whole of the difference from a product PDU: no
// XID, no Correlation ID, no payload format, no direction. A Keepalive says nothing
// about any warrant, which is why it needs a counter that is not Sequencer's — see
// keepaliveCounter below.

// Keepalive returns a Keepalive PDU (type 3) carrying sequence.
func Keepalive(sequence uint32) *PDU {
	return keepalivePDU(PDUTypeKeepalive, sequence)
}

// KeepaliveAck returns the Keepalive Acknowledgement (type 4) for sequence.
//
// Clause 6.2.4: "The Sequence Number in the Keepalive Acknowledgement PDU shall be
// equal to the Sequence Number in the Keepalive PDU" — so the caller passes back
// what it received rather than a number of its own. The number in an acknowledgement
// belongs to the sequence of whoever sent the Keepalive.
func KeepaliveAck(sequence uint32) *PDU {
	return keepalivePDU(PDUTypeKeepaliveAck, sequence)
}

func keepalivePDU(t PDUType, sequence uint32) *PDU {
	// Every field left at its zero value is a field clause 5.1 requires to be zero.
	// Setting them explicitly would read as a choice; leaving them is the same bytes
	// and says they are not.
	return &PDU{
		Type:       t,
		Attributes: []TLV{SequenceNumber(sequence)},
	}
}

// KeepaliveSequence returns the Sequence Number a Keepalive or Keepalive
// Acknowledgement carries, and whether it carried a well-formed one.
//
// False for an attribute that is absent or not the four octets clause 5.3.9
// defines. A peer that answers without a usable number has not answered the
// question the mechanism asks, and the caller decides what to do about it — this
// reports what arrived and judges nothing.
func KeepaliveSequence(p *PDU) (uint32, bool) {
	for _, a := range p.Attributes {
		if a.Type == AttrSequenceNumber && len(a.Value) == 4 {
			return binary.BigEndian.Uint32(a.Value), true
		}
	}

	return 0, false
}

// keepaliveCounter numbers the Keepalive PDUs sent on one connection.
//
// It is deliberately not Sequencer. Clause 5.3.9 numbers PDUs within an "XID, DID,
// NFID, IPID and Correlation ID context", and clause 5.1 has a Keepalive zero every
// one of those fields: a Keepalive's context is no task's, so numbering it from a
// task's sequence would advance that task's numbers for a PDU the task has nothing
// to do with. The mediation function reads those numbers to detect lost product.
//
// One per connection, so a new connection numbers from zero — which is what a new
// connection is, and it means a late acknowledgement from a socket that has already
// been dropped cannot match a number in flight on its replacement.
//
// Atomic because the timer that takes numbers and the connection teardown that
// discards them are different goroutines.
type keepaliveCounter struct {
	next atomic.Uint32
}

// take returns this connection's next Keepalive sequence number, starting at zero
// and wrapping to zero after 2^32-1 — clause 5.3.9's own restart rule, which applies
// to this counter for the same reason it applies to Sequencer's.
func (c *keepaliveCounter) take() uint32 {
	return c.next.Add(1) - 1
}

// issued is one past the highest number handed out, so a caller can tell an
// acknowledgement for a Keepalive this connection sent from one for a number it never
// did. Used to notice a peer that echoes something of its own invention.
func (c *keepaliveCounter) issued() uint32 {
	return c.next.Load()
}

// The specification's own timers, clause 6.2.4: "by default TIME_P1 shall be 60
// seconds", "by default TIME_P2 shall be 180 seconds".
const (
	// MinKeepaliveTime is the shortest either timer may be. TS 103 221-2 clause 6.2.4
	// gives both as an integer number of seconds, so anything below one second is not a
	// value the interface can express — and the sub-second end is where the arithmetic
	// around them stops behaving: a window divided to produce a tick interval reaches
	// zero, and a timer that fires continuously is a fault rather than a fast keepalive.
	MinKeepaliveTime = time.Second

	DefaultTimeP1 = 60 * time.Second
	DefaultTimeP2 = 180 * time.Second
)

// maxInboundPDU bounds what this element will hold from a peer before deciding the
// peer is broken.
//
// The read path exists to receive Keepalive Acknowledgements, which are 48 bytes.
// Unmarshal waits for as many bytes as a header claims and imposes no maximum of its
// own — nothing bounded it before, because until keepalive nothing on this interface
// ever read. A peer declaring a four-gigabyte payload would otherwise be a peer that
// can exhaust this process. The margin over 48 is for a peer that carries attributes
// we do not expect, which is allowed; four kilobytes of them is not.
const maxInboundPDU = 4096

// KeepaliveConfig configures the clause 6.2.4 mechanism on a client's connections.
//
// The zero value is the conformant one: the mechanism running at the specification's
// own timers. That is why the switch is Disabled rather than Enabled — an inverted
// flag is a smell, and a zero value that silently omits a mandatory mechanism is a
// worse one. A caller with no opinion gets what the specification requires.
type KeepaliveConfig struct {
	// Disabled turns the mechanism off: no keepalives are sent, nothing is read from
	// the connection, and no TIME_P2 disconnect can occur — which is exactly the
	// behaviour this package had before the mechanism existed.
	//
	// It exists because a mediation function that does not implement the MDF half of
	// clause 6.2.4 will never acknowledge, and an element pointed at one would
	// disconnect every TIME_P2 and lose whatever was in flight each time. The
	// reference implementation this project interoperates with is such a peer,
	// established by probe on 2026-08-14. Turning the mechanism off is a deployment's
	// answer to a non-conformant peer; it is not the shipped default.
	Disabled bool

	// TimeP1 is how often a Keepalive is sent on a held connection. Zero means
	// DefaultTimeP1.
	TimeP1 time.Duration

	// TimeP2 is how long the connection may go without an acknowledgement before it
	// is disconnected. Zero means DefaultTimeP2.
	TimeP2 time.Duration

	// OnFault is called when the mechanism establishes that a mediation function is
	// not answering, or that it is answering with something this element cannot
	// parse. It carries the same meaning as a delivery failure — the destination is
	// not working — so a POI wires it to whatever it already reports those with.
	//
	// It runs on the keepalive goroutine and must not block.
	OnFault func(error)
}

// Validate reports a configuration that would break the mechanism rather than run it.
//
// It lives here rather than in each network function because it is a rule about the
// mechanism, not about any element's configuration file: three copies of it in three
// repositories would be three chances for one of them to drift into accepting timers
// that disconnect every connection on schedule.
//
// **The constructors deliberately do not call it.** NewClient, NewPool and
// NewAsyncSender return no error, so a constructor that validated could only clamp an
// out-of-range value to the defaults — which is not enforcement, and would hide exactly
// the mistake this exists to surface — or change its signature, which is an API break
// for three network functions to guard a path none of them takes. All three call this
// themselves before building anything (amf and smf lawfulintercept, upf pfcpiface), so
// what a constructor check would add is a second answer for a configuration that has
// already been refused. If a caller ever appears that does not validate, that is the
// point to revisit this.
//
// The specification constrains only that each timer is at least one second. The
// relationship between them is left implied, and the implication is not subtle:
// TIME_P2 is the time allowed for an acknowledgement, TIME_P1 the interval between
// the requests being acknowledged, so a TIME_P2 that does not exceed TIME_P1 expires
// before the keepalive that would refresh it is even sent. Every connection would then
// be torn down on a timer, forever, and the element would report a fault each time —
// the exact failure this mechanism exists to distinguish from a real one.
func (k KeepaliveConfig) Validate() error {
	if k.TimeP1 < 0 || k.TimeP2 < 0 {
		return fmt.Errorf("x2x3: keepalive timers must not be negative (TIME_P1 %s, TIME_P2 %s)", k.TimeP1, k.TimeP2)
	}
	// The one-second minimum this comment has always described, now enforced. Zero is
	// not a value: it means "unset", and withDefaults supplies the specification's own
	// timer for it — which is why the test is on a positive value below the floor
	// rather than on anything that is not at least a second.
	if (k.TimeP1 > 0 && k.TimeP1 < MinKeepaliveTime) || (k.TimeP2 > 0 && k.TimeP2 < MinKeepaliveTime) {
		return fmt.Errorf(
			"x2x3: keepalive timers must be at least %s, which is the resolution TS 103 221-2 clause 6.2.4 expresses them in (TIME_P1 %s, TIME_P2 %s)",
			MinKeepaliveTime, k.TimeP1, k.TimeP2)
	}

	e := k.withDefaults()
	if e.TimeP2 <= e.TimeP1 {
		return fmt.Errorf(
			"x2x3: TIME_P2 (%s) must exceed TIME_P1 (%s), or every connection is disconnected before the keepalive that would keep it is sent",
			e.TimeP2, e.TimeP1)
	}

	return nil
}

func (k KeepaliveConfig) withDefaults() KeepaliveConfig {
	if k.TimeP1 <= 0 {
		k.TimeP1 = DefaultTimeP1
	}
	if k.TimeP2 <= 0 {
		k.TimeP2 = DefaultTimeP2
	}

	return k
}

// connState is everything that belongs to one connection and dies with it: the
// socket, the Keepalive numbering of clause 5.3.9, and the goroutines operating the
// mechanism on it.
//
// Tying all of it to the connection is what makes the hard cases fall out for free.
// A reader cannot outlive the socket it reads. A replacement connection numbers from
// zero, so a late acknowledgement from a dropped socket cannot match a number in
// flight on its successor. And a timer cannot dial, because it does not exist until
// a delivery has dialled.
type connState struct {
	conn net.Conn
	seq  keepaliveCounter

	// acks carries "an acknowledgement arrived" from the reader to the timer. One
	// slot and a non-blocking send: the timer only needs to know that one arrived
	// since it last looked, and the reader must never block on a timer.
	acks chan struct{}

	// stop is closed when this connection is dropped, whoever drops it.
	stop chan struct{}
	wg   sync.WaitGroup

	// mismatches counts acknowledgements carrying a Sequence Number this connection
	// never sent. Clause 6.2.4 requires the MDF to echo the number, so a mismatch is
	// a peer defect worth noticing — but not worth disconnecting a working connection
	// over, which is why it is counted rather than acted on. Counted rather than
	// logged because this package takes no logger; a test asserts it was seen.
	mismatches atomic.Uint64
}

// startKeepaliveLocked starts the mechanism on a freshly dialled connection. The
// caller holds mu.
func (c *Client) startKeepaliveLocked(st *connState) {
	if c.keepalive.Disabled {
		return
	}

	st.acks = make(chan struct{}, 1)
	st.wg.Add(2)

	go c.keepaliveLoop(st)
	go c.readLoop(st)
}

// keepaliveLoop sends a Keepalive every TIME_P1 and disconnects if TIME_P2 passes
// with no acknowledgement.
//
// The send is unconditional, not an idle timer. Clause 6.2.4 carries no idle
// qualifier, and product PDUs are not acknowledged: traffic on a connection
// establishes that the socket is open and nothing about whether the mediation
// function behind it is still running. An idle-reset timer would leave the busiest
// connection — where a dead MDF costs the most product — the only one never checked.
func (c *Client) keepaliveLoop(st *connState) {
	defer st.wg.Done()

	send := time.NewTicker(c.keepalive.TimeP1)
	defer send.Stop()

	// One deadline for the connection, refreshed by any acknowledgement, which is
	// what clause 6.2.4 describes: the POI disconnects if it "has not seen a
	// Keepalive Acknowledgement PDU within TIME_P2", not if one particular Keepalive
	// went unanswered. At the default timers that tolerates two lost or late
	// acknowledgements before the third failure disconnects.
	expiry := time.NewTimer(c.keepalive.TimeP2)
	defer expiry.Stop()

	for {
		select {
		case <-st.stop:
			return
		case <-send.C:
			if !c.sendKeepalive(st) {
				return
			}
		case <-st.acks:
			expiry.Stop()
			expiry.Reset(c.keepalive.TimeP2)
		case <-expiry.C:
			c.expire(st)

			return
		}
	}
}

// sendKeepalive writes one Keepalive, reporting whether the loop should continue.
func (c *Client) sendKeepalive(st *connState) bool {
	// The number is taken before the lock: it belongs to this connection's sequence
	// whether or not the write finds the connection still current.
	b, err := Keepalive(st.seq.take()).Marshal()
	if err != nil {
		return false // unreachable: a Keepalive's shape is fixed and valid
	}

	if err := c.writeOn(st, b); err != nil {
		// A connection this element replaced is not a fault, and saying so here is the
		// whole point of the distinction: the loop ends because its connection ended,
		// and the replacement has a timer of its own.
		if errors.Is(err, errStaleConn) {
			return false
		}

		c.unreachable.Store(true)
		c.fault(fmt.Errorf("x2x3: keepalive to %s: %w", c.addr, err))

		return false
	}

	return true
}

// errStaleConn reports that st is no longer the connection this client holds: it was
// dropped and redialled, or closed. It is deliberately distinct from a write failure.
//
// A write failure says something about the mediation function. This says something about
// us — the connection went because *this element* replaced it, which the one-shot redial
// in deliver does on any write error and Close does at shutdown. Reporting it as a fault
// would push mdfUnreachable and set the probe's answer to "faulty" every time an ordinary
// redial happened to race the keepalive timer, in the one mechanism whose purpose is
// telling a dead mediation function from a live one.
var errStaleConn = errors.New("x2x3: connection replaced")

// writeOn writes to st, but only while st is still the connection this client holds.
//
// The check is what makes a keepalive safe to write from its own goroutine: between
// the timer firing and the lock being acquired, a delivery may have failed, dropped
// this connection and dialled another. Writing then would put a keepalive numbered
// for one connection onto a different one.
func (c *Client) writeOn(st *connState, b []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.live != st {
		return errStaleConn
	}
	if _, err := c.writeLocked(b); err != nil {
		// Drop rather than redial here: the next delivery redials, and a keepalive
		// has nothing to deliver that would justify dialling on its own.
		c.dropLocked()

		return err
	}

	return nil
}

// readLoop is the only thing in this project that reads an X2/X3 socket.
//
// It exists for the acknowledgement, and it accepts exactly the two PDU types the
// mechanism defines. Anything else is a peer speaking something this element does
// not: the connection goes, and the next delivery redials.
func (c *Client) readLoop(st *connState) {
	defer st.wg.Done()

	var (
		buf []byte
		tmp = make([]byte, 512)
	)

	for {
		n, err := st.conn.Read(tmp)
		if err != nil {
			// Includes the close this element performed itself, which is routine —
			// every redial does it — so nothing is reported from here. The only
			// thing that reports is the TIME_P2 deadline.
			return
		}

		buf = append(buf, tmp[:n]...)
		// Refuse a PDU larger than this mechanism can be asked to hold before
		// accumulating it, rather than after: the length fields are the peer's
		// claim, and this is the point at which the claim is cheap to refuse.
		if len(buf) >= 12 {
			declared := uint64(binary.BigEndian.Uint32(buf[4:8])) + uint64(binary.BigEndian.Uint32(buf[8:12]))
			if declared > maxInboundPDU {
				c.protocolError(st, fmt.Errorf("x2x3: %s declared a %d-byte PDU, over the %d-byte limit", c.addr, declared, maxInboundPDU))

				return
			}
		}

		for {
			p, used, err := Unmarshal(buf)
			if errors.Is(err, ErrIncomplete) {
				break
			}
			if err != nil {
				c.protocolError(st, fmt.Errorf("x2x3: undecodable PDU from %s: %w", c.addr, err))

				return
			}

			buf = buf[used:]
			if !c.handleInbound(st, p) {
				return
			}
		}
	}
}

// handleInbound acts on one decoded PDU, reporting whether the reader continues.
func (c *Client) handleInbound(st *connState, p *PDU) bool {
	switch p.Type {
	case PDUTypeKeepaliveAck:
		seq, ok := KeepaliveSequence(p)
		// An acknowledgement numbered beyond what this connection has handed out was
		// never sent by us. Counted, not acted on: a peer's numbering defect must not
		// tear down a connection that is demonstrably answering.
		if !ok || seq >= st.seq.issued() {
			st.mismatches.Add(1)
		}

		// The exchange succeeded whatever the number said — something is alive at the
		// other end and answering keepalives, which is the whole question TIME_P2 asks.
		c.unreachable.Store(false)
		select {
		case st.acks <- struct{}{}:
		default:
		}

		return true

	case PDUTypeKeepalive:
		return c.answerKeepalive(st, p)

	case PDUTypeX2, PDUTypeX3:
		fallthrough
	default:
		c.protocolError(st, fmt.Errorf("x2x3: %s sent PDU type %d on a delivery connection", c.addr, p.Type))

		return false
	}
}

// answerKeepalive is the MDF-facing half of clause 6.2.4, which makes both PDU types
// supported by POIs *and* MDFs. A peer that keepalives us gets an acknowledgement
// carrying its own Sequence Number.
//
// It does not touch this connection's counter. The number in an acknowledgement
// belongs to the sequence of whoever sent the Keepalive, and advancing ours here
// would put a gap in the numbering the peer is watching for lost keepalives.
func (c *Client) answerKeepalive(st *connState, p *PDU) bool {
	seq, ok := KeepaliveSequence(p)
	if !ok {
		// Clause 6.2.4 requires the acknowledgement to carry the same number, and a
		// number that was not sent cannot be echoed. Counted and ignored — refusing
		// the connection over it would punish a peer defect with lost product.
		st.mismatches.Add(1)

		return true
	}

	b, err := KeepaliveAck(seq).Marshal()
	if err != nil {
		return false // unreachable: the shape is fixed and valid
	}

	return c.writeOn(st, b) == nil
}

// protocolError drops a connection whose peer is not speaking X2/X3, and reports it.
//
// Reported rather than dropped quietly: a mediation function sending something this
// element cannot parse is a fault in the delivery plane, and the ADMF is the only
// party that can act on it.
//
// It reports even when the connection has already been replaced, which is deliberate and
// is *not* the errStaleConn case above. There, the connection went because this element
// replaced it and nothing had gone wrong; here a peer sent bytes no X2/X3 implementation
// should send, and that stays true whichever socket carried them.
//
// It marks the destination unreachable, as the TIME_P2 expiry and a failed delivery both
// do. This is the same conclusion arrived at by a third route — the exchange with this
// mediation function did not work — and leaving it out meant the two mechanisms disagreed
// about one destination: the ADMF received a pushed fault while the status answer it could
// ask for went on saying the destination was reachable. An element whose two answers
// contradict each other is one whose status answer stops being read.
func (c *Client) protocolError(st *connState, err error) {
	// Stored before the fault is reported and before the connection is dropped, so a
	// status request racing this cannot be answered "reachable" by an element that has
	// just concluded otherwise — the ordering expire already uses.
	c.unreachable.Store(true)

	c.mu.Lock()
	if c.live == st {
		c.dropLocked()
	}
	c.mu.Unlock()

	c.fault(err)
}

// expire applies clause 6.2.4's TIME_P2 rule: "the POI shall disconnect the
// connection and shall attempt to reconnect to the MDF and report an error through
// the X1 interface".
//
// All three, in that order. The reconnect is one attempt rather than a loop — this
// restores a connection the element was holding, which is not the same as dialling
// one it never had — and if it fails the next delivery redials as it always would.
func (c *Client) expire(st *connState) {
	// Set before the fault is reported and before the redial, so that a status
	// request racing this cannot be answered "reachable" by an element that has just
	// concluded otherwise.
	c.unreachable.Store(true)

	c.mu.Lock()
	if c.live == st {
		c.dropLocked()
		// Failure is not reported here: the dial error says the MDF is unreachable,
		// which is what has just been reported anyway.
		//nolint:errcheck // the fault below carries the same conclusion
		_ = c.dialLocked()
	}
	c.mu.Unlock()

	c.fault(fmt.Errorf("x2x3: no keepalive acknowledgement from %s within %s (TIME_P2)", c.addr, c.keepalive.TimeP2))
}

func (c *Client) fault(err error) {
	if c.keepalive.OnFault != nil {
		c.keepalive.OnFault(err)
	}
}
