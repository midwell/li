// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x2x3

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Client delivers X2 (xIRI) and X3 (xCC) PDUs to a Mediation & Delivery
// Function over a single TLS-secured TCP connection (ETSI TS 103 221-2). It
// connects lazily on the first Send and reconnects once on a write failure.
// It is safe for concurrent use.
//
// The caller supplies the *tls.Config — for LI this is mtls.ClientTLS(), which
// presents the network element's LI certificate and verifies the MDF.
type Client struct {
	addr         string
	tlsConfig    *tls.Config
	dialTimeout  time.Duration
	writeTimeout time.Duration
	keepalive    KeepaliveConfig

	mu sync.Mutex
	// live is the connection currently held, with the keepalive state that belongs
	// to it, or nil when none is. Everything about one connection dies with it —
	// see connState.
	live *connState

	// unreachable is what the most recent exchange with this destination established,
	// kept outside mu because a fault probe reads it on the X1 request goroutine: mu is
	// held across a dial and a write, and an answer to a provisioning function must not
	// wait for either. See Unreachable.
	unreachable atomic.Bool
}

// NewClient returns a delivery client for the MDF at addr ("host:port").
//
// The zero KeepaliveConfig is the conformant one — the clause 6.2.4 mechanism, at the
// specification's own timers — so a caller that has no opinion gets the behaviour the
// specification requires rather than none of it.
func NewClient(addr string, tlsConfig *tls.Config, keepalive KeepaliveConfig) *Client {
	return &Client{
		addr:         addr,
		tlsConfig:    tlsConfig,
		dialTimeout:  10 * time.Second,
		writeTimeout: 5 * time.Second,
		keepalive:    keepalive.withDefaults(),
	}
}

// Send marshals pdu and writes it to the MDF, (re)connecting as needed. A PDU
// is self-delimiting (its header carries the header and payload lengths), so no
// extra framing is added on the wire.
func (c *Client) Send(pdu *PDU) error {
	b, err := pdu.Marshal()
	if err != nil {
		return err
	}

	return c.sendBytes(b)
}

// sendBytes writes already-marshalled PDU bytes and records what the attempt established
// about the destination. One place records it, so the answer Unreachable gives cannot
// disagree with the outcome the caller saw.
func (c *Client) sendBytes(b []byte) error {
	err := c.deliver(b)
	c.unreachable.Store(err != nil)

	return err
}

// Unreachable reports whether the most recent exchange with this destination failed and
// none has since succeeded.
//
// It answers from what that exchange already established and dials nothing. A POI consults
// it from a fault probe, which runs on the X1 request goroutine: a probe that performed I/O
// would hold up a provisioning function's answer and — with a short enough timeout at the
// other end — could make a working element look dead while it asked itself a slow question.
//
// "Exchange" rather than "delivery attempt", since the keepalive mechanism: a connection
// whose mediation function stops acknowledging is reported within TIME_P2 even though
// nothing has been delivered over it. That is the improvement keepalive hands this probe —
// a destination that dies while idle used to be invisible until the next send.
//
// It is still false before anything has been sent, deliberately, and the mechanism does not
// change that: an element with nothing to deliver has not found its mediation function
// unreachable, it has not looked, and keepalives run only on a connection that a delivery
// has already dialled.
func (c *Client) Unreachable() bool {
	return c.unreachable.Load()
}

// deliver writes already-marshalled PDU bytes, reconnecting once if the MDF has
// dropped an idle connection. Reached from both Send and SendBatch through sendBytes, so
// both get the same reconnect behaviour — a batch is only a longer write.
func (c *Client) deliver(b []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.live == nil {
		if err := c.dialLocked(); err != nil {
			return err
		}
	}
	if err := c.writeLocked(b); err == nil {
		return nil
	}
	// One reconnect attempt — the MDF may have dropped an idle connection.
	c.dropLocked()
	if err := c.dialLocked(); err != nil {
		return err
	}
	if err := c.writeLocked(b); err != nil {
		c.dropLocked()
		return fmt.Errorf("x2x3: send to %s: %w", c.addr, err)
	}
	return nil
}

func (c *Client) dialLocked() error {
	ctx, cancel := context.WithTimeout(context.Background(), c.dialTimeout)
	defer cancel()

	d := tls.Dialer{NetDialer: &net.Dialer{}, Config: c.tlsConfig}
	conn, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return fmt.Errorf("x2x3: dial %s: %w", c.addr, err)
	}
	c.live = &connState{conn: conn, stop: make(chan struct{})}
	// The keepalive timer and the read path belong to this connection and to no
	// other: they start here and stop in dropLocked, which is what makes a stale
	// reader impossible and a keepalive on a connection nobody holds impossible.
	c.startKeepaliveLocked(c.live)

	return nil
}

func (c *Client) writeLocked(b []byte) error {
	// Bound the write so a stalled/half-open MDF cannot block delivery (and every
	// other Send behind the mutex) indefinitely; a timeout is treated as any other
	// write error — drop + one redial.
	if c.writeTimeout > 0 {
		//nolint:errcheck // a deadline a connection will not take is not actionable here
		_ = c.conn().SetWriteDeadline(time.Now().Add(c.writeTimeout))
	}
	_, err := c.conn().Write(b)
	return err
}

// conn is the held connection. Callers hold mu, and every one of them has already
// established that a connection exists.
func (c *Client) conn() net.Conn { return c.live.conn }

// dropLocked closes the held connection and signals whatever runs on its behalf to
// stop. It does not wait for those goroutines, deliberately: the keepalive timer
// takes mu to write, so waiting here — under mu — would deadlock against the very
// goroutine being waited for. They observe the closed connection or the closed stop
// channel and exit on their own, and nothing they do afterwards can touch the
// client, because each checks that it is still the live connection first.
func (c *Client) dropLocked() {
	if c.live == nil {
		return
	}
	_ = c.live.conn.Close()
	close(c.live.stop)
	c.live = nil
}

// Close closes the underlying connection, if any, and waits for its keepalive timer
// and reader to exit — so a caller that has closed a client is not left with
// goroutines it cannot see. The wait happens after mu is released, for the reason
// dropLocked gives.
func (c *Client) Close() error {
	c.mu.Lock()
	live := c.live
	if live == nil {
		c.mu.Unlock()
		return nil
	}
	err := live.conn.Close()
	close(live.stop)
	c.live = nil
	c.mu.Unlock()

	live.wg.Wait()

	return err
}

// SendBatch marshals several PDUs and writes them with a single call. PDUs are
// self-delimiting, so concatenating them needs no additional framing, and the
// receiver reads them exactly as it would separate writes. Fewer syscalls and
// fuller TLS records matter when a heavy target's content is the thing being
// delivered.
//
// A PDU that cannot be marshalled is skipped rather than discarding the batch
// around it, but the failure is returned once the rest has been sent: intercept
// product was lost, and losing it quietly is the one outcome this plane may not
// have. A delivery failure takes precedence, being the larger loss.
func (c *Client) SendBatch(pdus []*PDU) error {
	if len(pdus) == 0 {
		return nil
	}

	var (
		buf        []byte
		marshalErr error
	)

	for _, pdu := range pdus {
		b, err := pdu.Marshal()
		if err != nil {
			if marshalErr == nil {
				marshalErr = err
			}

			continue
		}

		buf = append(buf, b...)
	}

	if len(buf) == 0 {
		return marshalErr
	}

	if err := c.sendBytes(buf); err != nil {
		return err
	}

	return marshalErr
}
