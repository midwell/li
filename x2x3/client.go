// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x2x3

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
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

	mu   sync.Mutex
	conn net.Conn
}

// NewClient returns a delivery client for the MDF at addr ("host:port").
func NewClient(addr string, tlsConfig *tls.Config) *Client {
	return &Client{addr: addr, tlsConfig: tlsConfig, dialTimeout: 10 * time.Second, writeTimeout: 5 * time.Second}
}

// Send marshals pdu and writes it to the MDF, (re)connecting as needed. A PDU
// is self-delimiting (its header carries the header and payload lengths), so no
// extra framing is added on the wire.
func (c *Client) Send(pdu *PDU) error {
	b, err := pdu.Marshal()
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
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
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: c.dialTimeout}, "tcp", c.addr, c.tlsConfig)
	if err != nil {
		return fmt.Errorf("x2x3: dial %s: %w", c.addr, err)
	}
	c.conn = conn
	return nil
}

func (c *Client) writeLocked(b []byte) error {
	// Bound the write so a stalled/half-open MDF cannot block delivery (and every
	// other Send behind the mutex) indefinitely; a timeout is treated as any other
	// write error — drop + one redial.
	if c.writeTimeout > 0 {
		_ = c.conn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	}
	_, err := c.conn.Write(b)
	return err
}

func (c *Client) dropLocked() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}

// Close closes the underlying connection, if any.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}
