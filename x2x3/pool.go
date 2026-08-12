// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x2x3

import (
	"crypto/tls"
	"sync"
)

// Pool holds one delivery client per destination address, created on first use.
//
// A POI needs this rather than a single client because destinations arrive per task over
// X1: they are not known at startup, and several agencies' endpoints may be in use at
// once. One client per process was the shape that made two warrants provisioned to two
// agencies both deliver to whichever address configuration happened to name.
//
// Each client is wrapped in an AsyncSender, because delivery must not run on the
// signalling goroutine that produced the record: a slow or unreachable MDF would delay a
// targeted subscriber's signalling, which is both an availability risk and a
// target-observable timing side channel.
//
// Safe for concurrent use.
type Pool struct {
	tlsConfig *tls.Config
	onError   func(error)
	onDrop    func()

	mu      sync.Mutex
	senders map[string]Sender
}

// NewPool returns a pool that dials with tlsConfig. onError is called with each worker
// delivery error and onDrop when a full queue costs a PDU; both may be nil, and both run
// on a delivery worker goroutine, so neither may block.
func NewPool(tlsConfig *tls.Config, onError func(error), onDrop func()) *Pool {
	return &Pool{
		tlsConfig: tlsConfig,
		onError:   onError,
		onDrop:    onDrop,
		senders:   make(map[string]Sender),
	}
}

// For returns the delivery client for addr ("host:port"), creating it on first use.
func (p *Pool) For(addr string) Sender {
	p.mu.Lock()
	defer p.mu.Unlock()

	if s, ok := p.senders[addr]; ok {
		return s
	}

	s := NewAsyncSender(NewClient(addr, p.tlsConfig), 0, p.onError, p.onDrop)
	p.senders[addr] = s

	return s
}

// Close drains and closes every client. It returns the first error, having closed the
// rest regardless: a half-closed pool would leave delivery workers running with nothing
// left to deliver to.
func (p *Pool) Close() error {
	p.mu.Lock()
	senders := p.senders
	p.senders = make(map[string]Sender)
	p.mu.Unlock()

	var firstErr error
	for _, s := range senders {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}
