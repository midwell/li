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
	keepalive KeepaliveConfig
	onError   func(error)
	onDrop    func()

	mu      sync.Mutex
	senders map[string]Sender
	// closed stops For building a sender after Close has run. Close empties the map
	// rather than marking the pool, so without this a late delivery is indistinguishable
	// from a first one.
	closed bool
}

// NewPool returns a pool that dials with tlsConfig, running the clause 6.2.4 keepalive
// mechanism on every connection it opens as keepalive describes — the zero value being
// the specification's own defaults.
//
// onError is called with each worker delivery error and onDrop when a full queue costs a
// PDU; both may be nil, and both run on a delivery worker goroutine, so neither may block.
//
// A keepalive fault means the same thing as a delivery error — this destination is not
// working — so it is reported through onError rather than through a callback of its own.
// One condition, one report, whichever of the two mechanisms noticed it.
func NewPool(tlsConfig *tls.Config, keepalive KeepaliveConfig, onError func(error), onDrop func()) *Pool {
	if keepalive.OnFault == nil {
		keepalive.OnFault = onError
	}

	return &Pool{
		tlsConfig: tlsConfig,
		keepalive: keepalive,
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
	// A closed pool builds nothing. Close empties the map, so a delivery racing it
	// would otherwise miss the cache, construct a fresh sender with a worker
	// goroutine behind it, and store it in a pool nobody will close again — a worker
	// running past the shutdown that was supposed to end it, holding a connection to
	// a mediation function this element no longer answers for.
	if p.closed {
		return nil
	}

	s := NewAsyncSender(NewClient(addr, p.tlsConfig, p.keepalive), 0, p.onError, p.onDrop)
	p.senders[addr] = s

	return s
}

// UnreachableAmong reports how many of addrs cannot currently be reached, and how many of
// them this pool has attempted a delivery to at all.
//
// Both numbers, because an element may deliver to several agencies and "one of three" and
// "three of three" call for different responses from a provisioning function. Neither names
// an address: which destination is failing belongs to that destination's own status, not to
// the element's, and a probe is the one place that distinction is easy to lose.
//
// The caller passes the destinations its *tasking* currently names, and that is the whole
// point of the argument. A pool never forgets a client, so a destination whose last delivery
// failed and whose warrant was then withdrawn would otherwise count for the life of the
// process — nothing will ever deliver there again to clear it, and an element holding no
// tasking at all would report itself faulty. That is the probe-stuck-on failure this design
// exists to avoid, and it is answered by asking only about destinations still in use.
//
// A destination nothing has been sent to is not counted either way — see Client.Unreachable —
// so an element that has delivered nothing reports nothing. A destination named twice counts
// once: two warrants to one agency are one place product goes, and counting it twice would
// make "2 of 2 unreachable" out of a single failing endpoint.
//
// It performs no I/O and answers from state each client already holds, so it is safe to call
// from a fault probe on the X1 request goroutine.
// UnreachableAt answers for one address what UnreachableAmong counts over many: is
// this destination currently unreachable.
//
// An address nothing has been sent to answers false, on the same reasoning
// UnreachableAmong applies — an element that has delivered nothing has not found a
// mediation function unreachable, it has not looked.
//
// It exists because a destination-scoped fault report names one destination, so the
// question the counting form answers ("how many") is not the one being asked. Both
// read the same state and neither performs I/O.
func (p *Pool) UnreachableAt(addr string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	s, ok := p.senders[addr]
	if !ok {
		return false
	}
	r, ok := s.(Reachability)

	return ok && r.Unreachable()
}

func (p *Pool) UnreachableAmong(addrs []string) (unreachable, inUse int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	counted := make(map[string]bool, len(addrs))
	for _, addr := range addrs {
		if counted[addr] {
			continue
		}
		counted[addr] = true

		s, ok := p.senders[addr]
		if !ok {
			continue
		}
		inUse++
		if r, ok := s.(Reachability); ok && r.Unreachable() {
			unreachable++
		}
	}

	return unreachable, inUse
}

// Close drains and closes every client. It returns the first error, having closed the
// rest regardless: a half-closed pool would leave delivery workers running with nothing
// left to deliver to.
func (p *Pool) Close() error {
	p.mu.Lock()
	senders := p.senders
	p.senders = make(map[string]Sender)
	p.closed = true
	p.mu.Unlock()

	var firstErr error
	for _, s := range senders {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}
