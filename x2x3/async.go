// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x2x3

import "sync"

// Sender is the minimal delivery contract an X2/X3 POI depends on. *Client
// satisfies it, and so does *AsyncSender, so a POI can wrap one in the other
// without changing its call sites.
type Sender interface {
	Send(*PDU) error
	Close() error
}

// AsyncSender decouples X2/X3 delivery from the caller's goroutine. Send enqueues
// the PDU onto a bounded buffer drained by a single background worker and returns
// immediately, so a slow or unreachable MDF never blocks a signalling or
// data-plane path — the target-observable timing side channel and availability
// risk that synchronous delivery introduces (review R3b; design D11 mandates
// "async X2/X3 delivery"; li-security-isolation "Delivery decoupled from
// signalling and data-plane processing").
//
// A single worker preserves per-POI delivery order (the MDF correlates by
// CIN/sequence, not arrival, so strict ordering is not required, but it is free
// and avoids reordering within one POI). When the buffer is full Send drops the
// PDU rather than block — LI product may be lost under sustained MDF outage, but
// the target's service is never delayed — and invokes onDrop so the fault can be
// surfaced to the ADMF over X1. Worker delivery errors invoke onError for the
// same purpose. Both callbacks run on the worker goroutine and must not block.
type AsyncSender struct {
	inner   Sender
	queue   chan *PDU
	onError func(error)
	onDrop  func()

	wg        sync.WaitGroup
	closeOnce sync.Once
}

// defaultQueueDepth bounds buffered-but-undelivered PDUs. Sized generously for
// LI product volume; a full queue means the MDF has been unreachable long enough
// that dropping (and reporting) is the correct, undetectable behaviour.
const defaultQueueDepth = 1024

// NewAsyncSender wraps inner with a bounded async delivery queue of the given
// depth (<=0 uses a default). onError is called with each worker delivery error;
// onDrop is called when Send drops a PDU because the buffer is full. Either may
// be nil. The worker starts immediately; call Close to stop it and close inner.
func NewAsyncSender(inner Sender, depth int, onError func(error), onDrop func()) *AsyncSender {
	if depth <= 0 {
		depth = defaultQueueDepth
	}
	a := &AsyncSender{
		inner:   inner,
		queue:   make(chan *PDU, depth),
		onError: onError,
		onDrop:  onDrop,
	}
	a.wg.Add(1)
	go a.run()
	return a
}

func (a *AsyncSender) run() {
	defer a.wg.Done()
	for pdu := range a.queue {
		if err := a.inner.Send(pdu); err != nil && a.onError != nil {
			a.onError(err)
		}
	}
}

// Send enqueues pdu for asynchronous delivery and returns immediately. It never
// blocks; a full buffer drops the PDU and invokes onDrop. The caller must not
// mutate pdu after Send (the worker reads it later). The returned error is always
// nil — delivery happens on the worker — and exists only to satisfy Sender.
func (a *AsyncSender) Send(pdu *PDU) error {
	select {
	case a.queue <- pdu:
	default:
		if a.onDrop != nil {
			a.onDrop()
		}
	}
	return nil
}

// Close stops accepting new PDUs, drains those already queued, waits for the
// worker to finish, and closes the inner Sender. Safe to call more than once.
func (a *AsyncSender) Close() error {
	a.closeOnce.Do(func() { close(a.queue) })
	a.wg.Wait()
	return a.inner.Close()
}
