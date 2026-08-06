// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package x1

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"time"
)

// X1 is a request/response control interface carrying a handful of small messages,
// so every phase of a connection can be given a short deadline. Without them
// net/http applies none at all, and a peer that opens a connection and then stalls
// — during the TLS handshake, before authentication has happened or can happen —
// holds it open indefinitely. Enough such connections and the element can no longer
// be tasked or, more to the point, untasked (review R42).
const (
	// x1ReadHeaderTimeout also bounds the TLS handshake, which is what makes it the
	// one that matters here: the stall an unauthenticated peer can cause happens
	// before any request exists.
	x1ReadHeaderTimeout = 10 * time.Second
	x1ReadTimeout       = 30 * time.Second
	x1WriteTimeout      = 30 * time.Second
	x1IdleTimeout       = 60 * time.Second
)

// NewListener returns the HTTP server an X1 endpoint should be served with:
// mutually authenticated, bounded in time, and silent.
//
// It exists so the three network functions cannot drift apart. They previously
// each constructed their own server, and a disclosure fixed in one had to be
// fixed again in the other two (review R35); the same would be true of every
// timeout here.
func NewListener(handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Handler:   handler,
		TLSConfig: tlsConfig,

		ReadHeaderTimeout: x1ReadHeaderTimeout,
		ReadTimeout:       x1ReadTimeout,
		WriteTimeout:      x1WriteTimeout,
		IdleTimeout:       x1IdleTimeout,

		// net/http sends server errors to the default logger, so a failed handshake
		// would print the peer's address to this process's stderr and hence to the
		// general operator log — publishing the LI domain's address and marking the
		// element as running a mutually authenticated listener that nothing else in
		// its configuration explains. Faults on this plane go to the ADMF over X1
		// (design D11), which is the only channel entitled to know (review R35).
		ErrorLog: log.New(io.Discard, "", 0),
	}
}
