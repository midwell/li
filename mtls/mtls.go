// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

// Package mtls loads the Lawful Interception PKI credentials and builds the
// mutual-TLS configurations for the X1/X2/X3 interfaces.
//
// LI requires mutual TLS with certificate verification on every interface
// (ETSI TS 103 221-1), using credentials from the operator's LI PKI — kept
// separate from the general SBI certificates for isolation. The credentials
// (this network element's LI certificate + key, and the LI CA trust anchor)
// are pre-provisioned out of band before any X1 tasking, corresponding to the
// ETSI TS 104 000 (X0) step; here that means the deployment places them at
// configured file paths (e.g. a dedicated, access-restricted Kubernetes
// Secret). Unlike SD-Core's SBI TLS, verification is never skipped.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// Material holds the loaded LI PKI credentials for one network element.
type Material struct {
	cert   tls.Certificate
	caPool *x509.CertPool
}

// Load reads this network element's LI certificate and key, and the LI CA
// trust anchor, from the given file paths (X0-pre-provisioned). All three are
// required — LI has no insecure/verification-skipped mode.
func Load(certPath, keyPath, caCertPath string) (*Material, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("mtls: load LI certificate/key: %w", err)
	}
	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("mtls: read LI CA certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("mtls: LI CA file %q contains no valid certificate", caCertPath)
	}
	return &Material{cert: cert, caPool: pool}, nil
}

// ServerTLS returns the TLS config for the X1 listener: it presents this NE's
// LI certificate and requires and verifies a client (ADMF) certificate issued
// by the LI CA. A peer without a valid LI certificate is rejected at handshake.
func (m *Material) ServerTLS() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{m.cert},
		ClientCAs:    m.caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
}

// ClientTLS returns the TLS config for delivering X2 (xIRI) and X3 (xCC) to an
// MDF: it presents this NE's LI certificate and verifies the MDF's server
// certificate against the LI CA (verification is never skipped).
func (m *Material) ClientTLS() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{m.cert},
		RootCAs:      m.caPool,
		MinVersion:   tls.VersionTLS12,
	}
}
