// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

// Test helper of crates/rustegon-net/tests/tls.rs (ADR-035, PD-193): parses a Rustegon node
// certificate with Go's crypto/x509 and completes an mTLS handshake with it against a rustls
// peer listener, presenting the same node certificate as client certificate.
//
// Usage: go run handshake.go <addr> <ca.pem> <node.crt> <node.key>
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

func fail(step string, err error) {
	fmt.Printf("FAIL %s: %v\n", step, err)
	os.Exit(1)
}

func main() {
	addr, caFile, certFile, keyFile := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	raw, err := os.ReadFile(certFile)
	if err != nil {
		fail("read", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		fail("pem", fmt.Errorf("no PEM block"))
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		fail("parse", err)
	}
	caPem, err := os.ReadFile(caFile)
	if err != nil {
		fail("read ca", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPem) {
		fail("ca", fmt.Errorf("no CA certificate"))
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		fail("key pair", err)
	}
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs:      roots,
		Certificates: []tls.Certificate{pair},
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		fail("handshake", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		fail("write", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		fail("read echo", err)
	}
	fmt.Println("OK")
}
