// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

// Package scram is the SCRAM-SHA-256 client (RFC 5802, RFC 7677; protocol.md §8) and SASLprep
// (RFC 4013), byte-exact with the .NET and Java drivers and the Rust client
// (crates/rustegon-security/src/authn/scram/client.rs).
package scram

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	// gs2Header: no channel binding, no authzid (PD-074).
	gs2Header = "n,,"
	// minIterations: RFC 7677 §4; lower is a downgrade attempt.
	minIterations = 4096
	// maxIterations bounds a malicious server making the client spin for minutes.
	maxIterations = 10_000_000
	// maxMessageLength bounds parsing work on untrusted input.
	maxMessageLength = 4096
	// nonceLength: 24 base62 characters, about 143 bits (same as the Rust and .NET clients).
	nonceLength = 24
	base62      = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// ErrAuthenticationFailed is wrapped by every handshake failure so callers can map it to
// UNAUTHENTICATED. Messages never contain the password or derived keys.
var ErrAuthenticationFailed = errors.New("authentication failed")

// Client runs one SCRAM-SHA-256 exchange, in order: ClientFirst, ProcessServerFirst,
// VerifyServerFinal. Not safe for concurrent use.
type Client struct {
	password        string
	clientNonce     string
	bare            string
	serverSignature []byte
}

// NewClient starts a handshake with a random 24-character base62 nonce. The user name is
// SASL-escaped but not prepared (as the Rust client); SASLprep applies to the password.
func NewClient(user, password string) (*Client, error) {
	nonce := make([]byte, nonceLength)
	var b [1]byte
	for i := range nonce {
		// Rejection sampling keeps the alphabet uniform: 248 = 4*62.
		for {
			if _, err := rand.Read(b[:]); err != nil {
				return nil, fmt.Errorf("scram: nonce generation: %w", err)
			}
			if b[0] < 248 {
				break
			}
		}
		nonce[i] = base62[b[0]%62]
	}
	return NewClientWithNonce(user, password, string(nonce))
}

// NewClientWithNonce starts a handshake with a fixed nonce (conformance vectors and tests).
func NewClientWithNonce(user, password, nonce string) (*Client, error) {
	if !validNonce(nonce) {
		return nil, errors.New("scram: invalid client nonce")
	}
	return &Client{password: password, clientNonce: nonce, bare: "n=" + encodeSaslName(user) + ",r=" + nonce}, nil
}

// ClientFirst returns the client-first message.
func (c *Client) ClientFirst() string { return gs2Header + c.bare }

// ProcessServerFirst validates server-first and returns client-final (CPU bound: PBKDF2).
// Checks follow the .NET client: length, exactly r/s/i, base64 salt, iterations in
// [4096, 10 000000], server nonce strictly extending ours, non-empty salt, SASLprep'd password.
func (c *Client) ProcessServerFirst(serverFirst string) (string, error) {
	if len(serverFirst) > maxMessageLength {
		return "", fail("server-first message too long")
	}
	attrs := strings.Split(serverFirst, ",")
	if len(attrs) != 3 {
		return "", fail("malformed server-first message")
	}
	nonce, err := attr(attrs[0], 'r')
	if err != nil {
		return "", err
	}
	saltB64, err := attr(attrs[1], 's')
	if err != nil {
		return "", err
	}
	salt, err := decodeBase64(saltB64)
	if err != nil {
		return "", err
	}
	iterText, err := attr(attrs[2], 'i')
	if err != nil {
		return "", err
	}
	// Digits only (no sign, no spaces), as .NET's NumberStyles.None; Atoi rejects overflow.
	iterations, convErr := strconv.Atoi(iterText)
	if convErr != nil || strings.IndexFunc(iterText, func(r rune) bool { return r < '0' || r > '9' }) >= 0 ||
		iterations < minIterations || iterations > maxIterations {
		return "", fail("iteration count out of bounds")
	}
	if !validNonce(nonce) || len(nonce) <= len(c.clientNonce) || !strings.HasPrefix(nonce, c.clientNonce) || len(salt) == 0 {
		return "", fail("malformed server-first message")
	}
	prepared, err := SASLPrep(c.password)
	if err != nil {
		return "", fail("the password is not valid SASLprep text")
	}

	salted, err := pbkdf2.Key(sha256.New, prepared, salt, iterations, sha256.Size)
	if err != nil {
		return "", fail("key derivation failed")
	}
	clientKey := hmacSHA256(salted, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	serverKey := hmacSHA256(salted, []byte("Server Key"))
	clear(salted)

	withoutProof := "c=" + base64.StdEncoding.EncodeToString([]byte(gs2Header)) + ",r=" + nonce
	authMessage := []byte(c.bare + "," + serverFirst + "," + withoutProof)
	signature := hmacSHA256(storedKey[:], authMessage)
	proof := make([]byte, len(clientKey))
	subtle.XORBytes(proof, clientKey, signature)
	clear(clientKey)
	c.serverSignature = hmacSHA256(serverKey, authMessage)
	clear(serverKey)
	return withoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof), nil
}

// VerifyServerFinal checks the server signature (mutual authentication) in constant time.
func (c *Client) VerifyServerFinal(serverFinal string) error {
	if c.serverSignature == nil {
		return errors.New("scram: server-first has not been processed")
	}
	if len(serverFinal) > maxMessageLength {
		return fail("server-final message too long")
	}
	if e, ok := strings.CutPrefix(serverFinal, "e="); ok {
		// RFC 5802 server-error-value: a short server token, not a secret.
		return fail("server error " + strconv.Quote(e))
	}
	v, ok := strings.CutPrefix(serverFinal, "v=")
	if !ok {
		return fail("server signature missing")
	}
	sig, err := decodeBase64(v)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(sig, c.serverSignature) != 1 {
		return fail("server signature mismatch")
	}
	return nil
}

// encodeSaslName is RFC 5802 §5.1 saslname: "=" -> "=3D", "," -> "=2C".
func encodeSaslName(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "=", "=3D"), ",", "=2C")
}

// validNonce is RFC 5802 §7: printable = %x21-2B / %x2D-7E.
func validNonce(n string) bool {
	if n == "" {
		return false
	}
	for i := 0; i < len(n); i++ {
		if n[i] < 0x21 || n[i] > 0x7E || n[i] == ',' {
			return false
		}
	}
	return true
}

func attr(part string, key byte) (string, error) {
	if len(part) >= 2 && part[0] == key && part[1] == '=' {
		return part[2:], nil
	}
	return "", fail("malformed SCRAM message")
}

func decodeBase64(s string) ([]byte, error) {
	// Go's decoder silently skips CR/LF; reject them so only canonical padded base64 passes.
	if len(s)%4 != 0 || strings.ContainsAny(s, "\r\n") {
		return nil, fail("malformed base64 in SCRAM message")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fail("malformed base64 in SCRAM message")
	}
	return b, nil
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func fail(reason string) error { return fmt.Errorf("%w: %s", ErrAuthenticationFailed, reason) }
