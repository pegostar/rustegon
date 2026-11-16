// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rustegon

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
)

// Version is the driver version reported to the server (ClientInfo.driver_version).
const Version = "0.1.0-alpha.1"

// DriverName is reported to the server in ClientInfo.driver_name.
const DriverName = "rustegon-go"

// DefaultPort is the gRPC port used when an endpoint names none.
const DefaultPort = 7700

// Mechanism is an authentication mechanism.
type Mechanism int

// Authentication mechanisms.
const (
	MechanismScramSHA256 Mechanism = iota + 1
	MechanismX509
	MechanismAPIKey
)

// String returns the connection-string spelling of the mechanism.
func (m Mechanism) String() string {
	switch m {
	case MechanismScramSHA256:
		return "SCRAM-SHA-256"
	case MechanismX509:
		return "X509"
	case MechanismAPIKey:
		return "APIKEY"
	}
	return ""
}

// Credential identifies the client. Its secret is never printed (String redacts it).
type Credential struct {
	mechanism Mechanism
	user      string
	secret    string
	hasSecret bool
}

// ScramCredential is a SCRAM-SHA-256 login (password, PD-074).
func ScramCredential(user, password string) *Credential {
	return &Credential{mechanism: MechanismScramSHA256, user: user, secret: password, hasSecret: true}
}

// APIKeyCredential authenticates every call with an API key (no session).
func APIKeyCredential(key string) *Credential {
	return &Credential{mechanism: MechanismAPIKey, secret: key, hasSecret: true}
}

// X509Credential logs in with the TLS client certificate of TLSSettings (implies TLS).
func X509Credential() *Credential { return &Credential{mechanism: MechanismX509} }

// Mechanism returns the mechanism.
func (c *Credential) Mechanism() Mechanism { return c.mechanism }

// User returns the user name (SCRAM), empty otherwise.
func (c *Credential) User() string { return c.user }

// String describes the credential without its secret.
func (c *Credential) String() string {
	if c == nil {
		return "<none>"
	}
	if c.user != "" {
		return fmt.Sprintf("%s(%s, ‹redacted›)", c.mechanism, c.user)
	}
	return fmt.Sprintf("%s(‹redacted›)", c.mechanism)
}

// TLSSettings configure TLS. ADR-034: TLS is off by default; Enabled, a CA file, a server name,
// a client certificate or an X509 credential turn it on.
type TLSSettings struct {
	// Enabled turns TLS on explicitly.
	Enabled bool
	// CAFile is a PEM file of trusted CA certificates (default: the system roots).
	CAFile string
	// ServerName overrides the name expected in the server certificate.
	ServerName string
	// CertificateFile and KeyFile are the PEM client certificate and key (X.509 login).
	CertificateFile string
	KeyFile         string
}

func (t TLSSettings) effective(cred *Credential) bool {
	return t.Enabled || t.CAFile != "" || t.ServerName != "" || t.CertificateFile != "" || t.KeyFile != "" ||
		(cred != nil && cred.mechanism == MechanismX509)
}

// ReadConsistency is the read consistency level (consistency.md); the zero value leaves the
// choice to the server (linearizable).
type ReadConsistency int

// Read consistency levels.
const (
	ServerDefaultConsistency ReadConsistency = iota
	Linearizable
	BoundedStaleness
	Follower
)

// WriteConcern is the write concern; the zero value is the server default (majority).
type WriteConcern int

// Write concerns.
const (
	ServerDefaultConcern WriteConcern = iota
	Majority
	All
)

// Settings is the complete client configuration. Build it with DefaultSettings,
// ParseConnectionString or the Option functions of New.
type Settings struct {
	Endpoints              []string
	Credential             *Credential
	TLS                    TLSSettings
	DefaultDatabase        string
	ApplicationName        string
	ConnectTimeout         time.Duration
	OperationTimeout       time.Duration
	ReadConsistency        ReadConsistency
	MaxStaleness           time.Duration
	WriteConcern           WriteConcern
	RetryReads             bool
	RetryWrites            bool
	MaxRetries             int
	ConnectionsPerEndpoint int
	// AllowPasswordChangeOnly accepts a login whose account must change its password, so that
	// ChangePassword can run (PD-076); other operations then fail on the server.
	AllowPasswordChangeOnly bool
	// Logger receives driver logs; nil = no logs. Secrets are never logged.
	Logger *slog.Logger

	// mechanism is the authMechanism of a connection string that named one without a user
	// (the credential is then set in code); kept for the connstring.yaml comparison.
	mechanism string
}

// DefaultSettings returns the defaults of connstring.yaml.
func DefaultSettings() Settings {
	return Settings{
		Endpoints:              []string{"localhost:7700"},
		ConnectTimeout:         10 * time.Second,
		OperationTimeout:       30 * time.Second,
		RetryReads:             true,
		RetryWrites:            true,
		MaxRetries:             1,
		ConnectionsPerEndpoint: 2,
	}
}

// String describes the settings without secrets.
func (s Settings) String() string {
	return fmt.Sprintf("Settings{Endpoints:%v Credential:%v TLS:%v DefaultDatabase:%q}", s.Endpoints, s.Credential, s.TLS.effective(s.Credential), s.DefaultDatabase)
}

// TLSEnabled reports whether the client will use TLS (ADR-034 implication rules).
func (s Settings) TLSEnabled() bool { return s.TLS.effective(s.Credential) }

func (s *Settings) validate() error {
	if len(s.Endpoints) == 0 {
		return argumentError("at least one endpoint is required")
	}
	for i, e := range s.Endpoints {
		n, err := normalizeEndpoint(e)
		if err != nil {
			return err
		}
		s.Endpoints[i] = n
	}
	if s.ConnectTimeout <= 0 || s.OperationTimeout <= 0 {
		return argumentError("timeouts must be positive")
	}
	if s.MaxRetries < 0 || s.MaxRetries > 10 {
		return argumentError("MaxRetries must be in 0..10")
	}
	if s.ConnectionsPerEndpoint < 1 || s.ConnectionsPerEndpoint > 64 {
		return argumentError("ConnectionsPerEndpoint must be in 1..64")
	}
	if s.ReadConsistency == BoundedStaleness && s.MaxStaleness <= 0 {
		return argumentError("BoundedStaleness needs MaxStaleness")
	}
	if (s.TLS.CertificateFile == "") != (s.TLS.KeyFile == "") {
		return argumentError("TLS CertificateFile and KeyFile go together")
	}
	if c := s.Credential; c != nil {
		switch c.mechanism {
		case MechanismScramSHA256:
			if c.user == "" {
				return argumentError("a SCRAM credential needs a user")
			}
			if !c.hasSecret {
				return argumentError("the SCRAM credential of user %q has no password: set one with ScramCredential", c.user)
			}
		case MechanismAPIKey:
			if c.secret == "" {
				return argumentError("an API key credential needs a key")
			}
		case MechanismX509:
			if s.TLS.CertificateFile == "" {
				return argumentError("an X509 credential needs TLS CertificateFile and KeyFile")
			}
		}
	}
	return nil
}

// normalizeEndpoint checks "host[:port]" (IPv6 in brackets) and returns "host:port".
func normalizeEndpoint(text string) (string, error) {
	host, port := text, ""
	if strings.HasPrefix(text, "[") {
		end := strings.IndexByte(text, ']')
		if end < 0 {
			return "", argumentError("unterminated IPv6 literal in an endpoint")
		}
		host = text[1:end]
		rest := text[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return "", argumentError("invalid endpoint")
			}
			port = rest[1:]
			if port == "" {
				return "", argumentError("empty port")
			}
		}
		if ip := net.ParseIP(host); ip == nil || !strings.Contains(host, ":") {
			return "", argumentError("invalid IPv6 literal")
		}
	} else {
		if i := strings.LastIndexByte(text, ':'); i >= 0 {
			host, port = text[:i], text[i+1:]
			if port == "" {
				return "", argumentError("empty port")
			}
		}
		if strings.Contains(host, ":") {
			return "", argumentError("an IPv6 address needs brackets")
		}
		if host == "" {
			return "", argumentError("empty host")
		}
		for _, r := range host {
			ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_'
			if !ok {
				return "", argumentError("invalid character in a host name")
			}
		}
		host = strings.ToLower(host)
	}
	p := DefaultPort
	if port != "" {
		for _, r := range port {
			if r < '0' || r > '9' {
				return "", argumentError("the port must be numeric")
			}
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", argumentError("the port must be in 1..65535")
		}
		p = n
	}
	return net.JoinHostPort(host, strconv.Itoa(p)), nil
}

// Option configures a Client (New).
type Option func(*Settings) error

// WithSettings replaces the whole configuration (later options still apply).
func WithSettings(s Settings) Option {
	return func(t *Settings) error {
		*t = s
		t.Endpoints = append([]string(nil), s.Endpoints...)
		return nil
	}
}

// WithConnectionString applies a rustegon:// connection string (connstring.yaml grammar).
func WithConnectionString(uri string) Option {
	return func(t *Settings) error {
		s, err := ParseConnectionString(uri)
		if err != nil {
			return err
		}
		*t = s
		return nil
	}
}

// WithEndpoints sets the seed endpoints ("host[:port]").
func WithEndpoints(endpoints ...string) Option {
	return func(s *Settings) error { s.Endpoints = append([]string(nil), endpoints...); return nil }
}

// WithCredential sets the credential.
func WithCredential(c *Credential) Option {
	return func(s *Settings) error { s.Credential = c; return nil }
}

// WithTLS sets the TLS settings.
func WithTLS(t TLSSettings) Option { return func(s *Settings) error { s.TLS = t; return nil } }

// WithDefaultDatabase sets the database of Client.Database("") and of transactions.
func WithDefaultDatabase(name string) Option {
	return func(s *Settings) error { s.DefaultDatabase = name; return nil }
}

// WithApplicationName sets the application name reported to the server.
func WithApplicationName(name string) Option {
	return func(s *Settings) error { s.ApplicationName = name; return nil }
}

// WithConnectTimeout bounds the establishment of a connection.
func WithConnectTimeout(d time.Duration) Option {
	return func(s *Settings) error { s.ConnectTimeout = d; return nil }
}

// WithOperationTimeout sets the default deadline of an operation, retries included (PD-097).
func WithOperationTimeout(d time.Duration) Option {
	return func(s *Settings) error { s.OperationTimeout = d; return nil }
}

// WithReadConsistency sets the default read consistency and its staleness bound.
func WithReadConsistency(level ReadConsistency, maxStaleness time.Duration) Option {
	return func(s *Settings) error { s.ReadConsistency, s.MaxStaleness = level, maxStaleness; return nil }
}

// WithWriteConcern sets the default write concern.
func WithWriteConcern(wc WriteConcern) Option {
	return func(s *Settings) error { s.WriteConcern = wc; return nil }
}

// WithRetryReads enables or disables the retry of reads.
func WithRetryReads(on bool) Option { return func(s *Settings) error { s.RetryReads = on; return nil } }

// WithRetryWrites enables or disables the retry of idempotent writes.
func WithRetryWrites(on bool) Option {
	return func(s *Settings) error { s.RetryWrites = on; return nil }
}

// WithMaxRetries sets the retry budget of one operation (0..10).
func WithMaxRetries(n int) Option { return func(s *Settings) error { s.MaxRetries = n; return nil } }

// WithConnectionsPerEndpoint sets the number of HTTP/2 connections per endpoint (1..64).
func WithConnectionsPerEndpoint(n int) Option {
	return func(s *Settings) error { s.ConnectionsPerEndpoint = n; return nil }
}

// WithAllowPasswordChangeOnly accepts logins that must change their password (PD-076).
func WithAllowPasswordChangeOnly(on bool) Option {
	return func(s *Settings) error { s.AllowPasswordChangeOnly = on; return nil }
}

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option { return func(s *Settings) error { s.Logger = l; return nil } }
