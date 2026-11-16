// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rustegon

import (
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ParseConnectionString parses rustegon://[user[:password]@]host[:port][,host[:port]...][/database][?options]
// into DefaultSettings overlaid by the string (grammar and options: drivers/conformance/connstring.yaml,
// DEC-014). ADR-034: TLS is off by default; without an explicit tls option, any tls* option or
// authMechanism=X509 turns it on, and tls=false together with either is an error.
//
// Errors match ErrArgument and never quote the string or a decoded value (it may hold a secret).
func ParseConnectionString(uri string) (Settings, error) {
	const scheme = "rustegon://"
	if !strings.HasPrefix(uri, scheme) {
		if strings.HasPrefix(uri, "rustegon+srv://") {
			return Settings{}, connErr("rustegon+srv is not supported yet")
		}
		return Settings{}, connErr("the scheme must be rustegon://")
	}
	rest := uri[len(scheme):]
	var options string
	hasOptions := false
	if q := strings.IndexByte(rest, '?'); q >= 0 {
		options, hasOptions = rest[q+1:], true
		rest = rest[:q]
	}
	// The user information ends at the first '@'; a second one is a raw '@' in the password
	// (RFC 3986 needs %40) and is refused rather than guessed at.
	at := strings.IndexByte(rest, '@')
	if at >= 0 && strings.IndexByte(rest[at+1:], '@') >= 0 {
		return Settings{}, connErr("the user information contains a raw '@': percent-encode it as %40")
	}
	authority, path := rest, ""
	if slash := strings.IndexByte(rest[at+1:], '/'); slash >= 0 {
		authority, path = rest[:at+1+slash], rest[at+1+slash+1:]
	}
	var user, password *string
	if at >= 0 {
		info := authority[:at]
		authority = authority[at+1:]
		u, p, hasP := strings.Cut(info, ":")
		du, err := decode(u, "user")
		if err != nil {
			return Settings{}, err
		}
		if du == "" {
			return Settings{}, connErr("empty user name")
		}
		user = &du
		if hasP {
			dp, err := decode(p, "password")
			if err != nil {
				return Settings{}, err
			}
			password = &dp
		}
	}
	s := DefaultSettings()
	if authority == "" {
		return Settings{}, connErr("at least one host is required")
	}
	s.Endpoints = nil
	for _, h := range strings.Split(authority, ",") {
		if strings.ContainsAny(h, " \t") {
			return Settings{}, connErr("whitespace in a host")
		}
		e, err := normalizeEndpoint(h)
		if err != nil {
			return Settings{}, connErr("invalid host")
		}
		s.Endpoints = append(s.Endpoints, e)
	}
	if path != "" {
		if strings.Contains(path, "/") {
			return Settings{}, connErr("the database name cannot contain '/'")
		}
		db, err := decode(path, "database")
		if err != nil {
			return Settings{}, err
		}
		s.DefaultDatabase = db
	}
	if err := applyOptions(&s, options, hasOptions, user, password); err != nil {
		return Settings{}, err
	}
	return s, nil
}

func connErr(reason string) error {
	return argumentError("invalid connection string: %s", reason)
}

func applyOptions(s *Settings, options string, hasOptions bool, user, password *string) error {
	seen := map[string]bool{}
	var mechanism, apiKey *string
	tlsOff, otherTLS, hasStaleness := false, false, false
	var pairs []string
	if hasOptions && options != "" {
		pairs = strings.Split(options, "&")
	}
	for _, pair := range pairs {
		eq := strings.IndexByte(pair, '=')
		if eq <= 0 {
			return connErr("every option needs a name and a value (name=value)")
		}
		key := pair[:eq]
		value, err := decode(pair[eq+1:], "option "+key)
		if err != nil {
			return err
		}
		k := strings.ToLower(key)
		if seen[k] {
			return connErr("option '" + key + "' is repeated")
		}
		seen[k] = true
		switch k {
		case "tls":
			b, err := boolOpt(key, value)
			if err != nil {
				return err
			}
			s.TLS.Enabled, tlsOff = b, !b
		case "tlscafile", "tlsservername", "tlscertificatefile", "tlskeyfile":
			if value == "" {
				return connErr("option '" + key + "' is empty")
			}
			otherTLS = true
			switch k {
			case "tlscafile":
				s.TLS.CAFile = value
			case "tlsservername":
				s.TLS.ServerName = value
			case "tlscertificatefile":
				s.TLS.CertificateFile = value
			default:
				s.TLS.KeyFile = value
			}
		case "authmechanism":
			m := strings.ToUpper(value)
			mechanism = &m
		case "apikey":
			if value == "" {
				return connErr("option '" + key + "' is empty")
			}
			apiKey = &value
		case "appname":
			if value == "" {
				return connErr("option '" + key + "' is empty")
			}
			s.ApplicationName = value
		case "connecttimeoutms", "operationtimeoutms", "maxstalenessms":
			n, err := intOpt(key, value, 1, 1<<31-1)
			if err != nil {
				return err
			}
			d := time.Duration(n) * time.Millisecond
			switch k {
			case "connecttimeoutms":
				s.ConnectTimeout = d
			case "operationtimeoutms":
				s.OperationTimeout = d
			default:
				s.MaxStaleness, hasStaleness = d, true
			}
		case "connectionsperendpoint":
			n, err := intOpt(key, value, 1, 64)
			if err != nil {
				return err
			}
			s.ConnectionsPerEndpoint = n
		case "maxretries":
			n, err := intOpt(key, value, 0, 10)
			if err != nil {
				return err
			}
			s.MaxRetries = n
		case "readconsistency":
			switch strings.ToLower(value) {
			case "linearizable":
				s.ReadConsistency = Linearizable
			case "bounded_staleness":
				s.ReadConsistency = BoundedStaleness
			case "follower":
				s.ReadConsistency = Follower
			default:
				return connErr("unknown value of option '" + key + "'")
			}
		case "writeconcern":
			switch strings.ToLower(value) {
			case "majority":
				s.WriteConcern = Majority
			case "all":
				s.WriteConcern = All
			default:
				return connErr("unknown value of option '" + key + "'")
			}
		case "retryreads", "retrywrites":
			b, err := boolOpt(key, value)
			if err != nil {
				return err
			}
			if k == "retryreads" {
				s.RetryReads = b
			} else {
				s.RetryWrites = b
			}
		default:
			return connErr("unknown option '" + key + "'")
		}
	}
	x509 := mechanism != nil && *mechanism == "X509"
	if tlsOff && (otherTLS || x509) {
		return connErr("tls=false contradicts the other tls options or authMechanism=X509")
	}
	// ADR-034: plain text by default; a tls* option or X.509 (which needs TLS) turns it on.
	if otherTLS || x509 {
		s.TLS.Enabled = true
	}
	if (s.TLS.CertificateFile == "") != (s.TLS.KeyFile == "") {
		return connErr("tlsCertificateFile and tlsKeyFile go together")
	}
	if s.ReadConsistency == BoundedStaleness && !hasStaleness {
		return connErr("readConsistency=bounded_staleness needs maxStalenessMs")
	}
	cred, err := credentialOf(mechanism, user, password, apiKey)
	if err != nil {
		return err
	}
	s.Credential = cred
	if cred == nil && mechanism != nil {
		s.mechanism = *mechanism
	}
	return nil
}

func credentialOf(mechanism, user, password, apiKey *string) (*Credential, error) {
	m := ""
	if mechanism != nil {
		m = *mechanism
	}
	switch {
	case (m == "" && apiKey != nil) || m == "APIKEY" || m == "API-KEY":
		if apiKey == nil || user != nil {
			return nil, connErr("authMechanism=APIKEY needs apiKey=... and no user")
		}
		return APIKeyCredential(*apiKey), nil
	case m == "X509":
		if password != nil || apiKey != nil {
			return nil, connErr("authMechanism=X509 takes no password or apiKey")
		}
		return X509Credential(), nil
	case m == "" || m == "SCRAM-SHA-256":
		if apiKey != nil {
			return nil, connErr("apiKey is only valid with authMechanism=APIKEY")
		}
		if user == nil {
			// Without a user the string names the mechanism only; the credential is set in code.
			return nil, nil
		}
		c := &Credential{mechanism: MechanismScramSHA256, user: *user}
		if password != nil {
			c.secret, c.hasSecret = *password, true
		}
		return c, nil
	default:
		return nil, connErr("unknown authMechanism")
	}
}

// decode is strict UTF-8 percent-decoding; '+' stays a plus sign.
func decode(s, what string) (string, error) {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%':
			if i+2 >= len(s) {
				return "", connErr("invalid percent-encoding in the " + what)
			}
			n, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				return "", connErr("invalid percent-encoding in the " + what)
			}
			b = append(b, byte(n))
			i += 2
		case c <= ' ' || c == 0x7f:
			return "", connErr("whitespace or a control character in the " + what)
		default:
			b = append(b, c)
		}
	}
	if !utf8.Valid(b) {
		return "", connErr("the " + what + " is not valid percent-encoded UTF-8")
	}
	return string(b), nil
}

func boolOpt(key, v string) (bool, error) {
	switch strings.ToLower(v) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, connErr("option '" + key + "' must be true or false")
}

func intOpt(key, v string, lo, hi int) (int, error) {
	for _, r := range v {
		if r < '0' || r > '9' {
			return 0, connErr("option '" + key + "' must be an integer")
		}
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, connErr("option '" + key + "' must be an integer in " + strconv.Itoa(lo) + ".." + strconv.Itoa(hi))
	}
	return n, nil
}
