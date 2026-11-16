// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package scram

import (
	"errors"
	"strings"
	"testing"
)

// TC-DRV-GO-003: shared SCRAM/SASLprep conformance vectors (README 00a77 checkScramVectors).
func TestTCDrvGo003ScramVectors(t *testing.T) {
	if err := CheckVectors("../../../conformance/scram/vectors.yaml"); err != nil {
		t.Fatal(err)
	}
}

func TestSASLPrepEdgeCases(t *testing.T) {
	ok := []struct{ name, in, want string }{
		{"mapped to nothing", "a\U000000AD\U0000200C\U0000200D\U00002060\U0000FE0F\U0000FEFFb", "ab"},
		{"non-ASCII spaces", "a\U00001680b\U00002003c\U0000202Fd\U0000205Fe", "a b c d e"},
		{"all mapped away", "\U000000AD\U0000FEFF", ""},
		{"RTL only", "\U00000627\U00000628", "\U00000627\U00000628"},
		{"RTL with neutral inside", "\U000006271\U00000628", "\U000006271\U00000628"},
		{"supplementary letter", "\U0001D400", "A"}, // MATHEMATICAL BOLD CAPITAL A, NFKC
	}
	for _, c := range ok {
		got, err := SASLPrep(c.in)
		if err != nil || got != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.name, got, err, c.want)
		}
	}
	bad := []struct{ name, in string }{
		{"ASCII control", "a\x7fb"},
		{"C.2.2 control", "a\u0085b"},
		{"private use", "a\U0000E000"},
		{"non-character", "a\U0000FFFF"},
		{"C.8 direction mark", "a\U0000200Eb"},
		{"C.9 tag", "a\U000E0001"},
		{"unassigned in 3.2", "a\U00000221"},
		{"unassigned tag-plane gap", "a\U000E0002"},
		{"bidi mixed L and R", "\U00000627a\U00000628"},
		{"bidi R not last", "\U000006271"},
		{"bidi R not first", "1\U00000627"},
		{"invalid UTF-8", "a\xffb"},
	}
	for _, c := range bad {
		if got, err := SASLPrep(c.in); err == nil {
			t.Errorf("%s: accepted as %q", c.name, got)
		} else if strings.Contains(err.Error(), c.in) && c.in != "" {
			t.Errorf("%s: error leaks the input", c.name)
		}
	}
}

const (
	testNonce = "1cDoP0b4fGrS3e7iJuV6hAlM"
	testSalt  = "c2FsdC0wMTIzNDU2Nzg5YWI="
)

func TestProcessServerFirstRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"wrong nonce prefix":     "r=XXXXP0b4fGrS3e7iJuV6hAlMserver,s=" + testSalt + ",i=4096",
		"nonce not extended":     "r=" + testNonce + ",s=" + testSalt + ",i=4096",
		"non-printable nonce":    "r=" + testNonce + "a b,s=" + testSalt + ",i=4096",
		"iterations too low":     "r=" + testNonce + "srv,s=" + testSalt + ",i=4095",
		"iterations too high":    "r=" + testNonce + "srv,s=" + testSalt + ",i=10000001",
		"iterations signed":      "r=" + testNonce + "srv,s=" + testSalt + ",i=+4096",
		"iterations not numeric": "r=" + testNonce + "srv,s=" + testSalt + ",i=abc",
		"iterations overflow":    "r=" + testNonce + "srv,s=" + testSalt + ",i=99999999999999999999999",
		"missing iterations":     "r=" + testNonce + "srv,s=" + testSalt,
		"attributes reordered":   "s=" + testSalt + ",r=" + testNonce + "srv,i=4096",
		"extra attribute":        "r=" + testNonce + "srv,s=" + testSalt + ",i=4096,x=1",
		"empty salt":             "r=" + testNonce + "srv,s=,i=4096",
		"bad base64 salt":        "r=" + testNonce + "srv,s=c2Fsd!==,i=4096",
		"unpadded salt":          "r=" + testNonce + "srv,s=c2FsdA,i=4096",
		"server error":           "e=other-error",
		"too long":               "r=" + testNonce + strings.Repeat("x", 5000) + ",s=" + testSalt + ",i=4096",
	}
	for name, sf := range cases {
		c, err := NewClientWithNonce("u", "p", testNonce)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.ProcessServerFirst(sf); !errors.Is(err, ErrAuthenticationFailed) {
			t.Errorf("%s: got %v, want ErrAuthenticationFailed", name, err)
		}
	}
}

func TestProcessServerFirstRejectsInvalidPassword(t *testing.T) {
	c, _ := NewClientWithNonce("u", "hunter2\u0007", testNonce)
	_, err := c.ProcessServerFirst("r=" + testNonce + "srv,s=" + testSalt + ",i=4096")
	if !errors.Is(err, ErrAuthenticationFailed) || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyServerFinal(t *testing.T) {
	if err := (&Client{}).VerifyServerFinal("v=AAAA"); err == nil {
		t.Error("accepted before server-first")
	}
	c, _ := NewClientWithNonce("u", "p", testNonce)
	if _, err := c.ProcessServerFirst("r=" + testNonce + "srv,s=" + testSalt + ",i=4096"); err != nil {
		t.Fatal(err)
	}
	for _, sf := range []string{"e=invalid-proof", "", "x=abc", "v=", "v=not-base64!", "v=AAAA"} {
		err := c.VerifyServerFinal(sf)
		if !errors.Is(err, ErrAuthenticationFailed) {
			t.Errorf("%q: got %v", sf, err)
		}
	}
	if err := c.VerifyServerFinal("e=invalid-proof"); !strings.Contains(err.Error(), "invalid-proof") {
		t.Errorf("server error not surfaced: %v", err)
	}
}

func TestNewClientNonce(t *testing.T) {
	a, err := NewClient("app,user", "pw")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewClient("app,user", "pw")
	if a.clientNonce == b.clientNonce || len(a.clientNonce) != nonceLength ||
		strings.Trim(a.clientNonce, base62) != "" {
		t.Errorf("bad nonces %q %q", a.clientNonce, b.clientNonce)
	}
	if want := "n,,n=app=2Cuser,r=" + a.clientNonce; a.ClientFirst() != want {
		t.Errorf("clientFirst %q", a.ClientFirst())
	}
	if _, err := NewClientWithNonce("u", "p", "bad,nonce"); err == nil {
		t.Error("accepted a nonce with a comma")
	}
}
