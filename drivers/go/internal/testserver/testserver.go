// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

// Package testserver runs a single-node rustegond for integration tests (PD-072): `rustegon init`
// into a fresh temporary directory, then `rustegond --stop-on-stdin-eof`, which prints
// `rustegond ready grpc=… http=…` and stops gracefully when stdin closes. Binaries come from
// RUSTEGON_BIN_DIR (default <repo>/target/debug).
package testserver

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	// AdminUser is the first administrator created by the first start (PD-054).
	AdminUser = "admin"
	// ClientCertificateUser is the CN of the client certificate issued by init --client-user;
	// it logs in as x509:CN=<name>, which a test must create.
	ClientCertificateUser = "conf_x509"
	readyPrefix           = "rustegond ready "
	startTimeout          = 120 * time.Second
	stopTimeout           = 30 * time.Second
)

// Server mode switches (ADR-034, PD-191): a node serves plain text by default; `rustegon init
// --tls` writes security.tls = true (stated explicitly even though the --import-* flags of the
// TLS node imply it, so the fixture does not depend on that implication).
var (
	// TLSInitArgs are added to `rustegon init` for a TLS node.
	TLSInitArgs = []string{"--tls"}
	// PlainTextArgs are added to rustegond for a plain-text node (none: the default).
	PlainTextArgs []string
)

// Server is a running node.
type Server struct {
	binDir    string
	root      string
	plainText bool
	// GRPC and HTTP are the 127.0.0.1:port endpoints.
	GRPC, HTTP string
	// AdminPassword is the generated password of AdminUser.
	AdminPassword string

	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stderr *bytes.Buffer
}

// TLS reports whether the node serves TLS.
func (s *Server) TLS() bool { return !s.plainText }

// CAFile is the node's CA certificate (PEM).
func (s *Server) CAFile() string { return filepath.Join(s.root, "data", "certs", "ca.crt") }

// ClientCertFile is the client certificate (PEM) of ClientCertificateUser.
func (s *Server) ClientCertFile() string {
	return filepath.Join(s.root, "data", "certs", "client-"+ClientCertificateUser, "client.crt")
}

// ClientKeyFile is the key of ClientCertFile.
func (s *Server) ClientKeyFile() string {
	return filepath.Join(s.root, "data", "certs", "client-"+ClientCertificateUser, "client.key")
}

func exe(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// FindBinaries returns the binary directory, or "" and the reason when it has no binaries.
func FindBinaries() (string, string) {
	dir := os.Getenv("RUSTEGON_BIN_DIR")
	if dir == "" {
		repo := RepositoryRoot()
		if repo == "" {
			return "", "RUSTEGON_BIN_DIR is not set and the repository root was not found"
		}
		dir = filepath.Join(repo, "target", "debug")
	}
	for _, n := range []string{"rustegon", "rustegond"} {
		if _, err := os.Stat(filepath.Join(dir, exe(n))); err != nil {
			return "", fmt.Sprintf("%s not found in %s (build with `cargo build -p rustegond -p rustegon-cli` or set RUSTEGON_BIN_DIR)", exe(n), dir)
		}
	}
	return dir, ""
}

// RepositoryRoot is the directory with Cargo.toml and proto/, searched upwards from the working directory.
func RepositoryRoot() string {
	d, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		if fileExists(filepath.Join(d, "Cargo.toml")) && fileExists(filepath.Join(d, "proto")) {
			return d
		}
		p := filepath.Dir(d)
		if p == d {
			return ""
		}
		d = p
	}
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// Start initializes and starts a node; plainText starts it without TLS (TC-DRV-GO-009).
func Start(binDir string, plainText bool) (*Server, error) {
	root, err := os.MkdirTemp("", "rustegon-go-")
	if err != nil {
		return nil, err
	}
	s := &Server{binDir: binDir, root: root, plainText: plainText}
	// 24 uniform base62 characters pass the password policy (as the server's own generator).
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var pw strings.Builder
	for i := 0; i < 24; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return nil, err
		}
		pw.WriteByte(alphabet[n.Int64()])
	}
	s.AdminPassword = pw.String()
	if err := os.WriteFile(s.passwordFile(), []byte(s.AdminPassword), 0o600); err != nil {
		return nil, err
	}
	args := []string{"init", "--data-dir", s.dataDir(), "--grpc-port", "0", "--http-port", "0",
		"--admin-password-file", s.passwordFile(), "--non-interactive"}
	if !plainText {
		// The same TLS node as the .NET/Node/Python fixtures: init generates the CA, the node
		// certificate (node role as a URI SAN, ADR-035) and the client certificate of
		// ClientCertificateUser for X.509 logins.
		args = append(args, "--client-user", ClientCertificateUser)
		args = append(args, TLSInitArgs...)
	}
	cmd := command(filepath.Join(binDir, exe("rustegon")), args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("rustegon init failed: %v\n%s", err, out.String())
	}
	line, err := s.launch(nil)
	if err != nil {
		return nil, err
	}
	for _, kv := range strings.Fields(line) {
		if k, v, ok := strings.Cut(kv, "="); ok {
			switch k {
			case "grpc":
				s.GRPC = v
			case "http":
				s.HTTP = v
			}
		}
	}
	return s, nil
}

func (s *Server) dataDir() string      { return filepath.Join(s.root, "data") }
func (s *Server) passwordFile() string { return filepath.Join(s.root, "admin.pw") }

// command prepares a process that sees only the flags given here, not an operator's
// RUSTEGON_* environment.
func command(path string, args ...string) *exec.Cmd {
	cmd := exec.Command(path, args...)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(kv), "RUSTEGON_") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	return cmd
}

func (s *Server) launch(extra []string) (string, error) {
	args := []string{"--config", filepath.Join(s.dataDir(), "rustegon.toml"), "--admin-password-file", s.passwordFile(), "--stop-on-stdin-eof",
		// The smallest iteration count the configuration accepts: fast logins in debug builds.
		"--set", "auth.scram_iterations=100000", "--set", "log.stderr=false",
		// One node serves every test of a run: the suite logs in (and fails logins on purpose)
		// far more often than the default rate limits allow. 0 = unlimited (PD-098).
		"--set", "rate_limit.auth_per_ip_per_min=0", "--set", "rate_limit.auth_per_user_per_min=0",
		"--set", "rate_limit.session_per_user_per_min=0", "--set", "rate_limit.admin_per_user_per_min=0"}
	if s.plainText {
		args = append(args, PlainTextArgs...)
	} else {
		// Client certificates are requested when presented, for X.509 logins.
		args = append(args, "--set", "tls.client_cert=optional")
	}
	args = append(args, extra...)
	cmd := command(filepath.Join(s.binDir, exe("rustegond")), args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &syncWriter{w: &stderr, mu: &s.mu}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	ready := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if l := sc.Text(); strings.HasPrefix(l, readyPrefix) {
				ready <- strings.TrimPrefix(l, readyPrefix)
				break
			}
		}
		close(ready)
		_, _ = io.Copy(io.Discard, stdout)
	}()
	select {
	case line, ok := <-ready:
		if !ok {
			_ = cmd.Process.Kill()
			return "", fmt.Errorf("rustegond closed stdout before it was ready; stderr:\n%s", s.stderrText(&stderr))
		}
		s.mu.Lock()
		s.cmd, s.stdin, s.stderr = cmd, stdin, &stderr
		s.mu.Unlock()
		return line, nil
	case <-time.After(startTimeout):
		_ = cmd.Process.Kill()
		return "", fmt.Errorf("rustegond did not become ready; stderr:\n%s", s.stderrText(&stderr))
	}
}

func (s *Server) stderrText(b *bytes.Buffer) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return b.String()
}

type syncWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}

// Crash kills the node (no graceful shutdown) and keeps its data directory.
func (s *Server) Crash() error {
	s.mu.Lock()
	cmd := s.cmd
	s.mu.Unlock()
	if err := cmd.Process.Kill(); err != nil {
		return err
	}
	_ = cmd.Wait()
	return nil
}

// Restart starts the node again on the same data directory and addresses (after Crash).
func (s *Server) Restart() error {
	_, err := s.launch([]string{"--set", "listen.grpc=" + s.GRPC, "--set", "listen.http=" + s.HTTP})
	return err
}

// Stop closes stdin (graceful shutdown; killed after 30 s) and deletes the directory.
func (s *Server) Stop() error {
	s.mu.Lock()
	cmd, stdin := s.cmd, s.stdin
	s.mu.Unlock()
	_ = stdin.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-time.After(stopTimeout):
		_ = cmd.Process.Kill()
		err = errors.New("rustegond did not stop in time")
	}
	// A file still held open (antivirus, slow handle release) may leave the directory behind.
	_ = os.RemoveAll(s.root)
	return err
}
