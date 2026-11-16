# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""A real ``rustegond`` for integration and conformance tests (PD-072): the same fixture as the
.NET and Java drivers. Binaries ``rustegon`` and ``rustegond`` come from ``RUSTEGON_BIN_DIR``
(default ``<repo>/target/debug``); without them the calling test is skipped, or fails under
``CI=true`` so CI cannot skip the integration tests silently.

The TLS node of the suite is ``rustegon init --tls`` (ADR-034): a CA, a node certificate for
127.0.0.1 and a client certificate for ``x509:CN=conf_x509``; the plain-text node (the ADR-034
default) is a plain ``rustegon init``. ``rustegond`` runs with the smallest SCRAM iteration
count, optional client certificates (TLS only) and the four rate limits at 0 (PD-098), and stops
when its stdin closes. The administrator is ``admin`` with a random password; no secret is
printed.
"""

from __future__ import annotations

import atexit
import os
import secrets
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Final

import pytest

from rustegon import ClientSettings, Credential

ADMIN_USER: Final = "admin"
X509_USER: Final = "conf_x509"
_READY: Final = "rustegond ready "
_START_TIMEOUT: Final = 90.0
REPO: Final = Path(__file__).resolve().parents[3]


def _exe(name: str) -> str:
    return name + ".exe" if sys.platform == "win32" else name


def bin_dir() -> Path:
    return Path(os.environ.get("RUSTEGON_BIN_DIR") or REPO / "target" / "debug")


def _scrubbed_env() -> dict[str, str]:
    """The child must not inherit this machine's RUSTEGON_* configuration."""
    return {k: v for k, v in os.environ.items() if not k.upper().startswith("RUSTEGON_")}


class TestServer:
    """One running node; ``tls`` False starts it in plain text (the ADR-034 default)."""

    __test__ = False  # not a pytest class

    def __init__(self, tls: bool) -> None:
        cli, daemon = bin_dir() / _exe("rustegon"), bin_dir() / _exe("rustegond")
        self.tls = tls
        self.root = Path(tempfile.mkdtemp(prefix="rustegon-python-it-"))
        self.data_dir = self.root / "data"
        self.admin_password = secrets.token_urlsafe(18) + "-Aa1"
        password_file = self.root / "admin-password"
        password_file.write_text(self.admin_password, encoding="utf-8")
        init = [
            str(cli),
            "init",
            "--data-dir",
            str(self.data_dir),
            "--grpc-port",
            "0",
            "--http-port",
            "0",
            "--admin-password-file",
            str(password_file),
            # ADR-034: init writes a plain-text node unless --tls asks for the CA, node and client certificates.
            *(("--tls", "--client-user", X509_USER) if tls else ()),
            "--non-interactive",
        ]
        r = subprocess.run(
            init,
            cwd=self.root,
            env=_scrubbed_env(),
            capture_output=True,
            text=True,
            timeout=_START_TIMEOUT,
            check=False,
        )
        if r.returncode != 0:
            raise RuntimeError(f"rustegon init failed: {r.stdout}{r.stderr}")
        cmd = [
            str(daemon),
            "--config",
            str(self.data_dir / "rustegon.toml"),
            "--admin-password-file",
            str(password_file),
            "--stop-on-stdin-eof",
            *(("--set", "tls.client_cert=optional") if tls else ()),
            *(
                [
                    "--set",
                    "auth.scram_iterations=100000",
                    "--set",
                    "log.stderr=false",
                    "--set",
                    "listen.shutdown_grace_secs=5",
                ]
            ),
            # PD-098: one node serves the whole run from one address; 0 = unlimited (test node only).
            *(["--set", "rate_limit.auth_per_ip_per_min=0", "--set", "rate_limit.auth_per_user_per_min=0"]),
            *(["--set", "rate_limit.session_per_user_per_min=0", "--set", "rate_limit.admin_per_user_per_min=0"]),
        ]
        self._stderr = (self.root / "rustegond.stderr").open("wb")
        self.process = subprocess.Popen(
            cmd,
            cwd=self.root,
            env=_scrubbed_env(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._stderr,
            text=True,
        )
        ready: list[str] = []
        event = threading.Event()

        def read() -> None:
            assert self.process.stdout is not None
            for line in self.process.stdout:
                if line.startswith(_READY):
                    ready.append(line[len(_READY) :].strip())
                    event.set()
            event.set()

        threading.Thread(target=read, daemon=True).start()
        if not event.wait(_START_TIMEOUT) or not ready:
            self.process.kill()
            raise RuntimeError(f"rustegond did not become ready: {(self.root / 'rustegond.stderr').read_text()}")
        grpc = next(kv[len("grpc=") :] for kv in ready[0].split() if kv.startswith("grpc="))
        self.host, _, port = grpc.rpartition(":")
        self.port = int(port)

    @property
    def ca_file(self) -> Path:
        return self.data_dir / "certs" / "ca.crt"

    @property
    def client_cert_file(self) -> Path:
        return self.data_dir / "certs" / f"client-{X509_USER}" / "client.crt"

    @property
    def client_key_file(self) -> Path:
        return self.data_dir / "certs" / f"client-{X509_USER}" / "client.key"

    def settings(self, credential: Credential, **kw: Any) -> ClientSettings:
        """Settings for this node: its endpoint, its CA when TLS is on, the given credential."""
        tls: dict[str, Any] = {"tls": True, "tls_ca_file": str(self.ca_file)} if self.tls else {}
        return ClientSettings(
            hosts=[(self.host, self.port)],
            credential=credential,
            application_name="rustegon-python-tests",
            **tls,
            **kw,
        )

    def admin_settings(self, **kw: Any) -> ClientSettings:
        return self.settings(Credential.scram(ADMIN_USER, self.admin_password), **kw)

    def stop(self) -> None:
        """Closes stdin (graceful shutdown) and waits for the exit."""
        if self.process.poll() is None:
            try:
                assert self.process.stdin is not None
                self.process.stdin.close()
                self.process.wait(30)
            except (OSError, subprocess.TimeoutExpired):
                self.process.kill()
        self._stderr.close()


_shared: TestServer | None = None
_unavailable: str | None = None


def start(tls: bool) -> TestServer:
    """A new node, or skip (fail under CI=true) when the binaries are missing."""
    missing = [p for p in (bin_dir() / _exe("rustegon"), bin_dir() / _exe("rustegond")) if not p.is_file()]
    if missing:
        reason = f"rustegon/rustegond not found in {bin_dir()} (build them, or set RUSTEGON_BIN_DIR)"
        if os.environ.get("CI", "").lower() == "true":
            pytest.fail(f"integration tests need the server: {reason}")
        pytest.skip(f"integration test skipped: {reason}")
    server = TestServer(tls)
    atexit.register(server.stop)
    return server


def shared() -> TestServer:
    """The TLS node of the run (conformance suite and integration tests), started on first use."""
    global _shared, _unavailable
    if _shared is None:
        if _unavailable is not None:
            pytest.skip(_unavailable)
        try:
            _shared = start(tls=True)
        except pytest.skip.Exception as e:
            _unavailable = str(e)
            raise
    return _shared
