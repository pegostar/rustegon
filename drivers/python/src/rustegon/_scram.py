# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""SCRAM-SHA-256 client (RFC 5802/7677) without channel binding, gs2 header ``n,,`` (PD-074),
and SASLprep (RFC 4013) with the Unicode 3.2 tables of RFC 3454, as the server's ``stringprep``
crate uses them (passwords are "stored strings": unassigned code points are refused).

Pinned by ``drivers/conformance/scram/vectors.yaml`` (TC-DRV-PY-007). Secrets are never part of
an error message.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import stringprep
import unicodedata

__all__ = ["ScramClient", "ScramError", "saslprep"]

_MIN_ITERATIONS = 4096


class ScramError(ValueError):
    """The exchange failed (malformed server message or wrong server signature)."""


def saslprep(text: str) -> str:
    """RFC 4013 SASLprep of a stored string; ``ValueError`` for prohibited or unassigned input."""
    mapped = []
    for ch in text:
        # A non-ASCII space maps to SPACE before the "mapped to nothing" table: U+200B is in both.
        if stringprep.in_table_c12(ch):
            mapped.append(" ")
        elif not stringprep.in_table_b1(ch):
            mapped.append(ch)
    out = unicodedata.ucd_3_2_0.normalize("NFKC", "".join(mapped))
    for ch in out:
        if (
            stringprep.in_table_c12(ch)
            or stringprep.in_table_c21_c22(ch)
            or stringprep.in_table_c3(ch)
            or stringprep.in_table_c4(ch)
            or stringprep.in_table_c5(ch)
            or stringprep.in_table_c6(ch)
            or stringprep.in_table_c7(ch)
            or stringprep.in_table_c8(ch)
            or stringprep.in_table_c9(ch)
        ):
            raise ValueError("the password contains a character prohibited by SASLprep")
        if stringprep.in_table_a1(ch):
            raise ValueError("the password contains an unassigned code point")
    if any(stringprep.in_table_d1(ch) for ch in out):
        if any(stringprep.in_table_d2(ch) for ch in out):
            raise ValueError("the password mixes left-to-right and right-to-left text")
        if not (stringprep.in_table_d1(out[0]) and stringprep.in_table_d1(out[-1])):
            raise ValueError("right-to-left text must start and end with a right-to-left character")
    return out


def _saslname(user: str) -> str:
    return user.replace("=", "=3D").replace(",", "=2C")


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


class ScramClient:
    """One SCRAM-SHA-256 exchange: ``client_first`` -> ``client_final`` -> ``verify_server_final``."""

    def __init__(self, user: str, password: str, nonce: str | None = None) -> None:
        self._user = user
        self._password = saslprep(password)
        self._nonce = nonce or secrets.token_urlsafe(18)
        self._first_bare = f"n={_saslname(user)},r={self._nonce}"
        self._server_signature: bytes | None = None
        self.salted_password = b""

    def client_first(self) -> str:
        """``n,,n=<user>,r=<nonce>``."""
        return "n,," + self._first_bare

    def client_final(self, server_first: str) -> str:
        """The proof message for the server's challenge."""
        attrs: dict[str, str] = {}
        for part in server_first.split(","):
            if len(part) < 2 or part[1] != "=":
                raise ScramError("malformed SCRAM server-first message")
            attrs.setdefault(part[0], part[2:])
        if "m" in attrs:
            raise ScramError("unsupported SCRAM extension")
        nonce, salt_b64, iterations = attrs.get("r"), attrs.get("s"), attrs.get("i")
        if not nonce or not salt_b64 or not iterations or not nonce.startswith(self._nonce):
            raise ScramError("SCRAM server nonce or parameters invalid")
        if len(nonce) == len(self._nonce):
            raise ScramError("the server did not extend the nonce")
        try:
            salt = base64.b64decode(salt_b64, validate=True)
            count = int(iterations)
        except ValueError as e:
            raise ScramError("malformed SCRAM salt or iteration count") from e
        if count < _MIN_ITERATIONS:
            raise ScramError("SCRAM iteration count below 4096")
        salted = hashlib.pbkdf2_hmac("sha256", self._password.encode("utf-8"), salt, count)
        without_proof = f"c=biws,r={nonce}"
        auth_message = f"{self._first_bare},{server_first},{without_proof}".encode()
        client_key = _hmac(salted, b"Client Key")
        stored_key = hashlib.sha256(client_key).digest()
        signature = _hmac(stored_key, auth_message)
        proof = bytes(a ^ b for a, b in zip(client_key, signature, strict=True))
        self._server_signature = _hmac(_hmac(salted, b"Server Key"), auth_message)
        self.salted_password = salted
        return f"{without_proof},p={base64.b64encode(proof).decode()}"

    def verify_server_final(self, server_final: str) -> None:
        """Mutual authentication: the server proves it knows the stored key."""
        if self._server_signature is None:
            raise ScramError("client_final has not been sent")
        if server_final.startswith("e="):
            raise ScramError("the server refused the SCRAM exchange")
        if not server_final.startswith("v="):
            raise ScramError("malformed SCRAM server-final message")
        try:
            got = base64.b64decode(server_final[2:], validate=True)
        except ValueError as e:
            raise ScramError("malformed SCRAM server signature") from e
        if not hmac.compare_digest(got, self._server_signature):
            raise ScramError("wrong SCRAM server signature")
