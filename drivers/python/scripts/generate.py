# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""Regenerates the checked-in generated sources of the Python driver (PD-171).

- ``src/rustegon/_pb/``: protobuf messages, gRPC stubs and their ``.pyi`` type stubs from
  ``proto/rustegon/v1/*.proto`` (grpcio-tools + mypy-protobuf), with the imports moved from
  ``rustegon.v1`` into the private package ``rustegon._pb``;
- ``src/rustegon/_error_table.py``: the error table from
  ``drivers/conformance/generated/errors.json`` (PD-075).

Usage: ``python scripts/generate.py`` (writes) or ``python scripts/generate.py --check`` (exit 1
when a file differs; ``test_tc_drv_py_010_generated_sources_are_current`` runs the check).
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
REPO = HERE.parent.parent
PROTO_DIR = REPO / "proto"
ERRORS_JSON = REPO / "drivers" / "conformance" / "generated" / "errors.json"
PB_DIR = HERE / "src" / "rustegon" / "_pb"
TABLE = HERE / "src" / "rustegon" / "_error_table.py"

HEADER = "# SPDX-License-Identifier: Apache-2.0\n# Copyright The Rustegon Authors\n"


def protos() -> dict[str, str]:
    """File name -> content of the generated protobuf modules."""
    from grpc_tools import protoc  # noqa: PLC0415 - build-time dependency only

    # protoc finds the mypy-protobuf plugins on PATH: the scripts directory of this interpreter.
    scripts = Path(sys.executable).parent
    os.environ["PATH"] = f"{scripts}{os.pathsep}{os.environ.get('PATH', '')}"
    files = sorted(
        str(p.relative_to(PROTO_DIR)).replace("\\", "/") for p in (PROTO_DIR / "rustegon" / "v1").glob("*.proto")
    )
    with tempfile.TemporaryDirectory() as out:
        include = str(Path(protoc.__file__).parent / "_proto")
        args = [
            "protoc",
            f"-I{PROTO_DIR}",
            f"-I{include}",
            f"--python_out={out}",
            f"--grpc_python_out={out}",
            f"--mypy_out={out}",
            f"--mypy_grpc_out={out}",
            *files,
        ]
        if protoc.main(args) != 0:
            raise SystemExit("protoc failed")
        result: dict[str, str] = {"__init__.py": HEADER + '"""Generated protobuf and gRPC code (private)."""\n'}
        for p in sorted((Path(out) / "rustegon" / "v1").iterdir()):
            text = p.read_text(encoding="utf-8")
            # Only the imports move to the private package: the serialized descriptors and the
            # gRPC method paths keep the proto package `rustegon.v1`.
            text = text.replace("from rustegon.v1 import", "from rustegon._pb import")
            text = re.sub(r"^import rustegon\.v1\.", "import rustegon._pb.", text, flags=re.M)
            text = re.sub(r"'rustegon\.v1\.(\w+_pb2)'", r"'rustegon._pb.\1'", text)
            result[p.name] = text
        return result


def _q(s: str) -> str:
    """A double-quoted literal, as ``ruff format`` writes it (the names are ASCII)."""
    return json.dumps(s)


def table() -> str:
    """The content of ``_error_table.py``."""
    data = json.loads(ERRORS_JSON.read_text(encoding="utf-8"))
    lines = [
        HEADER,
        '"""Error table generated from drivers/conformance/generated/errors.json - do not edit.',
        "",
        "Regenerate with ``python scripts/generate.py`` (PD-075, PD-171).",
        '"""',
        "",
        "from typing import Final",
        "",
        "# code -> (name, errors-map.yaml class id, gRPC status name, catalog retryable: yes|no|depends)",
        "CODES: Final[dict[int, tuple[str, str, str, str]]] = {",
    ]
    for c in data["codes"]:
        fields = ", ".join(_q(x) for x in (c["name"], c["exception"]["id"], c["grpc"], c["retryable"]))
        lines.append(f"    {c['code']}: ({fields}),")
    lines += [
        "}",
        "",
        "# gRPC status name -> (class id, synthesized code, retryable) for failures without ErrorDetail",
        "TRANSPORT: Final[dict[str, tuple[str, int, bool]]] = {",
    ]
    for t in data["transport"]:
        lines.append(f"    {_q(t['grpc'])}: ({_q(t['exception']['id'])}, {t['code']}, {t['retryable']}),")
    lines += ["}", "", f"UNKNOWN: Final = {_q(data['unknown']['id'])}", ""]
    return "\n".join(lines)


def main() -> int:
    check = "--check" in sys.argv[1:]
    wanted: dict[Path, str] = {TABLE: table()}
    for name, text in protos().items():
        wanted[PB_DIR / name] = text
    stale = [p for p, text in wanted.items() if not p.exists() or p.read_text(encoding="utf-8") != text]
    extra = [p for p in PB_DIR.glob("*") if p.is_file() and p not in wanted] if PB_DIR.exists() else []
    if check:
        for p in stale + extra:
            print(f"stale: {p.relative_to(HERE)}")
        return 1 if stale or extra else 0
    PB_DIR.mkdir(parents=True, exist_ok=True)
    for p in extra:
        p.unlink()
    for p in stale:
        p.write_text(wanted[p], encoding="utf-8", newline="\n")
        print(f"wrote {p.relative_to(HERE)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
