# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
"""TC-DRV-PY-017: the retry policy against the fake server of retry.yaml (PD-073, R1-R8)."""

from __future__ import annotations

from tests.fake_server import run_retry_scenarios


async def test_tc_drv_py_017_retry_scenarios_on_the_fake_server() -> None:
    assert await run_retry_scenarios() == []
