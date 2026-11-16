#!/usr/bin/env python3
"""Tests version_ok of scripts/mcp-smoke.py: what `praetore-mcp --version`
may print for a crate version, release, dev and prerelease (rc) alike.

    python3 -I scripts/test-mcp-smoke-version.py
"""

import importlib.util
import os
import sys

path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp-smoke.py")
spec = importlib.util.spec_from_file_location("mcp_smoke", path)
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)

ACCEPTED = [
    ("0.3.6", "praetore-mcp 0.3.6\n"),
    ("0.3.6", "praetore-mcp 0.3.6-dev\n"),
    ("0.3.6", "praetore-mcp 0.3.6-dev+abc1234\n"),
    ("0.3.6", "praetore-mcp 0.3.6-dev+" + "a" * 40 + "\n"),
    ("0.3.7-rc.1", "praetore-mcp 0.3.7-rc.1\n"),
    ("0.3.7-rc.1", "praetore-mcp 0.3.7-rc.1-dev\n"),
    ("0.3.7-rc.1", "praetore-mcp 0.3.7-rc.1-dev+abc1234\n"),
]
REFUSED = [
    ("0.3.6", "praetore-mcp 0.3.5\n"),
    ("0.3.6", "praetore-mcp 0.3.60\n"),
    ("0.3.6", "praetore-mcp 0x3x6\n"),
    ("0.3.6", "praetore-mcp 0.3.6"),
    ("0.3.6", "praetore-mcp 0.3.6-dev+abc12\n"),
    ("0.3.6", "praetore-mcp 0.3.6-dev+ABC1234\n"),
    ("0.3.6", "praetore-mcp 0.3.6-dev+" + "a" * 41 + "\n"),
    ("0.3.6", "praetore-mcp 0.3.6+abc1234\n"),
    ("0.3.6", "praetore-mcp 0.3.6-rc.1\n"),
    ("0.3.6", "praetore 0.3.6\n"),
    ("0.3.7-rc.1", "praetore-mcp 0.3.7\n"),
    ("0.3.7-rc.1", "praetore-mcp 0.3.7-rc.2\n"),
    ("0.3.7-rc.1", "praetore-mcp 0.3.7-dev+abc1234\n"),
]

failures = 0
for expected, printed in ACCEPTED:
    if not smoke.version_ok(printed, expected):
        failures += 1
        print(f"FAIL: {printed!r} should match {expected}")
for expected, printed in REFUSED:
    if smoke.version_ok(printed, expected):
        failures += 1
        print(f"FAIL: {printed!r} should not match {expected}")
print(f"{len(ACCEPTED) + len(REFUSED) - failures} of {len(ACCEPTED) + len(REFUSED)} cases pass")
sys.exit(1 if failures else 0)
