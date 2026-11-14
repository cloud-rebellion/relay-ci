#!/usr/bin/env python3
"""Validate the pinned full private context, not a substituted GitHub SHA."""
import json
from common import PRODUCT, PINS, results_directory
from binding import verify

identity = verify(initial=True)
if f"toolchain go{PINS['go']}\n" not in (PRODUCT / "go.mod").read_text():
    raise RuntimeError("Private source Go compiler differs from the trusted harness")
manifest = json.loads((PRODUCT / "frontend/scripts/frontend-tests.json").read_text())
if manifest["bunVersion"] != PINS["bun"]:
    raise RuntimeError("Private frontend registry differs from the trusted Bun pin")
(results_directory() / "source-identity.json").write_text(json.dumps(identity, indent=2) + "\n")
