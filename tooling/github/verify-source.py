#!/usr/bin/env python3
"""Validate the pinned full private context, not a substituted GitHub SHA."""
import json
from common import PRODUCT, PINS, results_directory
from binding import ACTIVE_GO_VERSION, compiler_contract, verify

identity = verify(initial=True)
if PINS['go'] != ACTIVE_GO_VERSION:
    raise RuntimeError("The active compiler pin must remain exactly Go 1.26.11")
identity['compiler_contract'] = compiler_contract(PRODUCT)
manifest = json.loads((PRODUCT / "frontend/scripts/frontend-tests.json").read_text())
if manifest["bunVersion"] != PINS["bun"]:
    raise RuntimeError("Private frontend registry differs from the trusted Bun pin")
(results_directory() / "source-identity.json").write_text(json.dumps(identity, indent=2) + "\n")
