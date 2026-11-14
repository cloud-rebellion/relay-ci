#!/usr/bin/env python3
"""Validate original go test -json output without turning skips into passes."""
import json
from pathlib import Path
import sys

INVITATION_REQUIREMENTS = [
    "TestInvitationEncodedTokenJourneyLive",
    "TestInvitationEncodedTokenJourneyLive/new_identity",
    "TestInvitationEncodedTokenJourneyLive/existing_identity_keeps_password_and_MFA",
    "TestAcceptOrganizationInviteSerializesMembershipLimitLive",
    "TestAcceptOrganizationInviteCannotReactivateEstablishedIdentityLive",
]


def validate(events, exit_code, required=(), allow_no_tests=False):
    if exit_code != 0:
        raise ValueError("Go test process failed")
    outcomes = {}
    package_outcomes = []
    for event in events:
        action, name = event.get("Action"), event.get("Test")
        if action == "fail":
            raise ValueError("Go package or test failed")
        if name and action in ("pass", "skip"):
            if action == "skip":
                raise ValueError(f"Go test or subtest skipped: {name}")
            key = (event["Package"], name)
            if key in outcomes:
                raise ValueError("Duplicate Go test outcome")
            outcomes[key] = action
        if not name and action in ("pass", "skip"):
            package_outcomes.append(action)
    if len(package_outcomes) != 1:
        raise ValueError("Missing or duplicate terminal package PASS")
    # Only a go-list-proven package without test files may have no cases.
    if not outcomes and not (allow_no_tests and package_outcomes == ["skip"]):
        raise ValueError("Go package produced zero passing test outcomes")
    if outcomes and package_outcomes != ["pass"]:
        raise ValueError("Go package did not terminate with PASS")
    names = [name for _, name in outcomes]
    for name in required:
        if names.count(name) != 1:
            raise ValueError(f"Required real invitation outcome missing: {name}")
    return len(outcomes)


if __name__ == "__main__":
    events = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines() if line.strip()]
    required = INVITATION_REQUIREMENTS if "--require-invitation" in sys.argv[3:] else []
    print(f"Validated {validate(events, int(sys.argv[2]), required, '--allow-no-tests' in sys.argv[3:])} Go test/subtest outcomes")
