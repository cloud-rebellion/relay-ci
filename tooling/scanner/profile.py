"""The reviewed assessment subject is closed; this is never a tag selector."""
import hashlib
from pathlib import Path

from registry import document, require
from artifact import TOOL_REFERENCE, TOOL_VERSION

IMAGE = {"repository": "clamav/clamav", "platform": "linux/amd64",
    "index_digest": "sha256:0f9bbc0c50dfcbaf54f6df9d4a1cc4671afb4d73555c8b84ce46a113829d1744",
    "manifest_digest": "sha256:2d901d81cbd1ed6556edfde8e20391bf81a13365d8f3ad9460d1c0340470ad89",
    "config_digest": "sha256:65c666efc694c8175057dc943f1b1bdc8efc7fbb9dacbfdda5163f4015af054f",
    "layer_count": 6, "compressed_layer_bytes": 79736974}
POLICY = {"severity": ["HIGH", "CRITICAL"], "accepted_findings": 0,
          "ignore_unfixed": False, "ignore_ids": [], "ignore_files": [], "skip_files": [],
          "vulnerability_db_maximum_age_seconds": 86400, "java_db_maximum_age_seconds": 604800}


def load(path):
    raw = Path(path).read_bytes()
    value = document(raw)
    require(set(value) == {"schema", "kind", "image", "tool", "vulnerability_policy", "source_policy_sha256",
                           "source_companion_sha256", "age", "public_base_identity"},
            "scanner-profile-closed-keys")
    require(value["schema"] == 1 and value["kind"] == "relay-public-scanner-artifact-assessment-v1",
            "scanner-profile-kind")
    require(value["image"] == IMAGE and value["vulnerability_policy"] == POLICY,
            "scanner-profile-subject-or-policy")
    require(value["tool"] == {"reference": TOOL_REFERENCE, "version": TOOL_VERSION,
                "pin_origin": "historical-tool-identity-revalidate-registry-and-runtime-in-this-run"},
            "scanner-profile-tool")
    require(value["source_policy_sha256"] == "20e2351806c6dd55b60a0589b53cbba0fc4fd4d256e589e6397e9850da513d2f"
            and value["source_companion_sha256"] == "7ae8c304f263099ba236634ac68f076c14034d4564773e8951d0e89586b90913",
            "scanner-profile-held-policy")
    require(value["public_base_identity"] == {
        "commit": "ecb76187a2851abe163f3a501e22dcde3264184c",
        "tree": "f7eaf16d828a4c3eb4a9f0f9dccfd7f3a94bcdc7"}, "scanner-profile-public-base")
    age = value["age"]
    require(age == {"version": "1.3.2", "archive_sha256": "cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10",
        "binary_sha256": None,
        "linux_amd64_archive_url": "https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-linux-amd64.tar.gz",
        "recipient": "age124v20atmxg6n4wf20z7v238mz3e68asqpe83nwmrnxvvsw49yausfdf67d"}, "scanner-profile-encryption")
    return value, hashlib.sha256(raw).hexdigest()
