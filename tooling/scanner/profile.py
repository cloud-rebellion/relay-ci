"""The reviewed assessment subject is closed; this is never a tag selector."""
import hashlib
from pathlib import Path

from registry import document, require
from artifact import TOOL_REFERENCE, TOOL_VERSION

IMAGE = {"repository": "clamav/clamav", "platform": "linux/amd64",
    "index_digest": "sha256:64ca916618842ba469ef38a501e6c2f42a68281c064c03749b0126c0fb085ce5",
    "manifest_digest": "sha256:b2c2f5c9a557dc1c1249e09448a84c59c3e414bb3bbbac0a9d065236c779842c",
    "config_digest": "sha256:f8ffef1c9fad7bf457d91ea84eee10883b86f810e8768bc5adc863ed4d188f6d",
    "layer_count": 6, "compressed_layer_bytes": 43306985}
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
