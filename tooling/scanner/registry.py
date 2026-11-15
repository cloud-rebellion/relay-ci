"""Anonymous, fixed-repository OCI custody. No target image is executed.

Authorization and signed redirect URLs stay in memory and are never diagnostic
fields. Callers must put all output in the owned hard-bounded filesystem.
"""
import hashlib
import json
from pathlib import Path
import re
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
MANIFEST_TYPES = {"application/vnd.oci.image.manifest.v1+json",
                  "application/vnd.docker.distribution.manifest.v2+json"}
INDEX_TYPES = {"application/vnd.oci.image.index.v1+json",
               "application/vnd.docker.distribution.manifest.list.v2+json"}
CONFIG_TYPES = {"application/vnd.oci.image.config.v1+json",
                "application/vnd.docker.container.image.v1+json"}
LAYER_TYPES = {"application/vnd.oci.image.layer.v1.tar+gzip",
               "application/vnd.docker.image.rootfs.diff.tar.gzip"}
ATTESTATION_TYPE = "application/vnd.in-toto+json"
CDN_HOSTS = {"production.cloudflare.docker.com", "production.cloudfront.docker.com",
             "docker-images-prod.s3.dualstack.us-east-1.amazonaws.com"}


class Refusal(RuntimeError):
    """Only fixed, non-sensitive error codes may cross the driver boundary."""


def require(condition, code):
    if not condition:
        raise Refusal(code)


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate-json-key")
            result[key] = value
        return result
    try:
        result = json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError):
        raise Refusal("invalid-json") from None
    require(isinstance(result, dict), "json-object-required")
    return result


def descriptor(value, types, maximum):
    require(isinstance(value, dict) and value.get("mediaType") in types,
            "descriptor-media-type")
    require(DIGEST.fullmatch(value.get("digest", "")) is not None,
            "descriptor-digest")
    size = value.get("size")
    require(type(size) is int and 0 < size <= maximum, "descriptor-size")
    # Foreign URLs would change the authorized source boundary.
    require(not value.get("urls") and not value.get("data"), "descriptor-external-source")
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


class Registry:
    def __init__(self, repository, *, opener=None, max_bytes=160 << 20):
        require(repository in {"clamav/clamav", "aquasec/trivy"}, "registry-repository")
        self.repository = repository
        self.base = "https://registry-1.docker.io/v2/" + repository
        self.opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.maximum = max_bytes
        self.total = 0
        self.requests = 0
        self.started = time.monotonic()
        self.token = None
        self.receipts = []
        self.refused_routes = []

    def _refused_route(self, parts):
        host = parts.hostname or ""
        fqdn = (len(host) <= 253 and host.isascii() and
                re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?", host)
                and not re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", host))
        try:
            port = parts.port
        except ValueError:
            port = "invalid"
        if port is None:
            port = 443 if parts.scheme == "https" else 80 if parts.scheme == "http" else "invalid"
        if type(port) is not int or not 1 <= port <= 65535:
            port = "invalid"
        if len(self.refused_routes) < 4:
            self.refused_routes.append({"hostname": host if fqdn else "invalid",
                "scheme": parts.scheme if parts.scheme in {"http", "https"} else "other",
                "port": port, "credentials_present": bool(parts.username or parts.password)})

    def _open(self, url, *, auth=False, cdn=False):
        parts = urllib.parse.urlsplit(url)
        allowed = CDN_HOSTS if cdn else {"registry-1.docker.io", "auth.docker.io"}
        try:
            port = parts.port
        except ValueError:
            port = "invalid"
        if not (parts.scheme == "https" and parts.hostname in allowed and
                not parts.username and not parts.password and port in (None, 443)):
            self._refused_route(parts)
            raise Refusal("registry-host")
        self.requests += 1
        require(self.requests <= 48 and time.monotonic() - self.started <= 900,
                "registry-request-budget")
        headers = {"Accept-Encoding": "identity", "User-Agent": "Relay-scanner-assessment/1",
                   "Accept": ",".join(sorted(MANIFEST_TYPES | INDEX_TYPES))}
        if auth:
            require(not cdn and parts.hostname == "registry-1.docker.io" and self.token,
                    "registry-authorization-boundary")
            headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            response = self.opener.open(request, timeout=45)
        except urllib.error.HTTPError as error:
            if auth and error.code in {301, 302, 303, 307, 308} and "/blobs/sha256:" in parts.path:
                location = error.headers.get("Location", "")
                error.close()
                # Never forward the registry bearer or save the signed URL.
                return self._open(location, cdn=True)
            error.close()
            raise Refusal("registry-http-status") from None
        except (OSError, urllib.error.URLError):
            raise Refusal("registry-transport") from None
        require(response.status == 200, "registry-http-status")
        return response

    def _read(self, url, maximum, *, auth=False, target=None, digest=None):
        raw = bytearray() if target is None else None
        count = 0
        checksum = hashlib.sha256()
        handle = target.open("xb") if target is not None else None
        try:
            with self._open(url, auth=auth) as response:
                encoding = response.headers.get("Content-Encoding", "identity")
                require(encoding == "identity", "registry-content-encoding")
                declared = response.headers.get("Content-Length")
                require(declared is None or declared.isdecimal() and int(declared) <= maximum,
                        "registry-content-length")
                while block := response.read(min(1 << 20, maximum - count + 1)):
                    count += len(block)
                    self.total += len(block)
                    require(count <= maximum and self.total <= self.maximum, "registry-byte-budget")
                    checksum.update(block)
                    if handle:
                        handle.write(block)
                    else:
                        raw.extend(block)
                require(declared is None or count == int(declared), "registry-truncated-response")
        finally:
            if handle:
                handle.close()
        actual = "sha256:" + checksum.hexdigest()
        require(digest is None or actual == digest, "registry-content-digest")
        return bytes(raw) if raw is not None else {"digest": actual, "bytes": count}

    def authorize(self):
        require(self.token is None, "registry-authorization-repeated")
        query = urllib.parse.urlencode({"service": "registry.docker.io",
                                       "scope": "repository:" + self.repository + ":pull"})
        value = document(self._read("https://auth.docker.io/token?" + query, 32768))
        token = value.get("token", value.get("access_token"))
        require(isinstance(token, str) and 0 < len(token) <= 16384 and
                not any(x.isspace() for x in token), "anonymous-authorization-shape")
        self.token = token

    def get(self, kind, digest, *, maximum=1 << 20, target=None):
        require(kind in {"manifests", "blobs"} and DIGEST.fullmatch(digest) is not None,
                "registry-fixed-digest-required")
        result = self._read(self.base + "/" + kind + "/" + digest, maximum,
                            auth=True, target=target, digest=digest)
        self.receipts.append({"kind": kind, "digest": digest,
                              "bytes": len(result) if isinstance(result, bytes) else result["bytes"]})
        return result

    def close(self):
        self.token = None


def select_image(index, expected):
    require(index.get("schemaVersion") == 2 and index.get("mediaType") in INDEX_TYPES,
            "oci-index-shape")
    entries = index.get("manifests")
    require(isinstance(entries, list) and 0 < len(entries) <= 32, "oci-index-count")
    require(len({x.get("digest") for x in entries}) == len(entries), "oci-index-duplicate")
    candidates = [x for x in entries if x.get("platform", {}).get("os") == "linux" and
                  x.get("platform", {}).get("architecture") == "amd64"]
    require(len(candidates) == 1, "oci-amd64-not-unique")
    selected = descriptor(candidates[0], MANIFEST_TYPES, 1 << 20)
    require(selected["digest"] == expected, "oci-platform-digest")
    attestations = [descriptor(x, MANIFEST_TYPES, 1 << 20) for x in entries
                    if x.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest"
                    and x.get("annotations", {}).get("vnd.docker.reference.digest") == expected]
    require(0 < len(attestations) <= 4, "oci-attestation-descriptors-missing")
    return selected, attestations


def inspect_attestation(raw, expected_subject):
    value = document(raw)
    require(value.get("_type") in {"https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1"},
            "attestation-statement-type")
    subjects = value.get("subject")
    require(DIGEST.fullmatch(expected_subject) is not None, "attestation-subject-target")
    require(isinstance(subjects, list) and 0 < len(subjects) <= 32, "attestation-subject-count")
    names = set()
    for subject in subjects:
        require(isinstance(subject, dict), "attestation-subject-type")
        name = subject.get("name")
        require(isinstance(name, str) and name and
                not any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in name) and
                len(name.encode("utf-8")) <= 4096, "attestation-subject-name")
        require(name not in names, "attestation-subject-duplicate-name")
        names.add(name)
        require(subject.get("digest") == {"sha256": expected_subject[7:]}, "attestation-subject")
    predicate_type = value.get("predicateType")
    require(predicate_type in {"https://slsa.dev/provenance/v0.2", "https://slsa.dev/provenance/v1",
                               "https://spdx.dev/Document"}, "attestation-predicate-type")
    require(isinstance(value.get("predicate"), dict), "attestation-predicate")
    predicate = value["predicate"]
    materials = predicate.get("materials", predicate.get("buildDefinition", {}).get("resolvedDependencies", []))
    require(isinstance(materials, list) and len(materials) <= 128, "attestation-material-count")
    git_materials = []
    for material in materials:
        require(isinstance(material, dict), "attestation-material-shape")
        uri = material.get("uri", "")
        hashes = material.get("digest", {})
        if isinstance(uri, str) and (uri.startswith("git+") or "github.com/" in uri):
            require(len(uri) <= 4096 and isinstance(hashes, dict) and len(hashes) <= 8,
                    "attestation-source-material-shape")
            # These are untrusted upstream assertions, not signed source proof.
            git_materials.append({"uri": uri, "digest": hashes})
    # Content-addressed registry linkage is verified, publisher signature/trust is
    # not invented. An unsigned statement can never authorize full acceptance.
    return {"predicate_type": predicate_type, "subject_verified": True,
            "subject_count": len(subjects),
            "publisher_signature_verified": False, "statement_sha256": sha(raw),
            "asserted_git_materials": git_materials}


def materialize(registry, profile, destination):
    """Fetch exact OCI blobs and return a single-image OCI *directory* for Trivy.

    Trivy 0.74.0 pkg/fanal/image/oci.go supports OCI directories; its archive
    reader is not assumed to support an OCI tar. A separate canonical tar is
    made for bounded custody after the scan, never used as a different image.
    """
    destination.mkdir(mode=0o700)
    blobs = destination / "blobs/sha256"
    blobs.mkdir(parents=True, mode=0o700)
    image = profile["image"]
    index_raw = registry.get("manifests", image["index_digest"])
    selected, attestations = select_image(document(index_raw), image["manifest_digest"])
    manifest_raw = registry.get("manifests", selected["digest"], maximum=selected["size"])
    require(len(manifest_raw) == selected["size"], "oci-manifest-size")
    manifest = document(manifest_raw)
    require(manifest.get("schemaVersion") == 2 and manifest.get("mediaType") in MANIFEST_TYPES,
            "oci-manifest-shape")
    config = descriptor(manifest.get("config"), CONFIG_TYPES, 256 << 10)
    require(config["digest"] == image["config_digest"], "oci-config-digest")
    config_raw = registry.get("blobs", config["digest"], maximum=config["size"])
    require(len(config_raw) == config["size"], "oci-config-size")
    config_value = document(config_raw)
    require(config_value.get("os") == "linux" and config_value.get("architecture") == "amd64",
            "oci-config-platform")
    layers = manifest.get("layers")
    require(isinstance(layers, list) and len(layers) == image["layer_count"], "oci-layer-count")
    for layer in layers:
        descriptor(layer, LAYER_TYPES, 128 << 20)
    require(len({x["digest"] for x in layers}) == len(layers) and
            sum(x["size"] for x in layers) == image["compressed_layer_bytes"], "oci-layer-closure")
    require(config_value.get("rootfs", {}).get("type") == "layers" and
            len(config_value.get("rootfs", {}).get("diff_ids", [])) == len(layers), "oci-rootfs-closure")
    for digest, raw in ((selected["digest"], manifest_raw), (config["digest"], config_raw)):
        (blobs / digest[7:]).write_bytes(raw)
    for layer in layers:
        receipt = registry.get("blobs", layer["digest"], maximum=layer["size"],
                               target=blobs / layer["digest"][7:])
        require(receipt["bytes"] == layer["size"], "oci-layer-size")
    statements = []
    attestation_root = destination.parent / "attestations"
    attestation_root.mkdir(mode=0o700)
    for entry in attestations:
        raw = registry.get("manifests", entry["digest"], maximum=entry["size"])
        require(len(raw) == entry["size"], "attestation-manifest-size")
        value = document(raw)
        require(value.get("schemaVersion") == 2 and value.get("mediaType") in MANIFEST_TYPES,
                "attestation-manifest-shape")
        (attestation_root / (entry["digest"][7:] + ".manifest.json")).write_bytes(raw)
        att_config = descriptor(value.get("config"), CONFIG_TYPES, 256 << 10)
        att_config_raw = registry.get("blobs", att_config["digest"], maximum=att_config["size"])
        require(len(att_config_raw) == att_config["size"], "attestation-config-size")
        (attestation_root / (att_config["digest"][7:] + ".config.json")).write_bytes(att_config_raw)
        items = value.get("layers")
        require(isinstance(items, list) and 0 < len(items) <= 4, "attestation-layer-count")
        for layer in items:
            descriptor(layer, {ATTESTATION_TYPE}, 16 << 20)
            raw = registry.get("blobs", layer["digest"], maximum=layer["size"])
            require(len(raw) == layer["size"], "attestation-layer-size")
            statements.append(inspect_attestation(raw, image["manifest_digest"]))
            (attestation_root / (layer["digest"][7:] + ".json")).write_bytes(raw)
    require(any(x["predicate_type"].startswith("https://slsa.dev/provenance/") for x in statements)
            and any(x["predicate_type"] == "https://spdx.dev/Document" for x in statements),
            "attestation-provenance-or-sbom-missing")
    (destination / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}\n')
    (destination / "index.json").write_text(json.dumps({"schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [selected]},
        sort_keys=True, separators=(",", ":")) + "\n")
    return {"manifest_digest": selected["digest"], "config_digest": config["digest"],
            "layer_count": len(layers), "compressed_layer_bytes": sum(x["size"] for x in layers),
            "attestations": statements, "source_signature_trust": "unverified-blocks-full-acceptance"}
