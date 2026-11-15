"""Ordinary ZIP32 quota/CSV observations; no outcome is acceptance evidence."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import zipfile

from daemon_policy import CONFIG, MARKER, REFERENCE
from registry import require
from zip_diagnostics import response_kind

MIB = 1 << 20
CONTROL_COUNT = 3
NAMES = ("zip32-individual-size", "zip32-expanded-size", "zip32-recursion",
         "zip32-file-count", "csv24-near-ceiling")
ARCHIVE_LIMIT = 4 * MIB
TOTAL_COMPRESSED_LIMIT = 16 * MIB


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def seed_blocks(name, size):
    require(type(size) is int and 0 < size <= 26 * MIB, "zip32-observation-member-bound")
    seed = b"Relay harmless ordinary ZIP32 member " + name.encode("ascii") + b"\n"
    for start in range(0, size, 65536):
        count = min(65536, size - start)
        yield (seed * (count // len(seed) + 1))[:count]


def prove_zip32(path, expected):
    """Check actual local/central headers and independently decode every member."""
    meta = Path(path).lstat()
    require(stat.S_ISREG(meta.st_mode) and not Path(path).is_symlink() and meta.st_uid == os.getuid()
            and meta.st_nlink == 1 and 0 < meta.st_size <= ARCHIVE_LIMIT,
            "zip32-observation-owned-archive-bound-before-read")
    raw = Path(path).read_bytes()
    require(0 < len(raw) <= ARCHIVE_LIMIT and MARKER not in raw and len(raw) >= 22
            and raw[-22:-18] == b"PK\x05\x06", "zip32-observation-wire-bound")
    end = struct.unpack_from("<4s4H2LH", raw, len(raw) - 22)
    require(1 <= len(expected) <= 10001 and end[1:5] == (0, 0, len(expected), len(expected))
            and end[7] == 0 and end[6] + end[5] == len(raw) - 22,
            "zip32-observation-EOCD-count-offset-bound")
    local_offset = 0
    central_offset = end[6]
    header_digest = hashlib.sha256()
    metadata_digest = hashlib.sha256()
    samples = []
    for index, (name, size, fingerprint) in enumerate(expected):
        require(type(name) is str and re.fullmatch(r"[A-Za-z0-9.-]{1,80}", name) is not None
                and type(size) is int and 0 < size <= 26 * MIB
                and re.fullmatch(r"[0-9a-f]{64}", fingerprint) is not None,
                "zip32-observation-expected-member-bound")
        require(local_offset + 30 <= end[6] and central_offset + 46 <= len(raw) - 22,
                "zip32-observation-header-contained")
        local = struct.unpack_from("<4s5H3L2H", raw, local_offset)
        central = struct.unpack_from("<4s6H3L5H2L", raw, central_offset)
        encoded = name.encode("ascii")
        require(local[0] == b"PK\x03\x04" and central[0] == b"PK\x01\x02"
                and local[1] == central[2] == 20 and local[2] == central[3] == 0
                and local[3] == central[4] == 8 and local[6] == central[7]
                and local[7] == central[8] < 0xffffffff and local[8] == central[9] == size < 0xffffffff
                and local[9] == central[10] == len(encoded) and local[10] == 0
                and central[11] == central[12] == central[13] == 0 and central[16] == local_offset,
                "zip32-observation-exact-real-32bit-fields-no-extra-descriptor-or-sentinel")
        local_end = local_offset + 30 + len(encoded)
        central_end = central_offset + 46 + len(encoded)
        require(local_end + local[7] <= end[6] and central_end <= len(raw) - 22
                and raw[local_offset + 30:local_end] == encoded
                and raw[central_offset + 46:central_end] == encoded,
                "zip32-observation-name-and-data-contained")
        header_digest.update(raw[local_offset:local_end])
        header_digest.update(raw[central_offset:central_end])
        metadata_digest.update(json.dumps([name, size, fingerprint], separators=(",", ":")).encode() + b"\n")
        if index in {0, 1, len(expected) - 1}:
            samples.append({"index": index, "name": name, "member_bytes": size,
                            "local_header_hex": raw[local_offset:local_end].hex(),
                            "central_header_hex": raw[central_offset:central_end].hex()})
        local_offset = local_end + local[7]
        central_offset = central_end
    require(local_offset == end[6] and central_offset == len(raw) - 22,
            "zip32-observation-exact-no-gap-local-central-span")
    decoded_total = 0
    with zipfile.ZipFile(path) as archive:
        require(archive.namelist() == [value[0] for value in expected], "zip32-observation-decoded-member-list")
        for name, size, fingerprint in expected:
            total = 0
            digest = hashlib.sha256()
            carry = b""
            with archive.open(name) as stream:
                while True:
                    block = stream.read(65536)
                    if not block:
                        break
                    require(total + len(block) <= size and MARKER not in carry + block,
                            "zip32-observation-decode-bound-or-unexpected-marker")
                    digest.update(block)
                    total += len(block)
                    carry = block[-(len(MARKER) - 1):]
            require(total == size and digest.hexdigest() == fingerprint,
                    "zip32-observation-decoded-size-and-generated-hash")
            decoded_total += total
            require(decoded_total <= 105 * MIB, "zip32-observation-decoded-aggregate-bound")
    return {"format_bits": 32, "member_count": len(expected), "expanded_bytes": decoded_total,
            "largest_member_bytes": max(value[1] for value in expected),
            "member_metadata_sha256": metadata_digest.hexdigest(),
            "local_and_central_headers_sha256": header_digest.hexdigest(),
            "all_members_decoded_hashes_match": True, "all_sizes_real_ZIP32": True,
            "ZIP64_extra_or_sentinel": False, "data_descriptor": False,
            "compressed_literal_marker_present": False, "header_samples": samples,
            "EOCD_hex": raw[-22:].hex()}


def write_zip32(path, entries):
    expected = []
    names = set()
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9, allowZip64=False) as archive:
        for name, value in entries:
            require(type(name) is str and re.fullmatch(r"[A-Za-z0-9.-]{1,80}", name) is not None
                    and name not in names and len(expected) < 10001, "zip32-observation-finite-member-name")
            names.add(name)
            size = value if type(value) is int else len(value)
            require(type(value) in {int, bytes} and 0 < size <= 26 * MIB, "zip32-observation-input-bound")
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 15, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.file_size = size
            info.external_attr = 0o600 << 16
            digest = hashlib.sha256()
            with archive.open(info, "w", force_zip64=False) as output:
                blocks = seed_blocks(name, size) if type(value) is int else (value,)
                for block in blocks:
                    digest.update(block)
                    output.write(block)
            expected.append((name, size, digest.hexdigest()))
    return prove_zip32(path, expected)


def identity(path):
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and not path.is_symlink() and before.st_uid == os.getuid()
            and before.st_nlink == 1 and 0 < before.st_size <= 24 * MIB,
            "zip32-observation-owned-file-bound")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        while True:
            block = source.read(65536)
            if not block:
                break
            total += len(block)
            require(total <= before.st_size, "zip32-observation-read-size-bound")
            digest.update(block)
    after = path.lstat()
    require(total == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            "zip32-observation-file-changed")
    return {"bytes": before.st_size, "sha256": digest.hexdigest()}


def build_quota_matrix(root):
    root = Path(root)
    require(root.resolve() == root and not root.exists() and root.parent.is_dir()
            and root.parent.stat().st_uid == os.getuid()
            and stat.S_IMODE(root.parent.stat().st_mode) == 0o700, "zip32-observation-fresh-private-root")
    root.mkdir(mode=0o700)
    rows = []

    def add(name, path, proof, **facts):
        rows.append({"name": name, "path": str(path), "input": identity(path), "proof": proof,
                     **facts, "qualification_credit": False, "accepted": False})

    path = root / "individual.zip"
    add(NAMES[0], path, write_zip32(path, [("large.txt", 25 * MIB + 1)]),
        diagnostic_target="individual-member-size", requested_member_bytes=25 * MIB + 1)
    path = root / "expanded.zip"
    add(NAMES[1], path, write_zip32(path, [("part%d.txt" % index, 21 * MIB) for index in range(5)]),
        diagnostic_target="expanded-size", requested_expanded_bytes=105 * MIB)
    current = b"Relay harmless ordinary ZIP32 nested content\n"
    levels = []
    for depth in range(18):
        path = root / ("nested-%02d.zip" % depth)
        levels.append(write_zip32(path, [("inside.zip" if depth else "inside.txt", current)]))
        current = path.read_bytes()
    add(NAMES[2], path, levels[-1], diagnostic_target="recursion", nesting=18, nested_layer_proofs=levels)
    path = root / "many.zip"
    add(NAMES[3], path, write_zip32(path, (("file-%05d.txt" % index,
        ("Relay distinct harmless file %d\n" % index).encode()) for index in range(10001))),
        diagnostic_target="file-count", requested_file_count=10001)
    path = root / "near-ceiling.csv"
    digest = hashlib.sha256()
    with path.open("xb") as output:
        output.write(b"v\n")
        digest.update(b"v\n")
        left = 24 * MIB - 2
        while left:
            count = min(left, 65536)
            block = b"1\n" * (count // 2)
            require(len(block) == count, "zip32-observation-CSV-even-size")
            output.write(block)
            digest.update(block)
            left -= count
    add(NAMES[4], path, {"format": "plain-CSV", "raw_bytes": 24 * MIB,
        "generated_sha256": digest.hexdigest(), "rows": (24 * MIB - 2) // 2,
        "compressed": False}, diagnostic_target="near-ceiling-CSV-utility")
    require(rows[-1]["input"] == {"bytes": 24 * MIB, "sha256": digest.hexdigest()}
            and len(rows) == 5 and tuple(row["name"] for row in rows) == NAMES
            and sum(row["input"]["bytes"] for row in rows[:4]) <= TOTAL_COMPRESSED_LIMIT,
            "zip32-observation-exact-five-and-compressed-bound")
    require(sum(path.stat().st_size for path in root.iterdir()) <= 48 * MIB,
            "zip32-observation-all-owned-inputs-bound")
    return rows


def make_quota_matrix(daemon):
    daemon.verify_mount()
    rows = build_quota_matrix(daemon.mount / "assessment/zip32-quota-observations")
    daemon.verify_mount()
    return rows


def file_stream(path, expected):
    require(identity(path) == expected, "zip32-observation-input-changed-before-send")
    digest = hashlib.sha256()
    total = 0
    yield b"zINSTREAM\x00"
    with Path(path).open("rb") as source:
        while True:
            block = source.read(65536)
            if not block:
                break
            total += len(block)
            require(total <= expected["bytes"], "zip32-observation-send-size-bound")
            digest.update(block)
            yield struct.pack("!I", len(block)) + block
    require(total == expected["bytes"] and digest.hexdigest() == expected["sha256"]
            and identity(path) == expected, "zip32-observation-input-changed-during-send")
    yield b"\x00" * 4


def observe_quota_matrix(candidate, rows, results):
    results = Path(results)
    report = results / "zip32-quota-observations-before-strict-corpus.json"
    cid = getattr(candidate, "cid", "")
    require(type(cid) is str and re.fullmatch(r"[0-9a-f]{64}", cid) is not None
            and not report.exists() and len(rows) == 5 and tuple(row["name"] for row in rows) == NAMES
            and all(row.get("qualification_credit") is False and row.get("accepted") is False for row in rows),
            "zip32-observation-once-exact-nonqualifying-matrix")
    observations = []

    def save():
        report.write_text(json.dumps({"schema": 1, "kind": "relay-ordinary-ZIP32-quota-CSV-observations-v1",
            "before_original_strict_corpus": True, "owned_candidate_CID": cid,
            "scanner_reference": REFERENCE, "scanner_config": CONFIG, "observations": observations,
            "qualification_credit": False, "accepted": False, "full_scanner_qualified": False,
            "application_acceptance": False, "deployment_authorized": False}, sort_keys=True, indent=2) + "\n")
    save()
    for row in rows:
        require(identity(row["path"]) == row["input"], "zip32-observation-input-changed")
        item = {key: value for key, value in row.items() if key != "path"}
        item.update(qualification_credit=False, accepted=False)
        observations.append(item)
        save()
        try:
            response = candidate.exchange(file_stream(row["path"], row["input"]))
            item["observation"] = response_kind(response)
            item.update(response_bytes=len(response), response_sha256=sha(response))
            with (results / (row["name"] + "-diagnostic.stdout")).open("xb") as output:
                output.write(response)
        except Exception as error:
            item.update(observation="transport-or-response-error-no-credit", error_type=type(error).__name__)
        finally:
            save()
    return observations
