#!/usr/bin/env python3
"""Fetch the exact private context without publishing its Git diagnostics."""
import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

from binding import HARNESS, load_profile


def main():
    os.umask(0o077)
    profile = load_profile()
    destination = HARNESS / "private-source"
    runner = Path(os.environ["RUNNER_TEMP"]).resolve()
    results = Path(os.environ["RELAY_CI_RESULTS_DIR"]).resolve()
    if destination.exists() or not results.is_relative_to(runner):
        raise RuntimeError("Private checkout requires fresh owned paths")
    results.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = os.environ.pop("RELAY_SOURCE_READ_KEY", "")
    hosts = profile.get("github_ssh_known_hosts", "")
    if not key.startswith("-----BEGIN OPENSSH PRIVATE KEY-----") or not hosts.startswith("github.com ssh-ed25519 "):
        raise RuntimeError("Missing repository-scoped key or pinned GitHub host identity")
    if hashlib.sha256(hosts.encode()).hexdigest() != profile["github_ssh_known_hosts_sha256"]:
        raise RuntimeError("GitHub host key pin changed")
    with tempfile.TemporaryDirectory(prefix="relay-read-key-", dir=runner) as temporary:
        directory = Path(temporary)
        private_key, known_hosts = directory / "key", directory / "known_hosts"
        private_key.write_text(key.rstrip() + "\n"); private_key.chmod(0o600)
        known_hosts.write_text(hosts); known_hosts.chmod(0o600)
        key = ""
        ssh = ["ssh", "-i", str(private_key), "-o", "IdentitiesOnly=yes",
               "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes",
               "-o", "UserKnownHostsFile=" + str(known_hosts), "-o", "GlobalKnownHostsFile=/dev/null"]
        env = {k: os.environ[k] for k in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR") if k in os.environ}
        env.update(GIT_SSH_COMMAND=" ".join(shlex.quote(x) for x in ssh),
                   GIT_TERMINAL_PROMPT="0", GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
        commands = [(["git", "init", "--quiet", str(destination)], HARNESS),
                    (["git", "remote", "add", "origin", "git@github.com:" + profile["private_repository"] + ".git"], destination),
                    (["git", "-c", "protocol.version=2", "fetch", "--no-tags", "--depth=1", "origin", profile["context_commit"]], destination),
                    (["git", "-c", "advice.detachedHead=false", "checkout", "--detach", "--quiet", profile["context_commit"]], destination)]
        with (results / "private-fetch.stdout").open("w") as stdout, (results / "private-fetch.stderr").open("w") as stderr:
            for command, cwd in commands:
                if subprocess.run(command, cwd=cwd, env=env, stdout=stdout, stderr=stderr, timeout=240).returncode:
                    raise RuntimeError("Exact private source could not be fetched")
    # The deploy-key file has been removed before any app-controlled process.


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        print("Private context preparation failed; diagnostics remain private.", file=sys.stderr)
        sys.exit(1)
