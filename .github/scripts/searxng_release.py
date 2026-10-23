"""Describe a validated sidecar release without executing image or repository code."""

import argparse
import hashlib
import json
from pathlib import Path
import re


IMAGE = "ghcr.io/odysseus-dev/odysseus-searxng"
REPOSITORY = "odysseus-dev/odysseus"
SOURCE_FILES = (
    "docker/searxng/Dockerfile",
    "docker/searxng/repair_trust.py",
    "docker/searxng/blocked-certificates.json",
    "docker/searxng/validate_image.py",
    "tests/fixtures/ca-trust/incident.json",
)


def revision(value):
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError("invalid source revision")
    return value


def digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ValueError("invalid image digest")
    return value


def source_snapshot(root, source_revision, repository):
    revision(source_revision)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid source repository")
    dockerfile = (root / SOURCE_FILES[0]).read_text()
    match = re.search(r"^FROM (\S+) AS base$", dockerfile, re.M)
    if not match or not re.fullmatch(r"docker\.io/searxng/searxng:[^\s@]+@sha256:[0-9a-f]{64}", match[1]):
        raise ValueError("SearXNG base must have an immutable upstream digest")
    return {
        "schema_version": 1,
        "repository": repository,
        "source_revision": source_revision,
        "upstream_image": match[1],
        "source_inputs": {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCE_FILES},
    }


def release_descriptor(amd64, arm64, manifest, source_revision, run_id, tag, arch_digests):
    revision(source_revision)
    if amd64 != arm64:
        raise ValueError("native architecture builds used different source inputs")
    if amd64.get("repository") != REPOSITORY or amd64.get("source_revision") != source_revision:
        raise ValueError("release source does not match the canonical workflow revision")
    if amd64.get("schema_version") != 1 or set(amd64.get("source_inputs", {})) != set(SOURCE_FILES):
        raise ValueError("incomplete source inventory")
    if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in amd64["source_inputs"].values()):
        raise ValueError("invalid source checksum")
    if not str(run_id).isdigit() or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag):
        raise ValueError("invalid workflow identity or image tag")
    if manifest.get("mediaType") not in (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ):
        raise ValueError("release is not a multiarch image index")
    children = manifest.get("manifests", [])
    platforms = sorted(f"{entry.get('platform', {}).get('os')}/{entry.get('platform', {}).get('architecture')}" for entry in children)
    if platforms != ["linux/amd64", "linux/arm64"]:
        raise ValueError("release must contain exactly the two validated Linux architectures")
    if len({digest(entry.get("digest")) for entry in children}) != 2:
        raise ValueError("architecture digests must be distinct")
    expected = {arch: digest(value) for arch, value in arch_digests.items()}
    actual = {entry["platform"]["architecture"]: entry["digest"] for entry in children}
    if actual != expected:
        raise ValueError("index does not reference the exact validated architecture images")
    return {
        **amd64,
        "image": f"{IMAGE}@{digest(manifest.get('digest'))}",
        "tag": tag,
        "platforms": platforms,
        "architecture_digests": actual,
        "workflow_run": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    inputs = sub.add_parser("inputs")
    inputs.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    inputs.add_argument("--revision", required=True)
    inputs.add_argument("--repository", required=True)
    inputs.add_argument("--output", type=Path, required=True)
    release = sub.add_parser("release")
    release.add_argument("--amd64", type=Path, required=True)
    release.add_argument("--arm64", type=Path, required=True)
    release.add_argument("--manifest", type=Path, required=True)
    release.add_argument("--amd64-digest", required=True)
    release.add_argument("--arm64-digest", required=True)
    release.add_argument("--revision", required=True)
    release.add_argument("--run-id", required=True)
    release.add_argument("--tag", required=True)
    release.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "inputs":
        value = source_snapshot(args.root, args.revision, args.repository)
    else:
        value = release_descriptor(
            json.loads(args.amd64.read_text()), json.loads(args.arm64.read_text()),
            json.loads(args.manifest.read_text()), args.revision, args.run_id, args.tag,
            {"amd64": args.amd64_digest, "arm64": args.arm64_digest},
        )
    args.output.write_text(json.dumps(value, indent=2) + "\n")


if __name__ == "__main__":
    main()
