"""Publication must preserve the images that passed native, credential-free checks."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("searxng_release", ROOT / ".github/scripts/searxng_release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
SHA = "a" * 40
DIGESTS = {"amd64": "sha256:" + "1" * 64, "arm64": "sha256:" + "2" * 64}


def descriptor(snapshot=None, manifest=None, digests=None):
    snapshot = snapshot or release.source_snapshot(ROOT, SHA, release.REPOSITORY)
    manifest = manifest or {
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "digest": "sha256:" + "3" * 64,
        "manifests": [
            {"digest": value, "platform": {"os": "linux", "architecture": arch}}
            for arch, value in DIGESTS.items()
        ],
    }
    return release.release_descriptor(snapshot, copy.deepcopy(snapshot), manifest, SHA, "123", "sha-test", digests or DIGESTS)


def test_release_binds_both_native_artifacts_and_immutable_index():
    value = descriptor()
    assert value["image"] == release.IMAGE + "@sha256:" + "3" * 64
    assert value["architecture_digests"] == DIGESTS
    assert value["platforms"] == ["linux/amd64", "linux/arm64"]
    assert set(value["source_inputs"]) == set(release.SOURCE_FILES)


@pytest.mark.parametrize("change", ["fork", "revision", "missing-input", "checksum"])
def test_release_refuses_unmatched_source(change):
    snapshot = release.source_snapshot(ROOT, SHA, release.REPOSITORY)
    if change == "fork":
        snapshot["repository"] = "fork/odysseus"
    elif change == "revision":
        snapshot["source_revision"] = "b" * 40
    elif change == "missing-input":
        snapshot["source_inputs"].pop(release.SOURCE_FILES[0])
    else:
        snapshot["source_inputs"][release.SOURCE_FILES[0]] = "invalid"
    with pytest.raises(ValueError):
        descriptor(snapshot=snapshot)


def test_release_refuses_different_native_build_inputs():
    snapshot = release.source_snapshot(ROOT, SHA, release.REPOSITORY)
    other = copy.deepcopy(snapshot)
    other["source_inputs"][release.SOURCE_FILES[0]] = "f" * 64
    with pytest.raises(ValueError, match="different source inputs"):
        release.release_descriptor(snapshot, other, {}, SHA, "123", "test", DIGESTS)


@pytest.mark.parametrize("change", ["missing-arm", "extra-platform", "wrong-os", "duplicate-digest", "wrong-digest", "moving-index"])
def test_release_refuses_incomplete_or_substituted_index(change):
    manifest = {
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "digest": "sha256:" + "3" * 64,
        "manifests": [{"digest": value, "platform": {"os": "linux", "architecture": arch}} for arch, value in DIGESTS.items()],
    }
    if change == "missing-arm":
        manifest["manifests"].pop()
    elif change == "extra-platform":
        manifest["manifests"].append({"digest": "sha256:" + "4" * 64, "platform": {"os": "unknown", "architecture": "unknown"}})
    elif change == "wrong-os":
        manifest["manifests"][1]["platform"]["os"] = "windows"
    elif change == "duplicate-digest":
        manifest["manifests"][1]["digest"] = DIGESTS["amd64"]
    elif change == "wrong-digest":
        manifest["manifests"][1]["digest"] = "sha256:" + "4" * 64
    else:
        manifest["digest"] = "latest"
    with pytest.raises(ValueError):
        descriptor(manifest=manifest)


def test_ci_publication_boundary_and_native_checks():
    workflow = yaml.safe_load((ROOT / ".github/workflows/searxng-image.yml").read_text())
    events = workflow.get("on", workflow.get(True))
    assert "pull_request_target" not in events
    assert workflow["permissions"] == {"contents": "read"}
    jobs = workflow["jobs"]
    assert [name for name, job in jobs.items() if job.get("permissions", {}).get("packages") == "write"] == ["publish"]
    publish = jobs["publish"]
    assert publish["needs"] == "validate"
    assert "github.repository == 'odysseus-dev/odysseus'" in publish["if"]
    assert "github.event_name == 'push'" in publish["if"]
    assert "refs/heads/release/searxng-ca-trust" in publish["if"]
    assert "github.ref)" in publish["if"]
    steps = publish["steps"]
    assert next(i for i, step in enumerate(steps) if "docker load" in step.get("run", "")) < next(i for i, step in enumerate(steps) if "docker/login-action" in step.get("uses", ""))
    for name in ("validate", "verify-published"):
        matrix = jobs[name]["strategy"]["matrix"]["include"]
        assert {(row["arch"], row["runner"]) for row in matrix} == {("amd64", "ubuntu-latest"), ("arm64", "ubuntu-24.04-arm")}
        assert any("validate-searxng-image.sh" in step.get("run", "") for step in jobs[name]["steps"])
    assert not any("login-action" in step.get("uses", "") for step in jobs["verify-published"]["steps"])
    assert set(jobs["release"]["needs"]) == {"publish", "verify-published"}


@pytest.mark.parametrize("failure,expected", [("none", 0), ("exec", 7), ("up", 1), ("existing-volume", 1)])
def test_compose_probe_owns_only_its_temporary_resources(tmp_path, failure, expected):
    """Exercise the real helper with a Docker double, including failure cleanup."""
    binary = tmp_path / "docker"
    calls = tmp_path / "calls.jsonl"
    binary.write_text('''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ["DOCKER_CALLS"], "a") as log:
    log.write(json.dumps({"args": args, "volume": os.environ["SEARXNG_VALIDATION_VOLUME"], "secret": os.environ["SEARXNG_SECRET"]}) + "\\n")
failure = os.environ["DOCKER_FAILURE"]
if args[:2] == ["volume", "inspect"]:
    sys.exit(0 if failure == "existing-volume" else 1)
if "exec" in args and failure == "exec":
    sys.exit(7)
if "up" in args and failure == "up":
    sys.exit(9)
''')
    binary.chmod(0o755)
    result = subprocess.run(["bash", str(ROOT / ".github/scripts/validate-searxng-image.sh"), "localhost/searxng:validated"], env={**os.environ, "PATH": str(tmp_path) + ":" + os.environ["PATH"], "DOCKER_CALLS": str(calls), "DOCKER_FAILURE": failure, "SEARXNG_SECRET": "operator-secret-must-not-propagate"}, capture_output=True, text=True)
    assert result.returncode == expected, result.stderr
    entries = [json.loads(line) for line in calls.read_text().splitlines()]
    assert all(entry["secret"] == "searxng-ci-validation-only" for entry in entries)
    commands = [entry["args"] for entry in entries]
    if failure == "existing-volume":
        assert len(commands) == 1
        return
    up = next(command for command in commands if "up" in command)
    assert up[up.index("--env-file") + 1] == "/dev/null"
    assert "--no-deps" in up and "--no-build" in up and "--wait" in up
    assert up[up.index("--pull") + 1] == "never"
    down = next(command for command in commands if "down" in command)
    assert "--volumes" not in down
    assert commands[-1] == ["volume", "rm", entries[-1]["volume"]]
    if failure != "up":
        execute = next(command for command in commands if "exec" in command)
        assert execute[-2:] == ["--running", "--live"]
