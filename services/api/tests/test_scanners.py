"""Syft and Grype: how their JSON maps into dependencies and findings, and
how a missing, failing or misbehaving scanner degrades."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from app.core.config import settings
from app.depscan import grype, syft
from app.depscan.grype import VulnFinding
from app.depscan.parsers import DiscoveredDependency

ROOT = Path("/tmp/ospmae-repo")


@pytest.fixture()
def scanner(monkeypatch):
    """Stand in for the scanner binary: record its command, return output."""

    calls: list[dict] = []
    result = {"returncode": 0, "stdout": "{}", "stderr": ""}

    def fake_run(cmd, **kwargs):
        calls.append({"cmd": cmd, **kwargs})
        return subprocess.CompletedProcess(
            cmd, result["returncode"], result["stdout"], result["stderr"]
        )

    monkeypatch.setattr(syft.subprocess, "run", fake_run)
    monkeypatch.setattr(grype.subprocess, "run", fake_run)
    monkeypatch.setattr(syft.shutil, "which", lambda cmd: f"/usr/bin/{cmd}")
    monkeypatch.setattr(grype.shutil, "which", lambda cmd: f"/usr/bin/{cmd}")
    monkeypatch.setattr(settings, "syft_enabled", True)
    monkeypatch.setattr(settings, "grype_enabled", True)
    return calls, result


def test_syft_inventory_maps_types_and_locations(scanner):
    calls, result = scanner
    result["stdout"] = json.dumps(
        {
            "artifacts": [
                {
                    "name": "react",
                    "version": "18.2.0",
                    "type": "npm",
                    "locations": [{"path": "/package-lock.json"}, {"path": ""}],
                },
                {
                    "name": "flask",
                    "version": "3.0.0",
                    "type": "",
                    "purl": "pkg:pypi/flask@3.0.0",
                    "locations": [{"accessPath": str(ROOT / "app/requirements.txt")}],
                },
                {
                    "name": "serde",
                    "version": "1.0.190",
                    "type": "",
                    "language": "Rust_Crate",
                },
                {"name": "log4j-core", "version": "2.17.1", "type": "java-archive"},
                {"name": "", "version": "1", "type": "npm"},
                {"name": "typeless", "version": "1"},
                "junk",
            ]
        }
    )
    found = syft.scan_syft(ROOT)
    assert found == [
        DiscoveredDependency("npm", "react", "18.2.0", True, "/package-lock.json"),
        DiscoveredDependency("python", "flask", "3.0.0", True, "app/requirements.txt"),
        DiscoveredDependency("cargo", "serde", "1.0.190", True, "syft"),
        DiscoveredDependency("java-archive", "log4j-core", "2.17.1", True, "syft"),
    ]
    assert calls[0]["cmd"] == ["syft", "scan", str(ROOT), "--quiet", "--output", "json"]
    assert calls[0]["timeout"] >= 30


def test_grype_findings_map_fixes_references_and_titles(scanner):
    calls, result = scanner
    match = {
        "artifact": {
            "name": "lodash",
            "version": "4.17.20",
            "type": "npm",
            "purl": "pkg:npm/lodash@4.17.20",
        },
        "vulnerability": {
            "id": "GHSA-35jh-r3h4-6jhm",
            "severity": "High",
            "description": "Command injection in lodash",
            "fix": {"versions": ["4.17.21", " "], "state": "fixed"},
            "urls": ["https://github.com/advisories/GHSA-35jh-r3h4-6jhm", " "],
            "references": [{"url": "https://nvd.nist.gov/x"}, {"href": "h"}, 3],
            "dataSource": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
        },
    }
    unfixed = {
        "artifact": {"name": "pyyaml", "version": "5.3", "purl": "pkg:pypi/pyyaml@5.3"},
        "vulnerability": {"id": "CVE-2020-14343", "namespace": "nvd:cpe", "fix": {}},
    }
    result["stdout"] = json.dumps(
        {
            "matches": [
                match,
                unfixed,
                {"artifact": {"name": "x", "type": "npm"}, "vulnerability": {}},
                {"artifact": "bad", "vulnerability": {}},
                {"artifact": {"name": "y"}, "vulnerability": {"id": "CVE-1"}},
                "junk",
            ]
        }
    )
    found = grype.scan_grype(ROOT)
    assert found == [
        VulnFinding(
            ecosystem="npm",
            package="lodash",
            version="4.17.20",
            vulnerability_id="GHSA-35jh-r3h4-6jhm",
            severity="High",
            title="Command injection in lodash",
            fixed_version="4.17.21",
            references=[
                "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
                "https://nvd.nist.gov/x",
                "h",
            ],
            raw=match,
        ),
        VulnFinding(
            ecosystem="python",
            package="pyyaml",
            version="5.3",
            vulnerability_id="CVE-2020-14343",
            severity=None,
            title="nvd:cpe",
            fixed_version=None,
            references=[],
            raw=unfixed,
        ),
    ]
    assert calls[0]["cmd"] == ["grype", f"dir:{ROOT}", "--quiet", "--output", "json"]


@pytest.mark.parametrize("module", [syft, grype])
def test_a_failing_scanner_reports_nothing(scanner, module):
    _, result = scanner
    scan = syft.scan_syft if module is syft else grype.scan_grype
    result.update(returncode=1, stdout="", stderr="boom")
    assert scan(ROOT) is None
    result.update(returncode=0, stdout="not json")
    assert scan(ROOT) is None
    result.update(stdout='{"artifacts": "nope", "matches": "nope"}')
    assert scan(ROOT) == []
    result.update(stdout="[]")
    assert scan(ROOT) == []


@pytest.mark.parametrize("module", [syft, grype])
def test_disabled_or_missing_scanners_never_run(scanner, monkeypatch, module):
    calls, _ = scanner
    scan = syft.scan_syft if module is syft else grype.scan_grype
    flag = "syft_enabled" if module is syft else "grype_enabled"
    monkeypatch.setattr(settings, flag, False)
    assert scan(ROOT) is None
    monkeypatch.setattr(settings, flag, True)
    monkeypatch.setattr(module.shutil, "which", lambda cmd: None)
    assert scan(ROOT) is None
    assert calls == []


@pytest.mark.parametrize("module", [syft, grype])
def test_scanner_timeouts_have_a_floor(monkeypatch, module):
    key = "syft_timeout_seconds" if module is syft else "grype_timeout_seconds"
    monkeypatch.setattr(settings, key, 1, raising=False)
    assert module._scan_timeout_seconds() == 30
    monkeypatch.setattr(settings, key, 600, raising=False)
    assert module._scan_timeout_seconds() == 600


@pytest.mark.parametrize(
    ("raw", "purl", "expected"),
    [
        ("go-module", "", "go"),
        ("", "pkg:golang/github.com/x/y@v1", "go"),
        ("", "pkg:composer/monolog/monolog@3", "composer"),
        ("", "not-a-purl", None),
        ("PHP_Composer", "", "composer"),
        ("x" * 40, "", "x" * 32),
    ],
)
def test_ecosystem_names_match_between_scanners(raw, purl, expected):
    assert grype._ecosystem(raw, purl) == expected
    assert syft._ecosystem(raw, None, purl) == expected
