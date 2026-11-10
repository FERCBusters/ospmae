"""Lockfile parsers: each supported format, its variants, and hostile input."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from app.depscan.parsers import (
    DiscoveredDependency,
    is_supported_lockfile,
    parse_lockfile,
    redact_url,
)

MAX = 1_000_000


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text)
    return path


def _found(tmp_path, name, text):
    path = _write(tmp_path, name, text)
    return [
        (d.ecosystem, d.name, d.version, d.is_indirect)
        for d in parse_lockfile(path, max_bytes=MAX)
    ]


def test_package_lock_v3_names_direct_and_nested_packages(tmp_path):
    v3 = {
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "app",
                "version": "1.0.0",
                "dependencies": {"react": "^18"},
                "devDependencies": {"@scope/pkg": "^2"},
            },
            "node_modules/react": {"version": "18.2.0"},
            "node_modules/@scope/pkg": {"version": "2.0.0", "dev": True},
            "node_modules/a/node_modules/b": {"version": "0.1.0"},
            "node_modules/linked": {"link": True},
            "packages/local": {"version": "0.0.1"},
        },
    }
    assert _found(tmp_path, "package-lock.json", json.dumps(v3)) == [
        ("npm", "react", "18.2.0", False),
        ("npm", "@scope/pkg", "2.0.0", False),
        ("npm", "b", "0.1.0", True),
    ]


def test_package_lock_v1_lists_top_level_dependencies(tmp_path):
    v1 = {
        "lockfileVersion": 1,
        "dependencies": {"lodash": {"version": "4.17.21"}, "nover": {}},
    }
    assert _found(tmp_path, "package-lock.json", json.dumps(v1)) == [
        ("npm", "lodash", "4.17.21", False)
    ]


def test_yarn_classic_and_berry_lockfiles(tmp_path):
    classic = (
        "# yarn lockfile v1\n\n"
        '"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n'
        '  version "7.23.2"\n'
        '  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.23.2.tgz"\n\n'
        "lodash@^4.17.21:\n"
        '  version "4.17.21"\n'
    )
    assert _found(tmp_path, "yarn.lock", classic) == [
        ("npm", "@babel/core", "7.23.2", True),
        ("npm", "lodash", "4.17.21", True),
    ]
    berry = (
        "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"
        '"lodash@npm:^4.17.21":\n  version: 4.17.21\n  resolution: "lodash@npm:4.17.21"\n\n'
        '"@scope/pkg@npm:1.2.3":\n  version: 1.2.3\n'
    )
    assert _found(tmp_path / "..", "yarn.lock", berry) == [
        ("npm", "lodash", "4.17.21", True),
        ("npm", "@scope/pkg", "1.2.3", True),
    ]


@pytest.mark.parametrize(
    "packages",
    [
        # Lockfile 5, with a peer suffix.
        "  /react/18.2.0:\n    resolution: {}\n"
        "  /@scope/pkg/1.0.0_react@18.2.0:\n    resolution: {}\n",
        # Lockfile 6.
        "  /react@18.2.0:\n    resolution: {}\n"
        "  /@scope/pkg@1.0.0(react@18.2.0):\n    resolution: {}\n",
        # Lockfile 9.
        "  react@18.2.0:\n    resolution: {}\n"
        "  '@scope/pkg@1.0.0':\n    resolution: {}\n",
    ],
)
def test_pnpm_lockfiles_of_every_version(tmp_path, packages):
    text = "lockfileVersion: '9.0'\npackages:\n" + packages
    assert _found(tmp_path, "pnpm-lock.yaml", text) == [
        ("npm", "react", "18.2.0", True),
        ("npm", "@scope/pkg", "1.0.0", True),
    ]


def test_toml_lockfiles(tmp_path):
    cargo = (
        "version = 3\n\n"
        '[[package]]\nname = "serde"\nversion = "1.0.190"\n\n'
        '[[package]]\nname = "nameless"\n'
    )
    assert _found(tmp_path, "Cargo.lock", cargo) == [
        ("cargo", "serde", "1.0.190", True)
    ]
    poetry = '[[package]]\nname = "flask"\nversion = "3.0.0"\n'
    assert _found(tmp_path, "poetry.lock", poetry) == [
        ("python", "flask", "3.0.0", True)
    ]


def test_pipfile_lock_marks_development_dependencies(tmp_path):
    pipfile = {
        "default": {"requests": {"version": "==2.31.0"}, "odd": "not-a-dict"},
        "develop": {"pytest": {"version": "==8.0.0"}, "unpinned": {}},
    }
    assert _found(tmp_path, "Pipfile.lock", json.dumps(pipfile)) == [
        ("python", "requests", "2.31.0", False),
        ("python", "pytest", "8.0.0", True),
    ]


def test_requirements_skip_options_urls_and_comments(tmp_path):
    text = (
        "# comment\n\n"
        "-r base.txt\n"
        "--index-url https://example.org/simple\n"
        "git+https://github.com/org/repo.git#egg=repo\n"
        "https://example.org/pkg.whl\n"
        "flask==3.0.0\n"
        "requests[security]>=2.31 ; python_version >= '3.8'\n"
        "bare\n"
    )
    assert _found(tmp_path, "requirements.txt", text) == [
        ("python", "flask", "==3.0.0", False),
        ("python", "requests", ">=2.31", False),
        ("python", "bare", "", False),
    ]


def test_go_modules_and_sums(tmp_path):
    mod = (
        "module example.com/app\n\ngo 1.22\n\n"
        "require golang.org/x/text v0.14.0\n"
        "require (\n"
        "\t// a comment\n"
        "\tgithub.com/pkg/errors v0.9.1\n"
        "\tgithub.com/x/y v1.0.0 // indirect\n"
        "\tlonely\n"
        ")\n"
        "replace a => b v1.0.0\n"
    )
    assert _found(tmp_path, "go.mod", mod) == [
        ("go", "golang.org/x/text", "v0.14.0", False),
        ("go", "github.com/pkg/errors", "v0.9.1", False),
        ("go", "github.com/x/y", "v1.0.0", True),
    ]
    gosum = (
        "github.com/pkg/errors v0.9.1 h1:abc=\n"
        "github.com/pkg/errors v0.9.1/go.mod h1:def=\n\nshort\n"
    )
    assert _found(tmp_path, "go.sum", gosum) == [
        ("go", "github.com/pkg/errors", "v0.9.1", True),
        ("go", "github.com/pkg/errors", "v0.9.1", True),
    ]


def test_composer_lock_marks_development_packages(tmp_path):
    lock = {
        "packages": [{"name": "monolog/monolog", "version": "3.5.0"}, "junk"],
        "packages-dev": [{"name": "phpunit/phpunit", "version": "10.5.0"}],
    }
    assert _found(tmp_path, "composer.lock", json.dumps(lock)) == [
        ("composer", "monolog/monolog", "3.5.0", False),
        ("composer", "phpunit/phpunit", "10.5.0", True),
    ]


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("package-lock.json", "{not json"),
        ("Pipfile.lock", "[1, 2"),
        ("Cargo.lock", "[[package]\nname ="),
        ("pnpm-lock.yaml", "packages: [unclosed"),
        ("pnpm-lock.yaml", "- just\n- a list\n"),
        ("pnpm-lock.yaml", "packages: not-a-mapping\n"),
        ("composer.lock", '{"packages": "nope"}'),
    ],
)
def test_malformed_lockfiles_yield_nothing(tmp_path, name, text):
    assert _found(tmp_path, name, text) == []


def test_oversized_empty_and_unknown_files_are_not_read(tmp_path):
    big = _write(tmp_path, "requirements.txt", "flask==3.0.0\n" * 100)
    assert parse_lockfile(big, max_bytes=50) == []
    empty = _write(tmp_path / "..", "go.sum", "")
    assert parse_lockfile(empty, max_bytes=MAX) == []
    assert parse_lockfile(tmp_path / "missing" / "go.mod", max_bytes=MAX) == []
    other = _write(tmp_path, "setup.py", "flask==3.0.0")
    assert parse_lockfile(other, max_bytes=MAX) == []
    assert is_supported_lockfile(Path("x/Cargo.lock"))
    assert not is_supported_lockfile(other)


def test_records_name_their_source_file(tmp_path):
    path = _write(tmp_path, "requirements.txt", "flask==3.0.0\n")
    assert parse_lockfile(path, max_bytes=MAX) == [
        DiscoveredDependency("python", "flask", "==3.0.0", False, str(path))
    ]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "fatal: https://user:tok3n@github.com/org/repo.git",
            "fatal: https://***:***@github.com/org/repo.git",
        ),
        ("git+ssh://git:pw@host/x", "git+ssh://***:***@host/x"),
        ("https://github.com/org/repo", "https://github.com/org/repo"),
        (None, ""),
    ],
)
def test_credentials_in_urls_are_masked(text, expected):
    assert redact_url(text) == expected
