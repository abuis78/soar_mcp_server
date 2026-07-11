#!/usr/bin/env python3
"""
SOAR MCP Server — App Package Hygiene Linter (issue #71)

Deterministic, offline checks for a SOAR app release archive (.tar/.tar.gz)
BEFORE install or publication. Validates archive members WITHOUT extracting to
disk, so it is safe to run against untrusted archives in CI.

Usage:
    python3 scripts/lint_soar_app_package.py <archive.tar[.gz]> [--json]

Exit code: 0 if no blocking errors, 1 otherwise.

Copyright 2026 Andreas Buis
"""
from __future__ import annotations

import argparse
import json
import sys
import tarfile

_TOP = "soar_mcp_server"

# Files that must be present inside the top-level app directory.
_REQUIRED_FILES = [
    "soar_mcp_server.json",
    "soar_mcp_connector.py",
    "soar_mcp_handler.py",
    "soar_mcp_config.py",
    "soar_mcp_tools.py",
]

# Manifest fields that must be present and non-empty.
_REQUIRED_MANIFEST_FIELDS = ["app_version", "main_module", "rest_handler", "appid"]

# Directories that must NOT be shipped inside the app package. Dev/CI-only paths
# are excluded so SOAR does not pylint them under Python 3.13 (issue #104): test
# files carry style warnings that can keep the app pinned to 3.9.
_EXCLUDED_PREFIXES = [
    f"{_TOP}/releases/", f"{_TOP}/local/", f"{_TOP}/.git/",
    f"{_TOP}/scripts/", f"{_TOP}/.github/",
]


def _is_blocked_name(name: str) -> bool:
    """macOS metadata / build artifacts / dev-only files that must not ship."""
    base = name.rstrip("/").split("/")[-1]
    return (
        base == ".DS_Store"
        or base.startswith("._")
        or "/__pycache__/" in f"/{name}"
        or name.endswith(".pyc")
        or base.startswith("test_")           # unit tests are dev-only (#104)
    )


def _unsafe_member(member: tarfile.TarInfo) -> str | None:
    """Return a reason string if the member is path-unsafe, else None."""
    name = member.name
    if name.startswith("/"):
        return "absolute path"
    parts = name.split("/")
    if ".." in parts:
        return "path traversal (..)"
    if member.issym() or member.islnk():
        return "symlink/hardlink"
    return None


def lint_archive(path: str) -> dict:
    """Return a report dict with `errors` (blocking) and `warnings` lists."""
    errors: list[str] = []
    warnings: list[str] = []

    try:
        tarf = tarfile.open(path, mode="r:*")
    except FileNotFoundError:
        return {"ok": False, "errors": [f"archive not found: {path}"], "warnings": []}
    except tarfile.TarError as exc:
        return {"ok": False, "errors": [f"not a readable tar archive: {exc}"], "warnings": []}

    with tarf:
        members = tarf.getmembers()
        names = [m.name for m in members]

        if not members:
            errors.append("archive is empty")

        # Top-level directory entry must be present (the v1.6.9 install bug).
        if f"{_TOP}/" not in names and _TOP not in names:
            errors.append(
                f"missing top-level directory entry '{_TOP}/' "
                "(pack from the parent dir: tar -czf app.tar soar_mcp_server/)"
            )

        # Every member must live under the top-level app directory.
        for name in names:
            top = name.split("/")[0]
            if top != _TOP:
                errors.append(f"member outside '{_TOP}/': {name}")

        # Path-safety, blocked files, excluded dirs.
        for m in members:
            reason = _unsafe_member(m)
            if reason:
                errors.append(f"unsafe member ({reason}): {m.name}")
            if _is_blocked_name(m.name):
                errors.append(f"blocked file in package: {m.name}")
            if any(m.name.startswith(p) for p in _EXCLUDED_PREFIXES):
                errors.append(f"release/local artifact must be excluded: {m.name}")

        # Required files present.
        member_set = set(names)
        for rel in _REQUIRED_FILES:
            if f"{_TOP}/{rel}" not in member_set:
                errors.append(f"required file missing: {_TOP}/{rel}")

        # Manifest validity.
        manifest_name = f"{_TOP}/soar_mcp_server.json"
        if manifest_name in member_set:
            try:
                fobj = tarf.extractfile(manifest_name)
                manifest = json.loads(fobj.read().decode("utf-8")) if fobj else {}
                for field in _REQUIRED_MANIFEST_FIELDS:
                    if not manifest.get(field):
                        errors.append(f"manifest field missing/empty: {field}")
            except Exception as exc:
                errors.append(f"manifest is not valid JSON: {exc}")

    return {"ok": not errors, "errors": errors, "warnings": warnings}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lint a SOAR app release archive.")
    parser.add_argument("archive", help="Path to the .tar/.tar.gz app package")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    args = parser.parse_args(argv)

    report = lint_archive(args.archive)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        if report["ok"]:
            print(f"OK — {args.archive} passed all package hygiene checks.")
        else:
            print(f"FAILED — {args.archive} has {len(report['errors'])} blocking error(s):")
            for e in report["errors"]:
                print(f"  ✗ {e}")
        for w in report["warnings"]:
            print(f"  ! {w}")

    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
