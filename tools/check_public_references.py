#!/usr/bin/env python3
"""Reject references from this public repository to unavailable project repos."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_PROJECT_REPOSITORIES = {
    "IICP",
    "iicp-client-python",
    "iicp-client-rust",
    "iicp-client-typescript",
    "iicp-directory-php",
    "iicp-directory-rust",
    "iicp-management",
    "iicp-node-monitor",
    "iicp-web-node",
}
REFERENCE = re.compile(r"(?:https://github\.com/)?RobLe3/([A-Za-z0-9_.-]+)")
TEXT_SUFFIXES = {".md", ".json", ".py", ".rs", ".toml", ".yml", ".yaml", ".txt"}


def findings(text: str) -> list[str]:
    return sorted({name for name in REFERENCE.findall(text) if name not in PUBLIC_PROJECT_REPOSITORIES})


def tracked_files() -> list[Path]:
    output = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    return [ROOT / raw.decode() for raw in output.split(b"\0") if raw and Path(raw.decode()).suffix.lower() in TEXT_SUFFIXES]


def main() -> int:
    failed = False
    for path in tracked_files():
        for name in findings(path.read_text(encoding="utf-8", errors="replace")):
            print(f"{path.relative_to(ROOT)}: unavailable repository reference: RobLe3/{name}", file=sys.stderr)
            failed = True
    if failed:
        return 1
    print("public repository-reference closure passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
