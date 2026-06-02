#!/usr/bin/env python3
"""Emit a GitHub Actions matrix for Ubuntu DWARF JSON generation."""

import argparse
import json
import re
import sys
from pathlib import Path


VALID_MODES = ("latest", "manual", "all")
VALID_UBUNTU = re.compile(r"^[0-9]{2}\.04$")
VALID_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")


def load_config(path):
    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: failed to read {path}: {exc}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(data, dict):
        print("error: config root must be an object", file=sys.stderr)
        sys.exit(1)

    return data


def selected_rows(config, mode):
    if mode == "latest":
        return [("latest", row) for row in config.get("latest", [])]
    if mode == "manual":
        return [("manual", row) for row in config.get("manual", [])]
    return (
        [("latest", row) for row in config.get("latest", [])]
        + [("manual", row) for row in config.get("manual", [])]
    )


def normalize_row(kind, row):
    if not isinstance(row, dict):
        raise ValueError(f"{kind} row must be an object")

    name = row.get("name")
    ubuntu = row.get("ubuntu")
    version = row.get("version", "")
    launchpad_files_url = row.get("launchpad_files_url", "")

    if not isinstance(name, str) or not VALID_NAME.match(name):
        raise ValueError(f"{kind} row has invalid name: {name!r}")
    if not isinstance(ubuntu, str) or not VALID_UBUNTU.match(ubuntu):
        raise ValueError(f"{name}: ubuntu must look like '22.04'")
    if kind == "manual" and not version:
        raise ValueError(f"{name}: manual row requires version")
    if version and not isinstance(version, str):
        raise ValueError(f"{name}: version must be a string")
    if launchpad_files_url and not isinstance(launchpad_files_url, str):
        raise ValueError(f"{name}: launchpad_files_url must be a string")

    return {
        "name": name,
        "ubuntu": ubuntu,
        "mode": kind,
        "version": version,
        "launchpad_files_url": launchpad_files_url,
    }


def build_matrix(config, mode):
    include = []
    names = set()
    for kind, row in selected_rows(config, mode):
        normalized = normalize_row(kind, row)
        if normalized["name"] in names:
            raise ValueError(f"duplicate matrix row name: {normalized['name']}")
        names.add(normalized["name"])
        include.append(normalized)
    return {"include": include}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        default=".github/dwarf-json-versions.json",
        type=Path,
        help="Path to DWARF JSON generation config",
    )
    parser.add_argument(
        "--mode",
        choices=VALID_MODES,
        default="all",
        help="Which matrix rows to emit",
    )
    args = parser.parse_args()

    try:
        matrix = build_matrix(load_config(args.config), args.mode)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(matrix, separators=(",", ":")))


if __name__ == "__main__":
    main()
