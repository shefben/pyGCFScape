#!/usr/bin/env python3
"""Validate a GCF file and display detailed information."""

from __future__ import annotations

import argparse
import sys

from pysteam.fs.cachefile import CacheFile
from py_gcf_validator.v6_validator import validate_v6


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a GCF file")
    parser.add_argument("gcf", help="Path to the GCF file")
    args = parser.parse_args(argv)

    try:
        cf = CacheFile.parse(args.gcf)
    except Exception as exc:  # pragma: no cover - handled in test
        print(f"Failed to parse {args.gcf}: {exc}")
        return 1

    h = cf.header
    print("Header")
    print(f"  format_version: {h.format_version}")
    print(f"  application_id: {h.application_id}")
    print(f"  application_version: {h.application_version}")
    print(f"  sector_size: {h.sector_size}")
    print(f"  sector_count: {h.sector_count}")

    m = cf.manifest
    print("\nManifest")
    print(f"  entries: {m.node_count}")
    print(f"  files: {m.file_count}")
    calc = m.calculate_checksum()
    print(f"  checksum: 0x{m.checksum:08X} ({'ok' if calc == m.checksum else 'mismatch'})")

    if cf.checksum_map is not None:
        cm = cf.checksum_map
        print("\nChecksum map")
        print(f"  file_entries: {cm.file_id_count}")
        print(f"  checksum_count: {cm.checksum_count}")
        ok = cm.verify_signature()
        print(f"  signature: {'ok' if ok else 'mismatch'}")

    errors = validate_v6(cf)
    if errors:
        print("\nErrors:")
        for e in errors:
            print(f"  - {e}")
        print("Validation failed")
        return 1

    print("\nValidation succeeded")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
