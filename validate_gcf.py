#!/usr/bin/env python3
"""Validate a GCF file and display detailed information."""

from __future__ import annotations

import argparse
import sys
import zlib
from zlib import adler32

from pysteam.fs.cachefile import CacheFile, CACHE_CHECKSUM_LENGTH


def _check_file(entry, checksum_map):
    me = entry._manifest_entry
    ci = me.checksum_index
    if ci == 0xFFFFFFFF:
        return None
    count, start = checksum_map.entries[ci]
    expected = checksum_map.checksums[start:start + count]
    fh = entry.open()
    try:
        data = fh.read()
    finally:
        fh.close()
    actual = []
    for offset in range(0, len(data), CACHE_CHECKSUM_LENGTH):
        chunk = data[offset:offset + CACHE_CHECKSUM_LENGTH]
        actual.append((zlib.crc32(chunk) ^ adler32(chunk)) & 0xFFFFFFFF)
    if not actual:
        actual.append((zlib.crc32(b"") ^ adler32(b"")) & 0xFFFFFFFF)
    if expected != actual:
        return entry.path()
    return None


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

    errors = []
    if cf.checksum_map is not None:
        for f in cf.root.all_files():
            bad = _check_file(f, cf.checksum_map)
            if bad is not None:
                errors.append(bad)

    print("\nChecksum map")
    if cf.checksum_map is not None:
        cm = cf.checksum_map
        print(f"  file_entries: {cm.file_id_count}")
        print(f"  checksum_count: {cm.checksum_count}")
        ok = cm.verify_signature()
        print(f"  signature: {'ok' if ok else 'mismatch'}")
    if errors:
        print("  mismatched files:")
        for p in errors:
            print(f"    - {p}")
        print("Validation failed")
        return 1

    print("  all file checksums match")
    print("Validation succeeded")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
