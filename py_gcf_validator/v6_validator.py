from __future__ import annotations

import os
import zlib
from typing import List

from pysteam.fs.cachefile import (
    CACHE_CHECKSUM_LENGTH,
    CacheFile,
    CacheFileBlockAllocationTableEntry,
    CacheFileManifestEntry,
    _bobhash,
)


def _read_c_string(blob: bytes, offset: int) -> bytes:
    end = blob.find(b"\0", offset)
    if end == -1:
        return b""
    return blob[offset:end]


def validate_v6(cache: CacheFile) -> List[str]:
    """Return a list of human readable error strings for ``cache``."""

    errors: List[str] = []

    h = cache.header
    # --------------------- File header ---------------------
    if h.header_version != 1:
        errors.append("FileHeader.HeaderVersion must be 1")
    if h.cache_type != 1:
        errors.append("FileHeader.CacheType must be 1 (GCF)")
    if h.format_version != 6:
        errors.append("FileHeader.FormatVersion must be 6")
    if h.dummy1 != 0:
        errors.append("FileHeader.Dummy0 must be 0")
    if h.is_mounted not in (0, 1):
        errors.append("FileHeader.IsMounted must be 0 or 1")
    if h.checksum != h.calculate_checksum():
        errors.append("FileHeader.Checksum mismatch")
    try:
        actual_size = os.path.getsize(cache.stream.name)
        if h.file_size != actual_size:
            errors.append(
                f"FileHeader.FileSize mismatch (header {h.file_size} != actual {actual_size})"
            )
    except Exception:
        pass

    # ---------------- Block allocation table ---------------
    bat = cache.blocks
    if bat.block_count != h.sector_count:
        errors.append("BlockAllocationTable.BlockCount mismatch with header")
    calc = (
        bat.block_count
        + bat.blocks_used
        + bat.last_block_used
        + bat.dummy1
        + bat.dummy2
        + bat.dummy3
        + bat.dummy4
    ) & 0xFFFFFFFF
    if bat.checksum != calc:
        errors.append("BlockAllocationTable header checksum mismatch")
    if not (0 <= bat.blocks_used <= bat.block_count):
        errors.append("BlockAllocationTable.BlocksUsed out of range")
    if bat.blocks_used and bat.last_block_used >= bat.block_count:
        errors.append("BlockAllocationTable.LastUsedBlock out of range")
    for i, blk in enumerate(bat.blocks):
        if blk.dummy0 != CacheFileBlockAllocationTableEntry.DUMMY0:
            errors.append(f"Block[{i}].Dummy0 expected {CacheFileBlockAllocationTableEntry.DUMMY0:#x}")
        if (
            blk._next_block_index not in (bat.block_count, 0xFFFFFFFF)
            and blk._next_block_index > bat.block_count
        ):
            errors.append(f"Block[{i}].NextBlockIndex out of range")
        if (
            blk._prev_block_index not in (bat.block_count, 0xFFFFFFFF)
            and blk._prev_block_index > bat.block_count
        ):
            errors.append(f"Block[{i}].PreviousBlockIndex out of range")
        if blk._first_sector_index >= cache.alloc_table.terminator:
            # valid terminator already handled in property
            pass
        elif blk._first_sector_index >= cache.alloc_table.sector_count:
            errors.append(f"Block[{i}].FirstClusterIndex out of range")
        if blk.entry_flags & CacheFileBlockAllocationTableEntry.FLAG_DATA:
            if blk.manifest_index >= cache.manifest.node_count:
                errors.append(f"Block[{i}].ManifestIndex out of range")

    # ---------------- File allocation table ----------------
    fat = cache.alloc_table
    if fat.sector_count != h.sector_count:
        errors.append("FileAllocationTable.ClusterCount mismatch with header")
    if fat.first_unused_entry > fat.sector_count:
        errors.append("FileAllocationTable.FirstUnusedEntry out of range")
    calc = (fat.sector_count + fat.first_unused_entry + fat.is_long_terminator) & 0xFFFFFFFF
    if fat.checksum != calc:
        errors.append("FileAllocationTable header checksum mismatch")
    terminator = 0xFFFFFFFF if fat.is_long_terminator else 0xFFFF
    for idx, nxt in enumerate(fat.entries):
        if nxt != terminator and nxt >= fat.sector_count:
            errors.append(f"FAT[{idx}] NextClusterIndex out of range")

    # ---------------------- Manifest -----------------------
    m = cache.manifest
    if m.header_version != 4:
        errors.append("Manifest.HeaderVersion must be 4")
    if m.application_id != h.application_id:
        errors.append("Manifest.ApplicationID mismatch")
    if m.application_version != h.application_version:
        errors.append("Manifest.ApplicationVersion mismatch")
    if m.hash_table_key_count and m.hash_table_key_count & (m.hash_table_key_count - 1):
        errors.append("Manifest.HashTableKeyCount must be power of two")
    if m.checksum != m.calculate_checksum():
        errors.append("Manifest checksum mismatch")

    if m.node_count == 0:
        errors.append("Manifest has no nodes")
    else:
        root = m.manifest_entries[0]
        if root.parent_index != 0xFFFFFFFF or root.next_index != 0 or root.name_offset != 0:
            errors.append("Root node is invalid")

    for idx, node in enumerate(m.manifest_entries):
        if node.name_offset >= m.name_size:
            errors.append(f"Node[{idx}] NameOffset out of range")
        is_file = (node.directory_flags & CacheFileManifestEntry.FLAG_IS_FILE) != 0
        if is_file:
            if (
                cache.checksum_map is not None
                and node.checksum_index != 0xFFFFFFFF
                and node.checksum_index >= len(cache.checksum_map.entries)
            ):
                errors.append(f"Node[{idx}] ChecksumIndex out of range")
        else:
            if node.checksum_index != 0xFFFFFFFF:
                errors.append(f"Node[{idx}] directory has checksum index")
        if node.parent_index != 0xFFFFFFFF and node.parent_index >= m.node_count:
            errors.append(f"Node[{idx}] ParentIndex out of range")
        if node.next_index != 0 and node.next_index >= m.node_count:
            errors.append(f"Node[{idx}] NextIndex out of range")
        if node.child_index != 0 and node.child_index >= m.node_count:
            errors.append(f"Node[{idx}] ChildIndex out of range")

    # Hash table validation
    if m.hash_table_key_count:
        mask = m.hash_table_key_count - 1
        for entry in m.manifest_entries:
            off = entry.name_offset
            name = _read_c_string(m.filename_table, off).lower()
            hval = _bobhash(name)
            bucket = hval & mask
            start = m.hash_table_keys[bucket]
            if start == 0xFFFFFFFF:
                errors.append(f"Hash table missing entry for {name.decode('utf-8', 'replace')}")
                continue
            idx = start - m.hash_table_key_count
            found = False
            while idx < len(m.hash_table_indices):
                val = m.hash_table_indices[idx]
                if val & 0x7FFFFFFF == entry.index:
                    found = True
                    break
                if val & 0x80000000:
                    break
                idx += 1
            if not found:
                errors.append(f"Hash table incorrect for {name.decode('utf-8', 'replace')}")

    for n in m.minimum_footprint_entries:
        if n >= m.node_count or not (
            m.manifest_entries[n].directory_flags & CacheFileManifestEntry.FLAG_IS_FILE
        ):
            errors.append(f"MinimumFootprint entry {n} invalid")
    for n in m.user_config_entries:
        if n >= m.node_count or not (
            m.manifest_entries[n].directory_flags & CacheFileManifestEntry.FLAG_IS_FILE
        ):
            errors.append(f"UserConfig entry {n} invalid")

    if cache.header.format_version > 1:
        if m.map_header_version != 1:
            errors.append("ManifestMap.HeaderVersion must be 1")
        if m.map_dummy1 != 0:
            errors.append("ManifestMap.Dummy0 must be 0")
    if len(m.manifest_map_entries) != m.node_count:
        errors.append("ManifestMap entries count mismatch")
    for idx, val in enumerate(m.manifest_map_entries):
        if val != cache.blocks.block_count and val >= cache.blocks.block_count:
            errors.append(f"ManifestMap[{idx}] FirstBlockIndex out of range")

    # -------------------- Checksum map ---------------------
    cm = cache.checksum_map
    if cm is None:
        errors.append("Missing checksum map")
    else:
        if cm.header_version != 1:
            errors.append("ChecksumMap.HeaderVersion must be 1")
        if cm.format_code != 0x14893721:
            errors.append("ChecksumMap.FormatCode mismatch")
        if cm.version != 1:
            errors.append("ChecksumMap.Dummy0 must be 1")
        if cm.file_id_count != len(cm.entries):
            errors.append("ChecksumMap.FileIdCount mismatch")
        if cm.checksum_count != len(cm.checksums):
            errors.append("ChecksumMap.ChecksumCount mismatch")
        if not cm.verify_signature():
            errors.append("ChecksumMap signature mismatch")
        if cm.latest_application_version != h.application_version:
            errors.append("ChecksumMap.ApplicationVersion mismatch")

    # -------------------- Data header ----------------------
    dh = cache.data_header
    if dh.application_version != h.application_version:
        errors.append("DataHeader.ApplicationVersion mismatch")
    if dh.sector_count != h.sector_count:
        errors.append("DataHeader.ClusterCount mismatch")
    if dh.sector_size != h.sector_size:
        errors.append("DataHeader.ClusterSize mismatch")
    calc = dh.calculate_checksum()
    if dh.checksum != calc:
        errors.append("DataHeader checksum mismatch")
    expected_size = dh.first_sector_offset + dh.sector_count * dh.sector_size
    if h.file_size != expected_size:
        errors.append("FileHeader.FileSize does not match data section size")

    # ------------------ File checksums ---------------------
    if cache.checksum_map is not None:
        for f in cache.root.all_files():
            me = f._manifest_entry
            ci = me.checksum_index
            if ci == 0xFFFFFFFF:
                continue
            count, start = cache.checksum_map.entries[ci]
            expected = cache.checksum_map.checksums[start:start + count]
            fh = f.open()
            try:
                data = fh.read()
            finally:
                fh.close()
            actual = []
            for offset in range(0, len(data), CACHE_CHECKSUM_LENGTH):
                chunk = data[offset:offset + CACHE_CHECKSUM_LENGTH]
                chk = (zlib.crc32(chunk) ^ zlib.adler32(chunk)) & 0xFFFFFFFF
                actual.append(chk)
            if not actual:
                chk = (zlib.crc32(b"") ^ zlib.adler32(b"")) & 0xFFFFFFFF
                actual.append(chk)
            if expected != actual:
                errors.append(f"Checksum mismatch for {f.path()}")

    return errors


def validate_v6_file(path: str) -> List[str]:
    cf = CacheFile.parse(path)
    try:
        return validate_v6(cf)
    finally:
        cf.close()
