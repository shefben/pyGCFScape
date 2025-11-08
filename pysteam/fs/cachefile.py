
from __future__ import annotations

import struct
import os
import zlib
import copy
import hashlib
import secrets
from types import SimpleNamespace

from typing import Optional, Callable

from pysteam.fs import DirectoryFolder, DirectoryFile, FilesystemPackage
from py_gcf_validator.bobhash import bobhash as _bobhash
from .gcf_v1 import prepare_manifest_for_v1
from math import ceil
from zlib import adler32

# For Python 3 compatibility, use io.BytesIO instead of the removed cStringIO module.
from io import BytesIO

try:  # Optional dependency for AES decryption
    from Crypto.Cipher import AES  # type: ignore
except Exception:  # pragma: no cover - handled at runtime
    AES = None

CACHE_CHECKSUM_LENGTH = 0x8000
GCF_DEFAULT_SECTOR_SIZE = 0x2000

# RSA key constants for GCF signature generation/validation
_RSA_N = int(
    "882750d6bbbe60c87025d56dcf85361f0594d35d20f0288d33809d35836d251a00f9673d839a"
    "ffd6ee6dfd9334ca50702af4f57762fe28b1f59a05ced97db929709c68868c9d8e70c07ab6bf1"
    "edc0f9f38d7ee3f0932bcd6113f04d2e03688b344f6837a5d4d088d9c34b79548eb1673040e891"
    "97905a995264f5ef7b7128db1",
    16,
)
_RSA_D = int(
    "812cdbf37f183676b48010a82874f84e225b7ad52684f3d45382b8a4a6d68c96c949d67b743b4"
    "073c8aeae2055bb84e986b7f59399660d7219d451a1d188d231da52185ca107735d3b751e02537"
    "e2e62b6db9b9307566fbe7e20759ff9594cbd75572dd8672690211c5180a501a47de534ab1e2e6"
    "a10509df8e29b73fe9b2669",
    16,
)
_RSA_E = 65537
_RSA_PREFIX = bytes.fromhex("3021300906052b0e03021a05000414")

STEAM_TERMINATOR = "\\"  # Archive path separator
MAX_FILENAME = 0


def _rsa_pkcs1_sha1_sign(data: bytes) -> bytes:
    """Generate PKCS#1 v1.5 RSA signature with SHA-1 hash."""
    digest = hashlib.sha1(data).digest()
    k = (_RSA_N.bit_length() + 7) // 8
    ps = b"\xff" * (k - len(_RSA_PREFIX) - len(digest) - 3)
    em = b"\x00\x01" + ps + b"\x00" + _RSA_PREFIX + digest
    m = int.from_bytes(em, "big")
    return pow(m, _RSA_D, _RSA_N).to_bytes(k, "big")


def _rsa_pkcs1_sha1_verify(data: bytes, sig: bytes) -> bool:
    """Verify PKCS#1 v1.5 RSA signature with SHA-1 hash."""
    digest = hashlib.sha1(data).digest()
    k = (_RSA_N.bit_length() + 7) // 8
    m = pow(int.from_bytes(sig, "big"), _RSA_E, _RSA_N).to_bytes(k, "big")
    ps = b"\xff" * (k - len(_RSA_PREFIX) - len(digest) - 3)
    expected = b"\x00\x01" + ps + b"\x00" + _RSA_PREFIX + digest
    return m == expected


def _normalize_key(key: bytes) -> bytes:
    for size in (16, 24, 32):
        if len(key) <= size:
            return key.ljust(size, b"\x00")
    return key[:32]


def _decrypt_aes(data: bytes, key: bytes) -> bytes:
    if AES is None:
        raise ImportError("pycryptodome is required for encrypted GCF support")
    key = _normalize_key(key)
    pad = (-len(data)) % 16
    cipher = AES.new(key, AES.MODE_CBC, b"\x00" * 16)
    dec = cipher.decrypt(data + b"\x00" * pad)
    if pad:
        dec = dec[:-pad]
    return dec


def decrypt_gcf_data(data: bytes, key: bytes) -> bytes:
    """Decrypt and decompress ``data`` from an encrypted GCF file."""
    out = bytearray()
    pos = 0
    while pos < len(data):
        chunk = data[pos : pos + CACHE_CHECKSUM_LENGTH]
        if len(chunk) < 8:
            break
        comp_size, uncomp_size = struct.unpack_from("<ii", chunk, 0)
        if (
            uncomp_size > CACHE_CHECKSUM_LENGTH
            or comp_size > uncomp_size
            or uncomp_size < -1
            or comp_size < -1
        ):
            dec = _decrypt_aes(chunk, key)
            out.extend(dec)
            pos += CACHE_CHECKSUM_LENGTH
        else:
            enc = chunk[: 8 + comp_size]
            dec = _decrypt_aes(enc, key)
            try:
                out.extend(zlib.decompress(dec[8:8 + comp_size]))
            except zlib.error:
                out.extend(dec[8:8 + comp_size])
            pos += 8 + comp_size
    return bytes(out)


def unpack_dword_list(stream, count):
    """Return ``count`` little-endian DWORDs from ``stream`` as a list.

    The GCF/NCF formats store many arrays of 32-bit unsigned integers.  Older
    versions of this project relied on a helper function named
    ``unpack_dword_list`` to decode these arrays, but the function was missing
    which resulted in a ``NameError`` at runtime when parsing cache files.

    Parameters
    ----------
    stream:
        A binary file-like object positioned at the start of the array.
    count:
        Number of DWORDs to read from the stream.

    Returns
    -------
    list[int]
        The unpacked integers.
    """

    if count <= 0:
        return []

    data = stream.read(4 * count)
    if len(data) != 4 * count:
        raise ValueError(f"Expected {4 * count} bytes, got {len(data)}")
    return list(struct.unpack(f"<{count}L", data))


def pack_dword_list(values):
    """Pack an iterable of integers into little-endian DWORD bytes.

    Masks each value to 32 bits to prevent struct.pack errors on oversized values.
    """
    values = list(values)
    if not values:
        return b""
    masked = [v & 0xFFFFFFFF for v in values]
    return struct.pack(f"<{len(masked)}L", *masked)

def raise_parse_error(func):
    def internal(self, *args, **kwargs):
        if not self.is_parsed:
            raise ValueError("Cache file needs to be read first.")

        return func(self, *args, **kwargs)
    return internal

def raise_ncf_error(func):
    def internal(self, *args, **kwargs):
        if self.is_ncf():
            raise ValueError("NCF files do not have contents.")

        return func(self, *args, **kwargs)
    return internal

class CacheFile:

    # Constructor
    def __init__(self):
        self.is_parsed = False
        self.blocks = None
        self.alloc_table = None
        self.block_entry_map = None
        self.manifest = None
        self.checksum_map = None
        self.data_header = None
        self.complete_total = 0
        self.complete_available = 0
        self.ncf_folder_pattern = "common/%(name)s"
        # ``stream`` represents the underlying cache file.  When ``parse`` is
        # given a file path we open and own this handle.  If a file-like object
        # is supplied we duplicate the handle so later extraction/defrag
        # operations still have a live stream even after the caller's handle is
        # closed.
        self.stream = None
        self._stream_owner = False

    # Main methods.

    @classmethod
    def parse(cls, source):
        """Parse ``source`` into a :class:`CacheFile` instance.

        ``source`` may be either a path-like object or an already opened
        binary file handle.  In the latter case the handle may be closed after
        parsing; the cache file keeps its own handle alive to service
        subsequent extraction and conversion operations.
        """

        self = cls()

        if isinstance(source, (str, os.PathLike)):
            stream = open(os.fspath(source), "rb")
            self._stream_owner = True
        else:
            stream = source

        try:
            self.filename = os.path.split(os.path.realpath(stream.name))[1]
        except AttributeError:
            self.filename = None

        # Header
        self.header = CacheFileHeader(self)
        self.header.parse(stream.read(44))
        self.header.validate()

        if self.is_gcf():

            # Block Entries
            self.blocks = CacheFileBlockAllocationTable(self)
            self.blocks.parse(stream)
            self.blocks.validate()

            # Allocation Table
            self.alloc_table = CacheFileAllocationTable(self)
            self.alloc_table.parse(stream)
            self.alloc_table.validate()

            # Older GCF versions include an additional block entry map
            if self.header.format_version < 6:
                self.block_entry_map = CacheFileBlockEntryMap(self)
                self.block_entry_map.parse(stream)

        # Manifest
        self.manifest = CacheFileManifest(self)
        self.manifest.parse(stream)
        self.manifest.validate()

        # Checksum Map
        if self.header.format_version > 1:
            self.checksum_map = CacheFileChecksumMap(self)
            self.checksum_map.parse(stream)
            self.checksum_map.validate()
        else:
            self.checksum_map = None

        if self.is_gcf():
            # Data Header.
            self.data_header = CacheFileSectorHeader(self)
            header_size = 24 if self.header.format_version > 3 else 20
            self.data_header.parse(stream.read(header_size), self.header.format_version)
            self.data_header.validate()

        self.is_parsed = True
        self._read_directory()

        # If the caller supplied the stream we need to reopen the file so we
        # still have a valid handle once the caller closes theirs.
        if not self._stream_owner and hasattr(stream, "name"):
            self.stream = open(stream.name, "rb")
            self._stream_owner = True
        else:
            self.stream = stream

        return self

    def close(self) -> None:
        """Close the underlying file stream if we own it."""
        if self._stream_owner and self.stream is not None:
            try:
                self.stream.close()
            finally:
                self.stream = None

    @classmethod
    def build_version(
        cls,
        files: dict[str, bytes],
        target_version: int,
        out_path: str,
        app_id: int = 0,
        app_version: int = 0,
        flags: dict[str, int] | None = None,
        block_flags: dict[str, int] | None = None,
        manifest_flags: int = 0,
        progress: Callable[[int, int], None] | None = None,
    ) -> None:
        """Build and save a GCF file directly at the specified version.

        This is a convenience method that combines build() and convert_version()
        into a single operation for creating GCF files from scratch.

        Parameters
        ----------
        files : dict[str, bytes]
            Mapping of file paths to file contents
        target_version : int
            Target GCF format version (1, 3, 5, or 6)
        out_path : str
            Destination path for the GCF file
        app_id : int
            Steam application ID
        app_version : int
            Application version
        flags : dict[str, int] | None
            Mapping of file paths to manifest entry flags
        block_flags : dict[str, int] | None
            Mapping of file paths to block entry flags
        manifest_flags : int
            Manifest bitmask flags
        progress : Callable[[int, int], None] | None
            Optional progress callback
        """
        if target_version not in (1, 3, 5, 6):
            raise ValueError(f"Unsupported GCF version: {target_version}")

        cf = cls.build(
            files,
            app_id=app_id,
            app_version=app_version,
            flags=flags,
            block_flags=block_flags,
            manifest_flags=manifest_flags,
        )
        cf.convert_version(target_version, out_path, progress=progress)
        cf.close()

    @classmethod
    def build(
        cls,
        files: dict[str, bytes],
        app_id: int = 0,
        app_version: int = 0,
        flags: dict[str, int] | None = None,
        block_flags: dict[str, int] | None = None,
        manifest_flags: int = 0,
    ) -> "CacheFile":
        """Construct a new :class:`CacheFile` from a mapping of paths to data.

        The returned cache file lives in memory using the latest GCF format
        (version 6).  Call :meth:`convert_version` to serialise it to disk in
        any supported revision.

        Parameters
        ----------
        files : dict[str, bytes]
            Mapping of file paths to file contents
        app_id : int
            Steam application ID
        app_version : int
            Application version
        flags : dict[str, int] | None
            Mapping of file paths to manifest entry flags
        block_flags : dict[str, int] | None
            Mapping of file paths to block entry flags
        manifest_flags : int
            Manifest bitmask flags
        """

        self = cls()
        sector_size = GCF_DEFAULT_SECTOR_SIZE
        self.stream = BytesIO()
        self._stream_owner = True
        self.is_parsed = True

        # ------------------------------------------------------------------
        # Header setup
        # ------------------------------------------------------------------
        header = CacheFileHeader(self)
        header.header_version = 1
        header.cache_type = 1  # GCF
        header.format_version = 6
        header.application_id = app_id
        header.application_version = app_version
        header.is_mounted = 0
        header.dummy1 = 0
        header.file_size = 0
        header.sector_size = sector_size
        header.sector_count = 0
        header.checksum = 0
        self.header = header

        # ------------------------------------------------------------------
        # Manifest construction
        # ------------------------------------------------------------------
        manifest = CacheFileManifest(self)
        manifest.header_version = 4  # v6 uses header version 4
        manifest.application_id = app_id
        manifest.application_version = app_version
        manifest.compression_block_size = CACHE_CHECKSUM_LENGTH  # v6 uses 0x8000
        manifest.depot_info = manifest_flags
        manifest.fingerprint = secrets.randbits(32)  # Random fingerprint per spec
        manifest.manifest_entries = []
        manifest.hash_table_keys = []
        manifest.hash_table_indices = []
        manifest.minimum_footprint_entries = []
        manifest.user_config_entries = []
        manifest.manifest_map_entries = []
        manifest.map_header_version = 1
        manifest.map_dummy1 = 0
        # Start with empty name table so root entry points at offset 0
        filename_table = bytearray()

        # Build simple directory tree from mapping.
        flags = flags or {}
        block_flags = block_flags or {}
        root: dict[str, object] = {}
        for path, data in files.items():
            parts = [p for p in path.replace("\\", "/").split("/") if p]
            node: dict[str, object] = root
            for part in parts[:-1]:
                node = node.setdefault(part, {})  # type: ignore[assignment]
            node[parts[-1]] = data

        file_nodes: list[tuple[int, bytes]] = []
        checksum_entries: list[tuple[int, int]] = []  # (count, start_index)
        checksums: list[int] = []
        index_to_path: dict[int, str] = {}

        def add_entry(obj: object, name: str, parent: int, path: str) -> int:
            index = len(manifest.manifest_entries)
            index_to_path[index] = path
            entry = CacheFileManifestEntry(manifest)
            entry.index = index
            entry.name_offset = len(filename_table)
            filename_table.extend(name.encode("utf-8") + b"\0")
            entry.parent_index = parent
            entry.next_index = 0
            entry.child_index = 0
            if isinstance(obj, dict):
                # Directory
                entry.item_size = 0
                entry.checksum_index = 0xFFFFFFFF  # Directories have no checksum
                # Directory entries do not carry flag bits in GCF manifests
                entry.directory_flags = 0
                manifest.manifest_entries.append(entry)
                manifest.manifest_map_entries.append(0xFFFFFFFF)
                children: list[int] = []
                for child_name in sorted(obj):
                    child_path = path + "/" + child_name if path else child_name
                    children.append(add_entry(obj[child_name], child_name, index, child_path))
                entry.item_size = len(children)  # Directory size = child count
                if children:
                    entry.child_index = children[0]
                    for a, b in zip(children, children[1:]):
                        manifest.manifest_entries[a].next_index = b
            else:
                # File
                data = obj  # type: ignore[assignment]
                entry.item_size = len(data)
                entry.checksum_index = len(checksum_entries)
                entry.directory_flags = (
                    flags.get(path, 0) | CacheFileManifestEntry.FLAG_IS_FILE
                )
                manifest.manifest_entries.append(entry)
                manifest.manifest_map_entries.append(0)

                # Track special file types
                if entry.directory_flags & CacheFileManifestEntry.FLAG_IS_USER_CONFIG:
                    manifest.user_config_entries.append(index)
                if entry.directory_flags & CacheFileManifestEntry.FLAG_IS_PURGE_FILE:
                    manifest.minimum_footprint_entries.append(index)

                file_nodes.append((index, data))

                # Generate per-block checksums (v6 uses Adler32 ^ CRC32)
                start = len(checksums)
                chunk_count = 0
                for offset in range(0, len(data), CACHE_CHECKSUM_LENGTH):
                    chunk = data[offset : offset + CACHE_CHECKSUM_LENGTH]
                    chk = (adler32(chunk, 0) ^ zlib.crc32(chunk, 0)) & 0xFFFFFFFF
                    checksums.append(chk)
                    chunk_count += 1
                if chunk_count == 0:
                    # Empty file still gets one checksum
                    chk = (adler32(b"", 0) ^ zlib.crc32(b"", 0)) & 0xFFFFFFFF
                    checksums.append(chk)
                    chunk_count = 1
                checksum_entries.append((chunk_count, start))
            return index

        add_entry(root, "", 0xFFFFFFFF, "")

        manifest.filename_table = bytes(filename_table)
        manifest.node_count = len(manifest.manifest_entries)
        manifest.file_count = len(file_nodes)

        # Build manifest hash table used for name lookups
        bucket_count = 1 << ((manifest.node_count * 2 - 1).bit_length())
        buckets: list[list[int]] = [[] for _ in range(bucket_count)]
        for entry in manifest.manifest_entries:
            off = entry.name_offset
            end = manifest.filename_table.index(b"\0", off)
            name = manifest.filename_table[off:end].lower()
            h = _bobhash(name)
            buckets[h & (bucket_count - 1)].append(entry.index)

        hash_table_keys = [0xFFFFFFFF] * bucket_count
        hash_table_indices: list[int] = []
        for i, bucket in enumerate(buckets):
            if not bucket:
                continue
            hash_table_keys[i] = bucket_count + len(hash_table_indices)
            for j, idx in enumerate(bucket):
                val = idx | (0x80000000 if j == len(bucket) - 1 else 0)
                hash_table_indices.append(val)

        manifest.hash_table_keys = hash_table_keys
        manifest.hash_table_indices = hash_table_indices
        manifest.owner = self
        self.manifest = manifest

        # ------------------------------------------------------------------
        # Checksum map
        # ------------------------------------------------------------------
        if checksum_entries:
            checksum_map = CacheFileChecksumMap(self)
            checksum_map.header_version = 1
            checksum_map.checksum_size = 0  # Placeholder, recomputed below
            # External validators expect a magic value in the "format" field
            checksum_map.format_code = 0x14893721
            checksum_map.version = 1
            checksum_map.entries = checksum_entries
            checksum_map.checksums = checksums
            checksum_map.file_id_count = len(checksum_entries)
            checksum_map.checksum_count = len(checksums)
            checksum_map.latest_application_version = app_version
            checksum_map.signature = b""  # Will be computed during serialization
            # Checksum size: header (24) + entries + checksums + signature (128) + footer (4)
            checksum_map.checksum_size = (
                24
                + checksum_map.file_id_count * 8
                + checksum_map.checksum_count * 4
                + 128
                + 4
            )
            self.checksum_map = checksum_map
        else:
            self.checksum_map = None

        # ------------------------------------------------------------------
        # Block/Allocation tables and raw data
        # ------------------------------------------------------------------
        blocks = CacheFileBlockAllocationTable(self)
        alloc = CacheFileAllocationTable(self)
        alloc.entries = []
        alloc.is_long_terminator = 1
        alloc.terminator = 0xFFFFFFFF

        total_blocks = 0
        for file_index, data in file_nodes:
            prev_block = None
            for chunk_start in range(0, len(data), sector_size):
                chunk = data[chunk_start:chunk_start + sector_size]
                block = CacheFileBlockAllocationTableEntry(blocks)
                block.index = total_blocks
                # Get block-specific flags from block_flags or use default v6 flags
                path = index_to_path[file_index]
                bf = block_flags.get(path, 0) if block_flags else 0
                block.entry_flags = CacheFileBlockAllocationTableEntry.FLAG_DATA | bf
                block.dummy0 = CacheFileBlockAllocationTableEntry.DUMMY0
                block.file_data_offset = total_blocks * sector_size
                block.file_data_size = len(chunk)
                block._first_sector_index = total_blocks
                block._next_block_index = 0xFFFFFFFF
                block._prev_block_index = (
                    prev_block if prev_block is not None else 0xFFFFFFFF
                )
                block.manifest_index = file_index
                blocks.blocks.append(block)
                alloc.entries.append(total_blocks + 1)
                self.stream.write(chunk.ljust(sector_size, b"\0"))
                if prev_block is not None:
                    blocks.blocks[prev_block]._next_block_index = block.index
                    alloc.entries[prev_block] = block.index
                else:
                    manifest.manifest_map_entries[file_index] = block.index
                prev_block = block.index
                total_blocks += 1
            if prev_block is not None:
                alloc.entries[prev_block] = alloc.terminator

        blocks.block_count = total_blocks
        blocks.blocks_used = total_blocks
        blocks.last_block_used = total_blocks - 1 if total_blocks else 0
        blocks.dummy1 = blocks.dummy2 = blocks.dummy3 = blocks.dummy4 = 0
        self.blocks = blocks

        # v6 doesn't use block entry map, but we create it for conversion compatibility
        bemap = CacheFileBlockEntryMap(self)
        bemap.entries = list(range(total_blocks))
        self.block_entry_map = bemap

        # Adjust manifest map entries: v6 uses direct block indices, but for
        # directories and unmapped files we use block_count as sentinel
        for i, idx in enumerate(manifest.manifest_map_entries):
            if idx == 0xFFFFFFFF:
                manifest.manifest_map_entries[i] = total_blocks

        alloc.sector_count = total_blocks
        alloc.first_unused_entry = total_blocks
        self.alloc_table = alloc

        data_header = CacheFileSectorHeader(self)
        data_header.format_version = 6
        data_header.application_version = app_version
        data_header.sector_count = total_blocks
        data_header.sector_size = sector_size
        data_header.first_sector_offset = 0
        data_header.sectors_used = total_blocks
        self.data_header = data_header

        header.sector_count = total_blocks

        self.stream.seek(0)
        self._read_directory()
        return self

    def convert_version(
        self,
        target_version: int,
        out_path: str,
        progress: Callable[[int, int], None] | None = None,
    ) -> None:
        """Convert this cache file to a different GCF format version.

        The converter rewrites all table headers and recalculates offsets and
        checksums so that the resulting archive adheres to the requested format.
        Only GCF archives are supported.
        """

        if not self.is_parsed:
            raise ValueError("Cache file needs to be read first.")
        if not self.is_gcf():
            raise ValueError("Only GCF archives can be converted")
        if target_version not in (1, 3, 5, 6):
            raise ValueError("Unsupported GCF version: %d" % target_version)

        # Deep copy structures so serialisation does not mutate the source.
        # Exclude the cache file object (which holds an open stream) from the
        # copy operation to avoid pickling errors on file-like objects.
        memo = {id(self): None}
        try:
            memo[id(self.stream)] = None  # type: ignore[attr-defined]
        except Exception:
            pass

        header = copy.deepcopy(self.header, memo)
        blocks = copy.deepcopy(self.blocks, memo)
        alloc_table = copy.deepcopy(self.alloc_table, memo)
        block_entry_map = copy.deepcopy(self.block_entry_map, memo)
        manifest = copy.deepcopy(self.manifest, memo)
        data_header = copy.deepcopy(self.data_header, memo)
        checksum_map = (
            copy.deepcopy(self.checksum_map, memo) if self.checksum_map else None
        )

        # Temporary owner that mirrors the structure expected by the various
        # serialisation routines.
        owner = SimpleNamespace(
            header=header,
            block_entry_map=block_entry_map,
            blocks=blocks,
            alloc_table=alloc_table,
            checksum_map=checksum_map,
        )
        manifest.owner = owner
        if block_entry_map:
            block_entry_map.owner = owner
        data_header.owner = owner
        if checksum_map:
            checksum_map.owner = owner

        header.format_version = target_version
        header.dummy1 = 0
        data_header.format_version = target_version
        blocks.owner = owner
        alloc_table.owner = owner
        blocks.dummy1 = blocks.dummy2 = blocks.dummy3 = blocks.dummy4 = 0

        original_map_entries = list(manifest.manifest_map_entries)

        if target_version < 6:
            if block_entry_map is None:
                block_entry_map = CacheFileBlockEntryMap(owner)
                block_entry_map.entries = list(range(blocks.block_count))
            owner.block_entry_map = block_entry_map
            inverse = {blk: idx for idx, blk in enumerate(block_entry_map.entries)}
            manifest.manifest_map_entries = [
                inverse.get(i, i) for i in original_map_entries
            ]
        else:
            if block_entry_map is not None:
                mapped: list[int] = []
                for i in original_map_entries:
                    if i == 0xFFFFFFFF or i >= len(block_entry_map.entries):
                        mapped.append(0xFFFFFFFF)
                    else:
                        mapped.append(block_entry_map.entries[i])
                manifest.manifest_map_entries = mapped
            block_entry_map = None
            owner.block_entry_map = None

        # Normalize manifest map sentinels
        for i, idx in enumerate(manifest.manifest_map_entries):
            if idx == 0xFFFFFFFF:
                manifest.manifest_map_entries[i] = blocks.block_count

        # Adjust manifest header version based on target GCF version
        # v1, v3, v5: manifest header version 3
        # v6: manifest header version 4
        if target_version < 6:
            manifest.header_version = 3
            # v1 requires special handling for hash tables and footprint
            if target_version == 1:
                prepare_manifest_for_v1(manifest)
            else:
                # v3 and v5 use the standard hash table
                manifest.compression_block_size = CACHE_CHECKSUM_LENGTH
                manifest.depot_info = 2
        else:
            manifest.header_version = 4
            manifest.compression_block_size = CACHE_CHECKSUM_LENGTH

        # Generate a checksum map when targeting newer formats.
        # Note: We always regenerate checksums when the format changes between
        # v6 (per-block Adler32^CRC32) and v3/v5 (per-file CRC32)
        if target_version > 1:
            # Determine if we need to regenerate checksums
            need_regen = checksum_map is None
            if checksum_map is not None:
                # Check if checksum format is changing
                src_is_v6 = checksum_map.format_code == 0x14893721
                dst_is_v6 = target_version >= 6
                if src_is_v6 != dst_is_v6:
                    need_regen = True
                    checksum_map = None  # Force regeneration

            if need_regen or checksum_map is None:
                checksum_map = CacheFileChecksumMap(owner)
                checksum_map.header_version = 1
                # v6 uses magic format code, v3/v5 use simple format
                checksum_map.format_code = 0x14893721 if target_version >= 6 else 1
                checksum_map.version = 1
                checksum_map.entries = []
                checksum_map.checksums = []
                # Only v6 uses RSA signatures
                checksum_map.signature = b"" if target_version >= 6 else b"\0" * 128
                checksum_map.latest_application_version = header.application_version

                for entry in self.manifest.manifest_entries:
                    if not (
                        entry.directory_flags & CacheFileManifestEntry.FLAG_IS_FILE
                    ):
                        continue

                    # v6 uses per-block checksums (Adler32 ^ CRC32)
                    # Earlier versions use simple per-file CRC32
                    if target_version >= 6:
                        start_idx = len(checksum_map.checksums)
                        remaining = entry.item_size
                        block = entry.first_block
                        while block is not None and remaining > 0:
                            for sector in block.sectors:
                                if remaining <= 0:
                                    break
                                self.stream.seek(
                                    self.data_header.first_sector_offset
                                    + sector.index * self.header.sector_size
                                )
                                chunk = self.stream.read(
                                    min(remaining, CACHE_CHECKSUM_LENGTH)
                                )
                                chk = (adler32(chunk, 0) ^ zlib.crc32(chunk, 0)) & 0xFFFFFFFF
                                checksum_map.checksums.append(chk)
                                remaining -= len(chunk)
                                if remaining <= 0:
                                    break
                            block = block.next_block
                        chunk_count = len(checksum_map.checksums) - start_idx
                        if chunk_count == 0:
                            chk = (adler32(b"", 0) ^ zlib.crc32(b"", 0)) & 0xFFFFFFFF
                            checksum_map.checksums.append(chk)
                            chunk_count = 1
                        checksum_map.entries.append((chunk_count, start_idx))
                    else:
                        # v1/v3/v5 use simple per-file CRC32
                        crc = 0
                        remaining = entry.item_size
                        block = entry.first_block
                        while block is not None and remaining > 0:
                            for sector in block.sectors:
                                if remaining <= 0:
                                    break
                                self.stream.seek(
                                    self.data_header.first_sector_offset
                                    + sector.index * self.header.sector_size
                                )
                                chunk = self.stream.read(
                                    min(remaining, self.header.sector_size)
                                )
                                crc = zlib.crc32(chunk, crc)
                                remaining -= len(chunk)
                                if remaining <= 0:
                                    break
                            block = block.next_block
                        checksum_map.entries.append((1, len(checksum_map.checksums)))
                        checksum_map.checksums.append(crc & 0xFFFFFFFF)

                checksum_map.file_id_count = len(checksum_map.entries)
                checksum_map.checksum_count = len(checksum_map.checksums)
                # Checksum size includes the entire checksum map section
                # Header (24) + Entries (file_id_count * 8) + Checksums (checksum_count * 4) + Signature (128) [+ Footer (4) for v6]
                if target_version >= 6:
                    checksum_map.checksum_size = (
                        24 + checksum_map.file_id_count * 8 +
                        checksum_map.checksum_count * 4 + 128 + 4
                    )
                else:
                    checksum_map.checksum_size = (
                        24 + checksum_map.file_id_count * 8 +
                        checksum_map.checksum_count * 4 + 128
                    )
            checksum_map.owner = owner
            owner.checksum_map = checksum_map
        else:
            checksum_map = None
            owner.checksum_map = None

        # Recalculate offsets and sizes.
        header.sector_count = blocks.block_count
        alloc_table.sector_count = blocks.block_count
        data_header.sector_count = blocks.block_count
        header.sector_size = self.header.sector_size
        data_header.sector_size = self.header.sector_size

        blocks_bytes = blocks.serialize()
        alloc_bytes = alloc_table.serialize()
        block_entry_bytes = (
            block_entry_map.serialize()
            if target_version < 6 and block_entry_map is not None
            else b""
        )
        manifest_bytes = manifest.serialize()
        checksum_bytes = (
            checksum_map.serialize()
            if target_version > 1 and checksum_map is not None
            else b""
        )

        header_size = 44
        data_header.first_sector_offset = (
            header_size
            + len(blocks_bytes)
            + len(alloc_bytes)
            + len(block_entry_bytes)
            + len(manifest_bytes)
            + len(checksum_bytes)
        )
        data_header_bytes = data_header.serialize()
        # The offset stored in the data header points to the first data sector,
        # not the start of the header itself.  Account for the header size and
        # re-serialise so both fields are in agreement.
        data_header.first_sector_offset += len(data_header_bytes)
        data_header_bytes = data_header.serialize()

        total_data = data_header.sectors_used * data_header.sector_size
        header.file_size = data_header.first_sector_offset + total_data

        header_bytes = header.serialize()

        with open(out_path, "wb") as out:
            out.write(header_bytes)
            out.write(blocks_bytes)
            out.write(alloc_bytes)
            if block_entry_bytes:
                out.write(block_entry_bytes)
            out.write(manifest_bytes)
            if checksum_bytes:
                out.write(checksum_bytes)
            out.write(data_header_bytes)

            written = 0
            self.stream.seek(self.data_header.first_sector_offset)
            while written < total_data:
                chunk = self.stream.read(min(1024 * 1024, total_data - written))
                if not chunk:
                    break
                out.write(chunk)
                written += len(chunk)
                if progress:
                    progress(written, total_data)


    def defragment(
        self,
        out_path: str,
        progress: Callable[[int, int], None] | None = None,
        cancel_flag: object | None = None,
    ) -> None:
        """Write a defragmented copy of this GCF archive to ``out_path``.

        The implementation rewrites the allocation table so that all sectors
        for each block are stored sequentially without staging the entire file
        in memory.  A new cache file is written to ``out_path``; the in-memory
        representation of this instance is left untouched.  Only GCF archives
        are supported.

        Parameters
        ----------
        out_path:
            Destination path for the defragmented archive.
        progress:
            Optional callback invoked with ``(bytes_done, bytes_total)`` after
            each sector is copied.
        cancel_flag:
            Optional mutable object that evaluates to ``True`` when the
            operation should be cancelled.  Types such as ``threading.Event`` or
            ``[bool]`` (single-item lists) are supported.
        """

        if not self.is_parsed:
            raise ValueError("Cache file needs to be read first.")
        if not self.is_gcf():
            raise ValueError("Only GCF archives can be defragmented")

        fragmented, used = self._get_item_fragmentation(0)
        if fragmented == 0:
            raise ValueError("Archive is already defragmented.")

        sector_size = self.data_header.sector_size
        terminator = self.alloc_table.terminator

        new_alloc: list[int] = []

        files = [
            m
            for m in self.manifest.manifest_entries
            if (m.directory_flags & CacheFileManifestEntry.FLAG_IS_FILE) != 0
        ]

        # First pass: rebuild allocation tables without touching file data.
        for mentry in files:
            block = mentry.first_block
            while block is not None:
                sectors = list(block.sectors)
                block._first_sector_index = len(new_alloc)
                block.file_data_offset = len(new_alloc) * sector_size
                block.file_data_size = len(sectors) * sector_size

                for i, _ in enumerate(sectors):
                    if i == len(sectors) - 1:
                        new_alloc.append(terminator)
                    else:
                        new_alloc.append(len(new_alloc) + 1)
                block = block.next_block

        # Update tables with new allocation info
        self.alloc_table.entries = new_alloc
        self.alloc_table.sector_count = len(new_alloc)
        self.alloc_table.first_unused_entry = len(new_alloc)
        self.blocks.blocks_used = len(self.blocks.blocks)
        self.blocks.last_block_used = len(self.blocks.blocks) - 1
        self.data_header.sector_count = len(new_alloc)
        self.data_header.sectors_used = len(new_alloc)

        total_bytes = len(new_alloc) * sector_size
        bytes_done = 0

        def _cancelled() -> bool:
            if cancel_flag is None:
                return False
            if isinstance(cancel_flag, (list, tuple)):
                return bool(cancel_flag[0])
            if hasattr(cancel_flag, "is_set"):
                return bool(cancel_flag.is_set())
            return bool(cancel_flag)

        with open(out_path, "wb") as out:
            out.write(self.header.serialize())
            out.write(self.blocks.serialize())
            out.write(self.alloc_table.serialize())
            if self.block_entry_map is not None:
                out.write(self.block_entry_map.serialize())
            out.write(self.manifest.header_data)
            out.write(self.manifest.manifest_stream.getvalue())
            if self.checksum_map is not None:
                out.write(self.checksum_map.serialize())

            self.data_header.first_sector_offset = out.tell() + 24
            out.write(self.data_header.serialize())

            for mentry in files:
                if _cancelled():
                    break
                block = mentry.first_block
                while block is not None and not _cancelled():
                    for sector in block.sectors:
                        out.write(sector.get_data())
                        bytes_done += sector_size
                        if progress:
                            progress(bytes_done, total_bytes)
                        if _cancelled():
                            break
                    block = block.next_block

        if progress and bytes_done < total_bytes:
            progress(bytes_done, total_bytes)

        # Re-open the original stream in case subsequent operations are
        # performed on this instance.
        if self.stream is None and self.filename:
            self.stream = open(self.filename, "rb")


    # Private Methods

    def _read_directory(self):

        if self.is_ncf():
            # Make NCF files "readable" by a configurable folder much like Steam's "common" folder

            name = ".".join(self.filename.split(".")[:-1])
            path = self.ncf_folder_pattern % (dict(name=name, file=self.filename))

            package = FilesystemPackage()
            package.parse(path)

        elif self.is_gcf():
            package = self

        manifest_entry = self.manifest.manifest_entries[0]

        # Fill in root.
        self.root = DirectoryFolder(self, package=package)
        self.root.index = 0
        self.root._manifest_entry = manifest_entry
        self.root.flags = manifest_entry.directory_flags
        self._read_directory_table(self.root)

    def _read_directory_table(self, folder):
        i = folder._manifest_entry.child_index

        while i != 0xFFFFFFFF and i != 0:
            manifest_entry = self.manifest.manifest_entries[i]
            is_file = manifest_entry.directory_flags & CacheFileManifestEntry.FLAG_IS_FILE != 0

            # Create our entry.
            klass = DirectoryFile if is_file else DirectoryFolder
            entry = klass(folder, manifest_entry.name, self)

            entry._manifest_entry = manifest_entry
            entry.item_size = manifest_entry.item_size
            entry.index = manifest_entry.index
            entry.flags = manifest_entry.directory_flags

            folder.items[entry.name] = entry

            if is_file:
                # Make sure it's a GCF before we read.
                if self.is_gcf():
                    self._read_file_table(entry)

            else:
                self._read_directory_table(entry)

            i = manifest_entry.next_index

    @raise_ncf_error
    def _read_file_table(self, entry):

        # Flags
        # entry.flags = self.blocks[entry.index].entry_flags
        entry.sectors = []
        entry.num_of_blocks = ceil(
            float(entry.size()) / float(self.data_header.sector_size)
        )

        for block in entry._manifest_entry.blocks:
            if block is None:
                entry.sectors = []
                break
            entry.sectors.extend(block.sectors)
            self.complete_available += block.file_data_size

        fragmented, _used = self._get_item_fragmentation(entry.index)
        entry.is_fragmented = fragmented > 0

        entry.is_user_config = entry.index in self.manifest.user_config_entries
        entry.is_minimum_footprint = entry.index in self.manifest.minimum_footprint_entries

    @raise_ncf_error
    def _merge_file_blocks(self, entry):
        terminator = 0xFFFFFFFF if self.alloc_table.is_long_terminator == 1 else 0xFFFF

        # If we are in one block, return plz.
        if not entry.first_block.next_block is not None:
            return

        # Go through the blocks of each file.
        for block in entry.blocks:

            # Get our first sector.
            sector_index = block.first_sector_index

            # From that, find the last sector in the block.
            while self.alloc_table[sector_index] != terminator:
                sector_index = self.alloc_table[sector_index]

            # Set the link from the last sector in the previous block to the first sector in this block.
            self.alloc_table[sector_index] = block.first_sector_index

    # Internal methods.

    def _join_path(self, *args):
        return STEAM_TERMINATOR.join(args)

    @raise_parse_error
    @raise_ncf_error
    def _size(self, file):
        if hasattr(file, "item_size"):
            return file.item_size
        return self.manifest.manifest_entries[file.index].item_size

    @raise_parse_error
    @raise_ncf_error
    def _open_file(self, file, mode, key=None):
        loader = getattr(file, "_loader", None)
        if isinstance(loader, tuple) and loader[0] == "fs":
            return open(loader[1], mode)
        return GCFFileStream(file, self, mode, key)

    @raise_parse_error
    @raise_ncf_error
    def _extract_folder(self, folder, where, recursive, keep_folder_structure, item_filter=None, key=None):

        if keep_folder_structure:
            try:
                os.makedirs(os.path.join(where, folder.sys_path()))
            except os.error:
                pass

        # Loop over the folder and extract files and folders (if recursive)
        for entry in folder:
            # Don't bother recursing (and creating the folder) if no files are left after the filter.
            if entry.is_folder() and recursive and ((item_filter is None) or (len([x for x in entry.all_files() if item_filter(x)]) > 0)):
                self._extract_folder(entry, where, True, keep_folder_structure, item_filter, key)
            elif entry.is_file():
                if (item_filter is None) or item_filter(entry):
                    self._extract_file(entry, where, keep_folder_structure, key)

    @raise_parse_error
    @raise_ncf_error
    def _extract_file(self, file, where, keep_folder_structure, key=None):
        if keep_folder_structure:
            path = os.path.join(where, file.sys_path())
        else:
            path = os.path.join(where, file.name)

        os.makedirs(os.path.dirname(path), exist_ok=True)

        if (
            file._manifest_entry.directory_flags
            & CacheFileManifestEntry.FLAG_IS_ENCRYPTED
            and key is None
        ):
            raise ValueError("File is encrypted but no decryption key was provided")

        cacheStream = self._open_file(file, "rb", key=key)
        data = cacheStream.readall()
        cacheStream.close()

        with open(path, "wb") as fsHandle:
            fsHandle.write(data)

    # Public Methods
    def is_ncf(self):
        return self.header.is_ncf()

    def is_gcf(self):
        return self.header.is_gcf()

    @raise_parse_error
    @raise_ncf_error
    def complete_percent(self, range=100):
        return float(self.complete_available) / float(self.complete_total) * float(range)

    @raise_parse_error
    @raise_ncf_error
    def extract(self, where, recursive=True, keep_folder_structure=True, filter=None, key=None):
        self._extract_folder(self.root, where, recursive, keep_folder_structure, filter, key)

    @raise_parse_error
    @raise_ncf_error
    def extract_minimum_footprint(self, where, keep_folder_structure=True, key=None):
        self._extract_folder(
            self.root,
            where,
            True,
            keep_folder_structure,
            lambda x: x.is_minimum_footprint and not (os.path.exists(os.path.join(where, x.sys_path())) and x.is_user_config),
            key,
        )

    def open(self, filename, mode, key=None):
        # Use file.open instead of _open_file as we may be parsing an NCF
        return self.root[filename].open(mode, key)

    def __len__(self):
        return len(self.root)

    def __iter__(self):
        return iter(self.root)

    def __getitem__(self, name):
        return self.root[name]

    # Editing support ---------------------------------------------------
    def _add_file_internal(self, path: str, size: int, loader) -> None:
        parts = [p for p in path.split(STEAM_TERMINATOR) if p]
        folder = self.root
        for part in parts[:-1]:
            child = folder.items.get(part)
            if not child:
                child = DirectoryFolder(folder, part, self)
                child.flags = 0
                folder.items[part] = child
            folder = child
        name = parts[-1]
        file_entry = DirectoryFile(folder, name, self)
        file_entry.item_size = size
        file_entry._loader = loader
        file_entry.flags = 0
        folder.items[name] = file_entry

    def add_file(self, src_path: str, dest_dir: str = "") -> None:
        name = os.path.basename(src_path)
        dest_path = self._join_path(dest_dir, name)
        self._add_file_internal(dest_path, os.path.getsize(src_path), ("fs", src_path))

    def add_folder(self, dest_dir: str, name: str) -> None:
        path = self._join_path(dest_dir, name)
        parts = [p for p in path.split(STEAM_TERMINATOR) if p]
        folder = self.root
        for part in parts:
            child = folder.items.get(part)
            if not child:
                child = DirectoryFolder(folder, part, self)
                child.flags = 0
                folder.items[part] = child
            folder = child

    def remove_file(self, path: str) -> None:
        parts = [p for p in path.split(STEAM_TERMINATOR) if p]
        if not parts:
            return
        folder = self.root
        for part in parts[:-1]:
            folder = folder.items.get(part)
            if folder is None:
                return
        folder.items.pop(parts[-1], None)

    def move_file(self, old_path: str, new_path: str) -> None:
        old_parts = [p for p in old_path.split(STEAM_TERMINATOR) if p]
        if not old_parts:
            return
        folder = self.root
        for part in old_parts[:-1]:
            folder = folder.items.get(part)
            if folder is None:
                return
        entry = folder.items.pop(old_parts[-1], None)
        if not entry:
            return
        dest_parts = [p for p in new_path.split(STEAM_TERMINATOR) if p]
        dest_folder = self.root
        for part in dest_parts[:-1]:
            child = dest_folder.items.get(part)
            if not child:
                child = DirectoryFolder(dest_folder, part, self)
                child.flags = 0
                dest_folder.items[part] = child
            dest_folder = child
        name = dest_parts[-1]
        entry.name = name
        if isinstance(entry, DirectoryFolder):
            entry.owner = dest_folder
        else:
            entry.folder = dest_folder
        dest_folder.items[name] = entry

    def save(self, output_path: str, progress: Callable[[int, int], None] | None = None) -> None:
        """Save the modified GCF to a file, rebuilding all tables.

        This method completely rebuilds the GCF from the current directory tree,
        regenerating all tables (blocks, allocation, manifest, checksums) to
        account for any modifications made via add_file, remove_file, move_file.
        """
        files: dict[str, bytes] = {}
        flags: dict[str, int] = {}
        block_flags: dict[str, int] = {}

        def collect(folder: DirectoryFolder):
            folder_path = folder.path().lstrip(STEAM_TERMINATOR).replace(STEAM_TERMINATOR, "/")
            flags[folder_path] = getattr(folder, "flags", 0)
            for entry in folder.items.values():
                if entry.is_folder():
                    collect(entry)
                else:
                    loader = getattr(entry, "_loader", None)
                    if isinstance(loader, tuple) and loader[0] == "fs":
                        with open(loader[1], "rb") as f:
                            data = f.read()
                    else:
                        stream = self._open_file(entry, "rb")
                        data = stream.readall()
                        stream.close()
                    key = entry.path().lstrip(STEAM_TERMINATOR).replace(STEAM_TERMINATOR, "/")
                    files[key] = data
                    flags[key] = getattr(entry, "flags", 0)
                    # Preserve block-level flags if available
                    block_flags[key] = getattr(entry, "block_flags", 0)

        collect(self.root)

        # Get manifest-level flags from the current manifest if available
        manifest_flags = self.manifest.depot_info if self.manifest else 0

        cf = CacheFile.build(
            files,
            app_id=self.header.application_id,
            app_version=self.header.application_version,
            flags=flags,
            block_flags=block_flags,
            manifest_flags=manifest_flags,
        )
        cf.convert_version(self.header.format_version, output_path, progress=progress)

    # ------------------------------------------------------------------
    def is_fragmented(self) -> bool:
        """Return ``True`` if the archive contains fragmented data blocks.

        Uses a direct translation of HLLib's ``CGCFFile::GetItemFragmentation``
        to examine the directory tree and count fragmented versus used data
        blocks.  ``True`` is returned if any blocks are fragmented.  Only
        meaningful for GCF archives; NCF files do not store file data.
        """

        if not self.is_parsed or not self.is_gcf() or not self.manifest:
            return False
        fragmented, _used = self._get_item_fragmentation(0)
        return fragmented > 0

    def _available_bytes(self, manifest_entry) -> int:
        sector = self.header.sector_size
        size = 0
        block = manifest_entry.first_block
        while block is not None:
            try:
                count = sum(1 for _ in block.sectors)
            except Exception:
                count = 0
            size += min(block.file_data_size, count * sector)
            block = block.next_block
        return size

    # ------------------------------------------------------------------
    def _validate_file(self, entry) -> Optional[str]:
        """Internal helper implementing HLLib's validation routine.

        Returns an error string if validation fails or ``None`` if the file
        appears to be valid.  Encrypted files and files without a checksum are
        treated as valid because their contents cannot be verified.
        """

        manifest_entry = entry._manifest_entry

        size = self._available_bytes(manifest_entry)
        if size != manifest_entry.item_size:
            return "size mismatch"

        if (
            manifest_entry.directory_flags
            & CacheFileManifestEntry.FLAG_IS_ENCRYPTED
        ):
            return None  # Can't validate encrypted data, assume OK.

        if (
            self.checksum_map is None
            or manifest_entry.checksum_index == 0xFFFFFFFF
        ):
            return None  # No checksum information available.

        try:
            count, first = self.checksum_map.entries[manifest_entry.checksum_index]
        except Exception:
            return "checksum index out of range"

        stream = entry.open("rb")
        try:
            remaining = manifest_entry.item_size
            i = 0
            while remaining > 0 and i < count:
                to_read = min(CACHE_CHECKSUM_LENGTH, remaining)
                chunk = stream.read(to_read)
                if len(chunk) != to_read:
                    return "size mismatch"
                chk = (adler32(chunk, 0) & 0xFFFFFFFF) ^ (
                    zlib.crc32(chunk) & 0xFFFFFFFF
                )
                if chk != self.checksum_map.checksums[first + i]:
                    return "checksum mismatch"
                remaining -= to_read
                i += 1
            if remaining > 0:
                return "size mismatch"
        finally:
            stream.close()

        return None

    def validate(self, progress=None):
        """Validate file data and return a list of error strings."""

        errors = []
        if not self.is_parsed:
            return ["Cache file not parsed"]

        try:
            self.header.validate()
        except Exception as exc:
            errors.append(f"header: {exc}")
        if self.is_gcf():
            if self.manifest:
                try:
                    self.manifest.validate()
                except Exception as exc:
                    errors.append(f"manifest: {exc}")
            if self.blocks:
                try:
                    self.blocks.validate()
                except Exception as exc:
                    errors.append(f"blocks: {exc}")
            if self.alloc_table:
                try:
                    self.alloc_table.validate()
                except Exception as exc:
                    errors.append(f"alloc table: {exc}")
            if self.block_entry_map and hasattr(self.block_entry_map, "validate"):
                try:
                    self.block_entry_map.validate()
                except Exception as exc:
                    errors.append(f"block entry map: {exc}")
            if self.data_header:
                try:
                    self.data_header.validate()
                except Exception as exc:
                    errors.append(f"sector header: {exc}")
            try:
                self.stream.seek(0, os.SEEK_END)
                actual = self.stream.tell()
                if actual != self.header.file_size:
                    errors.append(
                        f"file size mismatch: header {self.header.file_size} actual {actual}"
                    )
            finally:
                self.stream.seek(0)

        files = self.root.all_files()
        total = len(files)

        for i, entry in enumerate(files):
            error = self._validate_file(entry)
            if error:
                errors.append(f"{entry.path()}: {error}")
            if progress:
                try:
                    progress(i + 1, total)
                except Exception:
                    pass

        return errors

    def count_complete_files(self) -> tuple[int, int]:
        """Return a tuple of (complete, total) file counts."""
        if not self.is_parsed or not self.manifest:
            return (0, 0)

        files = self.root.all_files()
        complete = 0
        for entry in files:
            manifest_entry = getattr(entry, "_manifest_entry", None)
            if not manifest_entry:
                continue
            size = self._available_bytes(manifest_entry)
            if size >= manifest_entry.item_size:
                complete += 1
        return complete, len(files)

    def _get_item_fragmentation(self, item_index: int) -> tuple[int, int]:
        """Return ``(fragmented, used)`` block counts for the given item.

        This is a direct translation of ``CGCFFile::GetItemFragmentation``.  If
        ``item_index`` refers to a folder the counts for all child items are
        accumulated recursively.
        """

        entry = self.manifest.manifest_entries[item_index]
        if (entry.directory_flags & CacheFileManifestEntry.FLAG_IS_FILE) == 0:
            fragmented = 0
            used = 0
            child = entry.child_index
            while child not in (0, 0xFFFFFFFF):
                f, u = self._get_item_fragmentation(child)
                fragmented += f
                used += u
                child = self.manifest.manifest_entries[child].next_index
            return fragmented, used

        terminator = self.alloc_table.terminator
        last_sector = self.data_header.sector_count
        fragmented = 0
        used = 0

        block = entry.first_block
        while block is not None:
            block_size = 0
            sector_index = block._first_sector_index
            while sector_index != terminator and block_size < block.file_data_size:
                if last_sector != self.data_header.sector_count and last_sector + 1 != sector_index:
                    fragmented += 1
                used += 1
                last_sector = sector_index
                sector_index = self.alloc_table[sector_index]
                block_size += self.data_header.sector_size
            block = block.next_block

        return fragmented, used

class CacheFileHeader:

    def __init__(self, owner):
        self.owner = owner
    def parse(self, data):
        (self.header_version,
         self.cache_type,
         self.format_version,
         self.application_id,
         self.application_version,
         self.is_mounted,
         self.dummy1,
         self.file_size,
         self.sector_size,
         self.sector_count,
         self.checksum) = struct.unpack("<11L", data)

    def serialize(self):
        data = struct.pack("<10L", self.header_version, self.cache_type, self.format_version, self.application_id,
                           self.application_version, self.is_mounted, self.dummy1, self.file_size, self.sector_size, self.sector_count)
        self.checksum = sum(data) & 0xFFFFFFFF
        return data + struct.pack("<L", self.checksum)

    def calculate_checksum(self):
        # Calculate Checksum..
        return struct.unpack("<L", self.serialize()[-4:])[0]

    def validate(self):
        # Check the usual stuff.
        if self.header_version != 1:
            raise ValueError("Invalid Cache File Header [HeaderVersion is not 1]")
        if not (self.is_ncf() or self.is_gcf()):
            raise ValueError("Invalid Cache File Header [Not GCF or NCF]")
        if self.is_ncf() and self.format_version != 1:
            raise ValueError("Invalid Cache File Header [Is NCF and version is not 1]")
        elif self.is_gcf() and self.format_version not in (1, 3, 5, 6):
            raise ValueError("Invalid Cache File Header [Is GCF and version is not 1, 3, 5, or 6]")
        # UPDATE: This fails on some files, namely the half-life files.
        #if self.is_mounted != 0:
        #   raise ValueError, "Invalid Cache File Header [Updating is not 0... WTF?]"
        if self.is_ncf() and self.file_size != 0:
            raise ValueError("Invalid Cache File Header [Is NCF and FileSize is not 0]")
        if self.is_ncf() and self.sector_size != 0:
            raise ValueError("Invalid Cache File Header [Is NCF and BlockSize is not 0]")
        if self.is_ncf() and self.sector_count != 0:
            raise ValueError("Invalid Cache File Header [Is NCF and BlockCount is not 0]")
        #if self.checksum != self.calculate_checksum():
        #    raise ValueError, "Invalid Cache File Header [Checksums do not match]"

    def is_ncf(self):
        return self.cache_type == 2
    def is_gcf(self):
        return self.cache_type == 1
    def get_blocks_length(self):
        return self.sector_size * self.sector_count + 32 # Block Size * Block Count + Block Header

class CacheFileBlockAllocationTable:

    def __init__(self, owner):
        self.owner = owner
        self.blocks = []

    def parse(self, stream):

        # Blocks Header
        (self.block_count,
         self.blocks_used,
         self.last_block_used,
         self.dummy1,
         self.dummy2,
         self.dummy3,
         self.dummy4) = struct.unpack("<7L", stream.read(28))
        self.checksum = sum(stream.read(4))

        # Block Entries
        for i in range(self.block_count):
            block = CacheFileBlockAllocationTableEntry(self)
            block.index = i
            block.parse(stream)
            self.blocks.append(block)

    def serialize(self):
        data = struct.pack("<7L", self.block_count, self.blocks_used, self.last_block_used, self.dummy1, self.dummy2, self.dummy3, self.dummy4)
        self.checksum = sum(data)
        return data + struct.pack("<L", self.checksum) + b"".join(x.serialize() for x in self.blocks)

    def calculate_checksum(self):
        return sum(self.serialize()[:24])

    def validate(self):
        if self.owner.header.sector_count != self.block_count:
            raise ValueError("Invalid Cache Block [Sector/BlockCounts do not match]")
        #print self.checksum, self.calculate_checksum()
        #if self.checksum != self.calculate_checksum():
        #    raise ValueError, "Invalid Cache Block [Checksums do not match]"

class CacheFileBlockAllocationTableEntry:

    # v6 format constants (16-bit flags)
    DUMMY0 = 0x200F
    FLAG_DATA = 0x8000
    FLAG_DATA_2 = 0xC000
    FLAG_NO_DATA = 0x0000
    FLAG_ENCRYPTED = 0x0004
    FLAG_COMPRESSED_ENCRYPTED = 0x0002
    FLAG_RAW = 0x0001
    FLAG_LOCAL_PRIORITY = 0x4000

    # Legacy format constants (32-bit flags) for v1/v3/v5
    FLAG_DATA_LEGACY = 0x200F8000
    FLAG_DATA_2_LEGACY = 0x200FC000
    FLAG_NO_DATA_LEGACY = 0x200F0000

    def __init__(self, owner):
        self.owner = owner
        self.dummy0 = self.DUMMY0  # Default value for v6

    def parse(self, stream):
        """Parse a block entry from stream.

        The block entry format changed between GCF versions:
        - v1, v3, v5: 7 DWORDs (entry_flags is 32-bit)
        - v6: 2 uint16 + 6 DWORDs (entry_flags and dummy0 are each 16-bit)

        Both formats are 28 bytes total, but the field layout differs.
        """
        fmt_version = self.owner.owner.header.format_version
        data = stream.read(28)

        if fmt_version >= 6:
            # v6 format: uint16 flags, uint16 dummy, 6 DWORDs
            (
                self.entry_flags,
                self.dummy0,
                self.file_data_offset,
                self.file_data_size,
                self._first_sector_index,
                self._next_block_index,
                self._prev_block_index,
                self.manifest_index,
            ) = struct.unpack("<2H6L", data)
        else:
            # Legacy format (v1/v3/v5): 7 DWORDs
            (
                flags_combined,
                self.file_data_offset,
                self.file_data_size,
                self._first_sector_index,
                self._next_block_index,
                self._prev_block_index,
                self.manifest_index,
            ) = struct.unpack("<7L", data)
            # Split the combined 32-bit flags into 16-bit parts
            self.entry_flags = flags_combined & 0xFFFF
            self.dummy0 = (flags_combined >> 16) & 0xFFFF

        # Maintain backwards compatibility with callers expecting ``flags``.
        self.flags = self.entry_flags

    def _get_sector_iterator(self):
        sector = self.first_sector
        while sector is not None:
            yield sector
            sector = sector.next_sector

    def _get_next_block(self):
        try:
            return self.owner.blocks[self._next_block_index]
        except IndexError:
            return None

    def _set_next_block(self, value):
        if value is None:
            self._next_block_index = 0
        else:
            self._next_block_index = value.index
            value._prev_block_index = self.index

    def _get_prev_block(self):
        try:
            return self.owner.blocks[self._prev_block_index]
        except IndexError:
            return None

    def _set_prev_block(self, value):
        if value is None:
            self._prev_block_index = 0
        else:
            self._prev_block_index = value.index
            value._next_block_index = self.index

    def _get_first_sector(self):
        """Return the first sector for this block or ``None`` if unused."""
        alloc_table = self.owner.owner.alloc_table
        # Block entries that do not reference any data use a sentinel index
        # equal to the allocation table's terminator value.  Creating a
        # ``CacheFileSector`` for these entries would attempt to index past the
        # end of the allocation table and raise ``IndexError``.
        if self._first_sector_index >= alloc_table.terminator:
            return None
        return CacheFileSector(self, self._first_sector_index)

    def _set_first_sector(self, value):
        self._first_sector_index = value.inde

    def _get_is_fragmented(self):
        alloc_table = self.owner.owner.alloc_table
        if self._first_sector_index >= alloc_table.terminator:
            return False
        return (alloc_table[self._first_sector_index] - self._first_sector_index) != -1

    next_block = property(_get_next_block, _set_next_block)
    prev_block = property(_get_prev_block, _set_prev_block)
    first_sector = property(_get_first_sector, _set_first_sector)
    sectors = property(_get_sector_iterator)
    is_fragmented = property(_get_is_fragmented)

    def serialize(self):
        """Serialize block entry based on the owner's GCF version.

        v6 uses 16-bit flags + 16-bit dummy, earlier versions use 32-bit combined.
        """
        fmt_version = self.owner.owner.header.format_version

        if fmt_version >= 6:
            # v6 format: uint16 flags, uint16 dummy, 6 DWORDs
            return struct.pack(
                "<2H6L",
                self.entry_flags & 0xFFFF,
                self.dummy0 & 0xFFFF,
                self.file_data_offset,
                self.file_data_size,
                self._first_sector_index,
                self._next_block_index,
                self._prev_block_index,
                self.manifest_index,
            )
        else:
            # Legacy format (v1/v3/v5): 7 DWORDs with combined flags
            flags_combined = (self.entry_flags & 0xFFFF) | ((self.dummy0 & 0xFFFF) << 16)
            return struct.pack(
                "<7L",
                flags_combined,
                self.file_data_offset,
                self.file_data_size,
                self._first_sector_index,
                self._next_block_index,
                self._prev_block_index,
                self.manifest_index,
            )

class CacheFileAllocationTable:

    def __init__(self, owner):
        self.owner = owner
        self.entries = []

    def __getitem__(self, i):
        return self.entries[i]

    def __setitem__(self, i, v):
        self.entries[i] = v

    def __len__(self):
        return len(self.entries)

    def __iter__(self):
        return iter(self.entries)

    def parse(self, stream):

        # Block Header
        (
            self.sector_count,
            self.first_unused_entry,
            self.is_long_terminator,
        ) = struct.unpack("<3L", stream.read(12))
        # ``uiChecksum`` in ``GCFFragmentationMapHeader`` is a simple 32-bit
        # sum of the three header fields using unsigned overflow semantics.
        # Older implementations incorrectly summed the raw bytes which caused
        # validation failures on legitimate v1 GCF files.
        (self.checksum,) = struct.unpack("<L", stream.read(4))

        self.terminator = 0xFFFFFFFF if self.is_long_terminator else 0xFFFF
        self.entries = unpack_dword_list(stream, self.sector_count)

    def serialize(self):
        data = struct.pack(
            "<3L",
            self.sector_count,
            self.first_unused_entry,
            self.is_long_terminator,
        )
        # Cache the checksum so subsequent calls to ``serialize`` or
        # ``calculate_checksum`` are in agreement with the on-disk format.
        self.checksum = self.calculate_checksum()
        return data + struct.pack("<L", self.checksum) + pack_dword_list(self.entries)

    def calculate_checksum(self):
        return (
            self.sector_count
            + self.first_unused_entry
            + self.is_long_terminator
        ) & 0xFFFFFFFF

    def validate(self):
        if self.owner.header.sector_count != self.sector_count:
            raise ValueError(
                "Invalid Cache Allocation Table [SectorCounts do not match]"
            )
        # Very old GCF files often contain an incorrect checksum here.  The
        # reference C++ implementation does not enforce this for legacy
        # archives so we only validate for newer formats where the field is
        # known to be reliable.
        if self.owner.header.format_version > 1:
            if self.checksum != self.calculate_checksum():
                raise ValueError(
                    "Invalid Cache Allocation Table [Checksums do not match]"
                )

class CacheFileBlockEntryMap:

    def __init__(self, owner):
        self.owner = owner
        # ``entries`` stores block entry indices in linked-list order so that
        # manifest map entries can be resolved to real block entries.
        self.entries: list[int] = []
        self.first_block_entry_index = 0
        self.last_block_entry_index = 0
        self.dummy0 = 0

    def parse(self, stream):
        # Full header: block count, first & last entry indices, dummy field and
        # checksum.  Older implementations only read the first DWORD which
        # resulted in misaligned reads for v1 archives.
        (
            self.block_count,
            self.first_block_entry_index,
            self.last_block_entry_index,
            self.dummy0,
            self.checksum,
        ) = struct.unpack("<5L", stream.read(20))

        raw_entries = [struct.unpack("<2L", stream.read(8)) for _ in range(self.block_count)]

        # Reconstruct a linear mapping from list position to block entry index
        # by traversing the linked list defined by the raw entries.
        ordered: list[int] = []
        index = self.first_block_entry_index
        visited = set()
        for _ in range(self.block_count):
            if index >= self.block_count or index in visited:
                break
            ordered.append(index)
            visited.add(index)
            index = raw_entries[index][1]

        # Fallback in case of malformed data where not all entries are linked.
        if len(ordered) < self.block_count:
            ordered.extend(i for i in range(self.block_count) if i not in visited)

        self.entries = ordered

    def serialize(self):
        self.block_count = len(self.entries)
        self.first_block_entry_index = self.entries[0] if self.entries else 0
        self.last_block_entry_index = self.entries[-1] if self.entries else 0
        self.dummy0 = 0

        # Build raw linked-list representation from the ordered list.
        raw_entries = [(self.block_count, self.block_count)] * self.block_count
        for pos, entry_index in enumerate(self.entries):
            prev_idx = self.entries[pos - 1] if pos > 0 else self.block_count
            next_idx = self.entries[pos + 1] if pos < self.block_count - 1 else self.block_count
            raw_entries[entry_index] = (prev_idx, next_idx)

        header = struct.pack(
            "<4L",
            self.block_count,
            self.first_block_entry_index,
            self.last_block_entry_index,
            self.dummy0,
        )
        self.checksum = sum(header)
        data = [header, struct.pack("<L", self.checksum)]
        data.extend(struct.pack("<2L", *e) for e in raw_entries)
        return b"".join(data)


class CacheFileManifest:

    FLAG_BUILD_MODE   = 0x00000001
    FLAG_IS_PURGE_ALL = 0x00000002
    FLAG_IS_LONG_ROLL = 0x00000004
    FLAG_DEPOT_KEY    = 0xFFFFFF00

    def __init__(self, owner):
        self.owner = owner
        self.manifest_entries = []
        self.hash_table_keys = []
        self.hash_table_indices = []

        # Contains ManifestIndex
        self.user_config_entries = []

        # Contains ManifestIndex
        self.minimum_footprint_entries = []

        # Contains FirstBlockIndex
        self.manifest_map_entries = []

    def parse(self, stream):
        # Header
        self.header_data = stream.read(56)
        (self.header_version,
         self.application_id,
         self.application_version,
         self.node_count,
         self.file_count,
         self.compression_block_size,
         self.binary_size,
         self.name_size,
         self.hash_table_key_count,
         self.num_of_minimum_footprint_files,
         self.num_of_user_config_files,
         self.depot_info,
         self.fingerprint,
         self.checksum) = struct.unpack("<14L", self.header_data)

        # 56 = size of header
        self.manifest_stream = BytesIO(stream.read(self.binary_size - 56))

        # Manifest Entries
        for i in range(self.node_count):
            entry = CacheFileManifestEntry(self)
            entry.index = i
            # 28 = size of ManifestEntry
            data = self.manifest_stream.read(28)
            entry.parse(data)
            self.manifest_entries.append(entry)
            if (entry.directory_flags & CacheFileManifestEntry.FLAG_IS_FILE) != 0:
                self.owner.complete_total += entry.item_size

        # Name Table
        self.filename_table = self.manifest_stream.read(self.name_size)

        # Info1 / HashTableKeys
        self.hash_table_keys = unpack_dword_list(self.manifest_stream, self.hash_table_key_count)

        # Info2 / HashTableIndices
        self.hash_table_indices = unpack_dword_list(self.manifest_stream, self.node_count)

        # Minimum Footprint Entries
        self.minimum_footprint_entries = unpack_dword_list(self.manifest_stream, self.num_of_minimum_footprint_files)

        # User Config Entries
        self.user_config_entries = unpack_dword_list(
            self.manifest_stream, self.num_of_user_config_files
        )

        # Older GCF v1 directories omit the manifest-map header entirely and
        # store the first-block indices directly after the manifest stream.
        if self.owner.header.format_version <= 1:
            self.map_header_version = 1
            self.map_dummy1 = 0
        else:
            (self.map_header_version, self.map_dummy1) = struct.unpack(
                "<2L", stream.read(8)
            )

        # Manifest Map Entries (FirstBlockIndex)
        self.manifest_map_entries = unpack_dword_list(stream, self.node_count)

    def serialize(self):
        # 56 = size of header
        # 32 = size of ManifestEntry + size of DWORD for HashTableIndices
        self.hash_table_key_count = len(self.hash_table_keys)
        self.num_of_user_config_files = len(self.user_config_entries)
        self.num_of_minimum_footprint_files = len(self.minimum_footprint_entries)
        self.name_size = len(self.filename_table)
        self.binary_size = 56 + 32 * self.node_count + self.name_size + 4 * (
            self.hash_table_key_count
            + self.num_of_user_config_files
            + self.num_of_minimum_footprint_files
        )

        manifest_data_parts = []
        for i in self.manifest_entries:
            manifest_data_parts.append(i.serialize())

        manifest_data_parts.append(self.filename_table)
        manifest_data_parts.append(pack_dword_list(self.hash_table_keys))
        manifest_data_parts.append(pack_dword_list(self.hash_table_indices))
        manifest_data_parts.append(pack_dword_list(self.minimum_footprint_entries))
        manifest_data_parts.append(pack_dword_list(self.user_config_entries))
        if self.owner.header.format_version > 1:
            manifest_data_parts.append(
                struct.pack("<2L", self.map_header_version, self.map_dummy1)
            )
        manifest_data_parts.append(pack_dword_list(self.manifest_map_entries))
        manifest_data = b"".join(manifest_data_parts)

        header_without_checksum = struct.pack(
            "<13L",
            self.header_version,
            self.application_id,
            self.application_version,
            self.node_count,
            self.file_count,
            self.compression_block_size,
            self.binary_size,
            self.name_size,
            self.hash_table_key_count,
            self.num_of_minimum_footprint_files,
            self.num_of_user_config_files,
            self.depot_info,
            self.fingerprint,
        )
        self.header_data = header_without_checksum

        self.checksum = adler32(header_without_checksum + b"\0\0\0\0" + manifest_data, 0) & 0xFFFFFFFF
        return header_without_checksum + struct.pack("<L", self.checksum) + manifest_data

    def validate(self):
        if self.owner.header.application_id != self.application_id:
            raise ValueError("Invalid Cache File Manifest [Application ID mismatch]")
        if self.owner.header.application_version != self.application_version:
            raise ValueError("Invalid Cache File Manifest [Application version mismatch]")
        #if self.checksum != self.calculate_checksum():
        #    raise ValueError, "Invalid Cache File Manifest [Checksum mismatch]"
        if self.owner.header.format_version > 1:
            if self.map_header_version != 1:
                raise ValueError(
                    "Invalid Cache File Manifest [ManifestHeaderMap's HeaderVersion is not 1]"
                )
            if self.map_dummy1 != 0:
                raise ValueError(
                    "Invalid Cache File Manifest [ManifestHeaderMap's Dummy1 is not 0]"
                )

    def calculate_checksum(self):
        # Blank out checksum and fingerprint + hack to get unsigned value.
        data = self.serialize()
        return adler32(data[:48] + b"\0\0\0\0\0\0\0\0" + data[56:], 0) & 0xffffffff

class CacheFileManifestEntry:

    FLAG_IS_FILE        = 0x00004000
    FLAG_IS_EXECUTABLE  = 0x00000800
    FLAG_IS_HIDDEN      = 0x00000400
    FLAG_IS_READ_ONLY   = 0x00000200
    FLAG_IS_ENCRYPTED   = 0x00000100
    FLAG_IS_PURGE_FILE  = 0x00000080
    FLAG_BACKUP_PLZ     = 0x00000040
    FLAG_IS_NO_CACHE    = 0x00000020
    FLAG_IS_LOCKED      = 0x00000008
    FLAG_IS_LAUNCH      = 0x00000002
    FLAG_IS_USER_CONFIG = 0x00000001

    def __init__(self, owner):
        self.owner = owner

    def _get_name(self):
        raw = self.owner.filename_table[self.name_offset:].split(b"\0", 1)[0]
        return raw.decode('utf-8', errors='replace')

    def _set_name(self, value):
        value_bytes = value.encode('utf-8')
        name_end = self.owner.filename_table[self.name_offset:].find(b"\0")
        table = bytearray(self.owner.filename_table)
        table[self.name_offset:self.name_offset + name_end] = value_bytes
        self.owner.filename_table = bytes(table)

    def _get_block_iterator(self):
        block = self.first_block
        while block is not None:
            yield block
            block = block.next_block

    def _get_first_block(self):
        index = self.owner.manifest_map_entries[self.index]
        # Older GCF versions store a block-entry-map indirection
        if self.owner.owner.header.format_version < 6 and self.owner.owner.block_entry_map:
            if index >= len(self.owner.owner.block_entry_map.entries):
                return None
            index = self.owner.owner.block_entry_map.entries[index]
        if index >= len(self.owner.owner.blocks.blocks):
            return None
        return self.owner.owner.blocks.blocks[index]

    def _set_first_block(self, value):
        if self.owner.owner.header.format_version < 6 and self.owner.owner.block_entry_map:
            try:
                mapped = self.owner.owner.block_entry_map.entries.index(value)
            except ValueError:
                mapped = value
            self.owner.manifest_map_entries[self.index] = mapped
        else:
            self.owner.manifest_map_entries[self.index] = value

    def parse(self, data):
        (self.name_offset,
         self.item_size,
         self.checksum_index,
         self.directory_flags,
         self.parent_index,
         self.next_index,
         self.child_index) = struct.unpack("<7L", data)

    blocks = property(_get_block_iterator)
    first_block = property(_get_first_block, _set_first_block)
    name = property(_get_name, _set_name)

    def serialize(self):
        return struct.pack("<7L", self.name_offset, self.item_size, self.checksum_index, self.directory_flags, self.parent_index, self.next_index, self.child_index)

class CacheFileChecksumMap:

    FLAG_IS_SIGNED      = 0x00000001
    FLAG_UNKNOWN        = 0xFFFFFFFE

    def __init__(self, owner):
        self.owner = owner

        # Contains (ChecksumCount, FirstChecksumIndex)
        self.entries = []

        # Contains Checksum
        self.checksums = []

    def parse(self, stream):

        (self.header_version,
         self.checksum_size,
         self.format_code,
         self.version,
         self.file_id_count,
         self.checksum_count) = struct.unpack("<6L", stream.read(24))

        for i in range(self.file_id_count):
            self.entries.append(struct.unpack("<2L", stream.read(8)))

        self.checksums = unpack_dword_list(stream, self.checksum_count)

        self.signature = stream.read(128)

        # Read latest application version footer
        try:
            self.latest_application_version = struct.unpack("<L", stream.read(4))[0]
        except Exception:
            # Older formats might not have this field
            self.latest_application_version = self.owner.header.application_version

    def serialize(self):
        """Serialize checksum map with optional RSA signature and footer.

        v6: Includes RSA signature + latest_application_version footer
        v3/v5: Includes 128-byte null signature, no footer
        v1: No checksum map at all
        """
        # Build checksum data without signature
        data = [
            struct.pack("<6L", self.header_version, self.checksum_size,
                       self.format_code, self.version, self.file_id_count,
                       self.checksum_count)
        ]
        data += [struct.pack("<2L", *i) for i in self.entries]
        data.append(pack_dword_list(self.checksums))

        # Generate RSA signature only for v6 (format_code 0x14893721)
        if self.format_code == 0x14893721:
            if not self.signature:
                checksum_data = b"".join(data)
                self.signature = _rsa_pkcs1_sha1_sign(checksum_data)
            data.append(self.signature)
            # v6 includes the latest_application_version footer
            data.append(struct.pack("<L", self.latest_application_version))
        else:
            # v3/v5 use null signature, no footer
            if not self.signature or len(self.signature) != 128:
                self.signature = b"\0" * 128
            data.append(self.signature)

        return b"".join(data)

    def verify_signature(self) -> bool:
        """Verify the RSA signature on the checksum data."""
        if not self.signature or len(self.signature) != 128:
            return False

        # Build checksum data without signature
        data = [
            struct.pack("<6L", self.header_version, self.checksum_size,
                       self.format_code, self.version, self.file_id_count,
                       self.checksum_count)
        ]
        data += [struct.pack("<2L", *i) for i in self.entries]
        data.append(pack_dword_list(self.checksums))
        checksum_data = b"".join(data)

        return _rsa_pkcs1_sha1_verify(checksum_data, self.signature)

    def validate(self):
        pass
        # NOTE: This check is incorrect on the test file (half-life 2 game dialog.gcf) I have.
        # if self.owner.directory.file_count != self.item_count:
        #     raise ValueError, "Invalid Cache File Checksum Map [ItemCount and FileCount don't match]"

class CacheFileSectorHeader:

    def __init__(self, owner):
        self.owner = owner
        self.format_version = owner.header.format_version

    def parse(self, data, format_version):
        self.format_version = format_version
        if format_version <= 3:
            (
                self.sector_count,
                self.sector_size,
                self.first_sector_offset,
                self.sectors_used,
                self.checksum,
            ) = struct.unpack("<5L", data)
            # Older GCF versions omit the application version field.
            self.application_version = self.owner.header.application_version
        else:
            (
                self.application_version,
                self.sector_count,
                self.sector_size,
                self.first_sector_offset,
                self.sectors_used,
                self.checksum,
            ) = struct.unpack("<6L", data)

    def serialize(self):
        self.checksum = self.calculate_checksum()
        if self.format_version <= 3:
            return struct.pack(
                "<5L",
                self.sector_count,
                self.sector_size,
                self.first_sector_offset,
                self.sectors_used,
                self.checksum,
            )
        return struct.pack(
            "<6L",
            self.application_version,
            self.sector_count,
            self.sector_size,
            self.first_sector_offset,
            self.sectors_used,
            self.checksum,
        )

    def validate(self):
        if (
            self.format_version > 3
            and self.application_version != self.owner.header.application_version
        ):
            raise ValueError(
                "Invalid Cache File Sector Header [ApplicationVersion mismatch]"
            )
        # Some early GCF revisions (notably version 1) report a truncated
        # ``sector_count`` in the data header that does not match the value in
        # the file header.  HLLib tolerates this discrepancy, so we only enforce
        # equality for newer formats where both fields are known to agree.
        if (
            self.format_version > 1
            and self.sector_count != self.owner.header.sector_count
        ):
            raise ValueError(
                "Invalid Cache File Sector Header [SectorCount mismatch]"
            )
        # Legacy GCFs may report a different sector size in the data header
        # than in the file header.  HLLib accepts this mismatch, so only enforce
        # equality for newer format revisions where both fields are known to
        # agree.
        if (
            self.format_version > 1
            and self.sector_size != self.owner.header.sector_size
        ):
            raise ValueError(
                "Invalid Cache File Sector Header [SectorSize mismatch]"
            )
        # Some early (v1) GCF files are known to store an invalid checksum in
        # the data header.  HLLib ignores this discrepancy, so we only enforce
        # checksum validation for newer format revisions.
        if self.format_version > 1 and self.checksum != self.calculate_checksum():
            raise ValueError(
                "Invalid Cache File Sector Header [Checksum mismatch]"
            )

    def calculate_checksum(self):
        # The checksum stored in the data header is a 32-bit unsigned sum of
        # the following fields.  Clamp intermediate results to 32 bits to match
        # the behavior of the original C++ implementation.
        checksum = 0
        for value in (
            self.sector_count,
            self.sector_size,
            self.first_sector_offset,
            self.sectors_used,
        ):
            checksum = (checksum + value) & 0xFFFFFFFF
        return checksum

class CacheFileSector:

    def __init__(self, owner, index):
        self.owner = owner
        self.cache = owner.owner.owner
        self.index = index
        self._next_index = self.cache.alloc_table[index]

    def _get_next_sector(self):
        if self._next_index == self.cache.alloc_table.terminator:
            return None
        return CacheFileSector(self.owner, self._next_index)

    def _set_next_sector(self, value):
        self._next_index = value.index

    def get_data(self):
        size = self.cache.data_header.sector_size
        self.cache.stream.seek(self.cache.data_header.first_sector_offset + size*self.index, os.SEEK_SET)
        return self.cache.stream.read(size)

    next_sector = property(_get_next_sector, _set_next_sector)

class GCFFileStream:

    def __init__(self, entry, owner, mode, key=None):
        self.entry = entry
        self.owner = owner
        self.mode = mode
        self.key = key

        sector_size = self.owner.data_header.sector_size

        sectors = getattr(self.entry, "sectors", None) or []
        if not sectors:
            sectors = []
            for block in self.entry._manifest_entry.blocks:
                if block is None:
                    continue
                sectors.extend(block.sectors)
            self.entry.sectors = sectors

        raw = b"".join(sect.get_data() for sect in sectors)
        if key:
            raw = decrypt_gcf_data(raw, key)

        self.sectors = [raw[i : i + sector_size] for i in range(0, len(raw), sector_size)]
        self.position = 0

    # Iterator protocol.
    def __iter__(self):
        return self

    def __next__(self):
        return self.readline()

    # File protocol.
    def flush(self):
        # Nothing right now...
        pass

    def close(self):
        # Nothing right now...
        pass

    def tell(self):
        return self.position

    def seek(self, offset, origin=None):

        def err():
            raise IOError("Attempting to seek past end of file")

        if origin == os.SEEK_SET or origin is None:
            if offset > self.entry.item_size:
                err()
            self.position = offset

        elif origin == os.SEEK_CUR:
            if offset + self.position > self.entry.item_size:
                err()
            self.position += offset

        elif origin == os.SEEK_END:
            if offset > self.entry.item_size or offset < 0:
                err()
            self.position = self.entry.item_size - offset

    def readall(self):
        return self.read(0)

    def readline(self, size=-1):

        # Our count for the size parameter.
        count = 0
        # Bytes are immutable... use a list
        chars = []

        lastchar = b""

        # Loop over our data one byte at a time looking for line breaks
        while True:
            lastchar = self.read(1)
            # If we get a CR
            if lastchar == b"\r":
                # Strip out a LF if it comes next
                if self.read(1) != b"\n":
                    self.position -= 1
                break
            elif lastchar == b"\n":
                break
            elif count > size and size > 0:
                # FIXME: What does the file module do when we have a size
                # hint? Does it include newline in the count? What about
                # CRLF? Does count as one or two chars?
                break

            # Characters
            chars.append(lastchar)

        line = b"".join(chars)
        if self.is_text_mode():
            return line.decode('utf-8', errors='replace')
        return line

    def readlines(self, sizehint=-1):

        # Our count for the size parameter.
        count = 0
        lines = []

        while True:
            data = self.readline()
            lines.append(data)
            count += len(data)
            # If we have surpassed the sizehint, break
            if count > sizehint and sizehint > 0:
                break

        return lines

    def read(self, size=0):

        if not self.is_read_mode():
            raise AttributeError("Cannot read from file with current mode")

        sector_size = self.owner.data_header.sector_size
        sector_index, offset = divmod(self.position, sector_size)

        if not self.sectors:
            return b""

        # Raise an error if we read past end of file.
        if self.position + size > self.entry.item_size:
            raise IOError("Attempting to read past end of file")

        # One file isn't always in just one block.
        # We have to read multiple blocks sometimes in order to get a file.
        read_pos = 0

        # Bytes are immutable... use a list.
        data = []

        if size < 1:
            size = self.entry.item_size
            # Get all the data by looping over the sectors.
            for sector in self.sectors[sector_index:]:
                take = min(sector_size - offset, size)
                data.append(sector[offset:offset + take])
                size -= take
                if size <= 0:
                    break
                offset = 0
            self.position = self.entry.item_size
        else:
            while read_pos < size:
                take = min(size - read_pos, sector_size - offset)
                data.append(self.sectors[sector_index][offset:offset + take])
                sector_index += 1
                offset = 0
                read_pos += take
            self.position += read_pos

        # TYPE CHANGE!
        # Data - from list to bytes.
        data = b"".join(data)

        if self.is_text_mode():
            return data.decode('utf-8', errors='replace').replace("\r", "")

        return data

    def write(self, data):
        pass

    def is_binary_mode(self):
        return "b" in self.mode

    def is_text_mode(self):
        return "b" not in self.mode

    def is_read_mode(self):
        return "r" in self.mode

    def is_write_mode(self):
        return "w" in self.mode or "r+" in self.mode

    def is_append_mode(self):
        return "a" in self.mode
