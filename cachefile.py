from __future__ import annotations

import struct
import binascii
import zlib
from dataclasses import dataclass, field
from typing import BinaryIO, Optional, List

# ---------------------------------------------------------------------------
# Flag constants pulled directly from HLLib's GCFFile.cpp
# ---------------------------------------------------------------------------
HL_GCF_FLAG_FILE = 0x00004000
HL_GCF_FLAG_ENCRYPTED = 0x00000100
HL_GCF_FLAG_BACKUP_LOCAL = 0x00000040
HL_GCF_FLAG_COPY_LOCAL = 0x0000000A
HL_GCF_FLAG_COPY_LOCAL_NO_OVERWRITE = 0x00000001
HL_GCF_CHECKSUM_LENGTH = 0x00008000

# Package and item attribute names mirroring CGCFFile's static arrays.
PACKAGE_ATTRIBUTE_NAMES = [
    "Version",
    "Cache ID",
    "Allocated Blocks",
    "Used Blocks",
    "Block Length",
    "Last Version Played",
]

ITEM_ATTRIBUTE_NAMES = [
    "Encrypted",
    "Copy Locally",
    "Overwrite Local Copy",
    "Backup Local Copy",
    "Flags",
    "Fragmentation",
]

###############################################################################
# 1.  Structure definitions (direct C++ -> Python translation)
###############################################################################


@dataclass
class GCFHeader:
    dummy0: int
    major_version: int
    minor_version: int
    cache_id: int
    last_version_played: int
    dummy1: int
    dummy2: int
    file_size: int
    block_size: int
    block_count: int
    dummy3: int

    @classmethod
    def read(cls, stream: BinaryIO) -> "GCFHeader":
        data = stream.read(44)
        values = struct.unpack("<11I", data)
        return cls(*values)


@dataclass
class GCFBlockEntryHeader:
    block_count: int
    blocks_used: int
    dummy0: int
    dummy1: int
    dummy2: int
    dummy3: int
    dummy4: int
    checksum: int

    @classmethod
    def read(cls, stream: BinaryIO) -> "GCFBlockEntryHeader":
        data = stream.read(32)
        values = struct.unpack("<8I", data)
        return cls(*values)


@dataclass
class GCFBlockEntry:
    entry_flags: int
    file_data_offset: int
    file_data_size: int
    first_data_block_index: int
    next_block_entry_index: int
    previous_block_entry_index: int
    directory_index: int

    @classmethod
    def read(cls, stream: BinaryIO) -> "GCFBlockEntry":
        data = stream.read(28)
        values = struct.unpack("<7I", data)
        return cls(*values)


@dataclass
class GCFFragmentationMapHeader:
    block_count: int
    first_unused_entry: int
    terminator: int
    checksum: int

    @classmethod
    def read(cls, stream: BinaryIO) -> "GCFFragmentationMapHeader":
        data = stream.read(16)
        values = struct.unpack("<4I", data)
        return cls(*values)


@dataclass
class GCFFragmentationMap:
    next_data_block_index: int

    @classmethod
    def read(cls, stream: BinaryIO) -> "GCFFragmentationMap":
        data = stream.read(4)
        (next_index,) = struct.unpack("<I", data)
        return cls(next_index)


@dataclass
class GCFBlockEntryMapHeader:
    block_count: int
    first_block_entry_index: int
    last_block_entry_index: int
    dummy0: int
    checksum: int

    @classmethod
    def read(cls, stream: BinaryIO) -> "GCFBlockEntryMapHeader":
        data = stream.read(20)
        values = struct.unpack("<5I", data)
        return cls(*values)


@dataclass
class GCFBlockEntryMap:
    previous_block_entry_index: int
    next_block_entry_index: int

    @classmethod
    def read(cls, stream: BinaryIO) -> "GCFBlockEntryMap":
        data = stream.read(8)
        values = struct.unpack("<2I", data)
        return cls(*values)


@dataclass
class GCFDirectoryHeader:
    dummy0: int
    cache_id: int
    last_version_played: int
    item_count: int
    file_count: int
    dummy1: int
    directory_size: int
    name_size: int
    info1_count: int
    copy_count: int
    local_count: int
    dummy2: int
    dummy3: int
    checksum: int

    @classmethod
    def read(cls, stream: BinaryIO) -> "GCFDirectoryHeader":
        data = stream.read(56)
        values = struct.unpack("<14I", data)
        return cls(*values)


@dataclass
class GCFDirectoryEntry:
    name_offset: int
    item_size: int
    checksum_index: int
    directory_flags: int
    parent_index: int
    next_index: int
    first_index: int

    @classmethod
    def read(cls, stream: BinaryIO) -> "GCFDirectoryEntry":
        data = stream.read(28)
        values = struct.unpack("<7I", data)
        return cls(*values)


@dataclass
class GCFDirectoryInfo1Entry:
    dummy0: int

    @classmethod
    def read(cls, stream: BinaryIO) -> "GCFDirectoryInfo1Entry":
        data = stream.read(4)
        (dummy0,) = struct.unpack("<I", data)
        return cls(dummy0)


@dataclass
class GCFDirectoryInfo2Entry:
    dummy0: int

    @classmethod
    def read(cls, stream: BinaryIO) -> "GCFDirectoryInfo2Entry":
        data = stream.read(4)
        (dummy0,) = struct.unpack("<I", data)
        return cls(dummy0)


@dataclass
class GCFDirectoryCopyEntry:
    directory_index: int

    @classmethod
    def read(cls, stream: BinaryIO) -> "GCFDirectoryCopyEntry":
        data = stream.read(4)
        (directory_index,) = struct.unpack("<I", data)
        return cls(directory_index)


@dataclass
class GCFDirectoryLocalEntry:
    directory_index: int

    @classmethod
    def read(cls, stream: BinaryIO) -> "GCFDirectoryLocalEntry":
        data = stream.read(4)
        (directory_index,) = struct.unpack("<I", data)
        return cls(directory_index)


@dataclass
class GCFDirectoryMapHeader:
    dummy0: int
    dummy1: int

    @classmethod
    def read(cls, stream: BinaryIO) -> "GCFDirectoryMapHeader":
        data = stream.read(8)
        values = struct.unpack("<2I", data)
        return cls(*values)


@dataclass
class GCFDirectoryMapEntry:
    first_block_index: int

    @classmethod
    def read(cls, stream: BinaryIO) -> "GCFDirectoryMapEntry":
        data = stream.read(4)
        (first_block_index,) = struct.unpack("<I", data)
        return cls(first_block_index)


@dataclass
class GCFChecksumHeader:
    dummy0: int
    checksum_size: int

    @classmethod
    def read(cls, stream: BinaryIO) -> "GCFChecksumHeader":
        data = stream.read(8)
        values = struct.unpack("<2I", data)
        return cls(*values)


@dataclass
class GCFChecksumMapHeader:
    dummy0: int
    dummy1: int
    item_count: int
    checksum_count: int

    @classmethod
    def read(cls, stream: BinaryIO) -> "GCFChecksumMapHeader":
        data = stream.read(16)
        values = struct.unpack("<4I", data)
        return cls(*values)


@dataclass
class GCFChecksumMapEntry:
    checksum_count: int
    first_checksum_index: int

    @classmethod
    def read(cls, stream: BinaryIO) -> "GCFChecksumMapEntry":
        data = stream.read(8)
        values = struct.unpack("<2I", data)
        return cls(*values)


@dataclass
class GCFChecksumEntry:
    checksum: int

    @classmethod
    def read(cls, stream: BinaryIO) -> "GCFChecksumEntry":
        data = stream.read(4)
        (checksum,) = struct.unpack("<I", data)
        return cls(checksum)


@dataclass
class GCFDataBlockHeader:
    last_version_played: int
    block_count: int
    block_size: int
    first_block_offset: int
    blocks_used: int
    checksum: int

    @classmethod
    def read(cls, stream: BinaryIO, version: int) -> "GCFDataBlockHeader":
        if version < 5:
            data = stream.read(20)
            block_count, block_size, first_block_offset, blocks_used, checksum = struct.unpack("<5I", data)
            return cls(0, block_count, block_size, first_block_offset, blocks_used, checksum)
        data = stream.read(24)
        values = struct.unpack("<6I", data)
        return cls(*values)


###############################################################################
# 1b. Directory tree structures
###############################################################################


@dataclass
class DirectoryItem:
    name: str
    index: int
    flags: int
    parent: Optional["DirectoryFolder"] = None


@dataclass
class DirectoryFile(DirectoryItem):
    size: int = 0


@dataclass
class DirectoryFolder(DirectoryItem):
    children: List[DirectoryItem] = field(default_factory=list)

    def add_folder(self, name: str, index: int, flags: int) -> "DirectoryFolder":
        folder = DirectoryFolder(name, index, flags, parent=self)
        self.children.append(folder)
        return folder

    def add_file(self, name: str, index: int, size: int, flags: int) -> DirectoryFile:
        file = DirectoryFile(name, index, flags, parent=self, size=size)
        self.children.append(file)
        return file

###############################################################################
# 2.  Skeleton class definition
###############################################################################


class GCFFile:
    """Python re-implementation of HLLib's CGCFFile."""

    def __init__(self, source: BinaryIO | str):
        if isinstance(source, (str, bytes, bytearray)):
            # Open in read/write mode so that defragmentation can update the file
            # in-place.  Callers that only need read access may pass an existing
            # stream opened in the desired mode.
            self.stream: BinaryIO = open(source, "r+b")
            self._owns_stream = True
        else:
            self.stream = source
            self._owns_stream = False

        # Placeholders for all major data blocks.
        self.header: Optional[GCFHeader] = None
        self.block_entry_header: Optional[GCFBlockEntryHeader] = None
        self.block_entries: List[GCFBlockEntry] = []
        self.fragmentation_map_header: Optional[GCFFragmentationMapHeader] = None
        self.fragmentation_map: List[GCFFragmentationMap] = []
        self.block_entry_map_header: Optional[GCFBlockEntryMapHeader] = None
        self.block_entry_map: List[GCFBlockEntryMap] = []
        self.directory_header: Optional[GCFDirectoryHeader] = None
        self.directory_entries: List[GCFDirectoryEntry] = []
        self.directory_names: Optional[bytes] = None
        self.directory_info1_entries: List[GCFDirectoryInfo1Entry] = []
        self.directory_info2_entries: List[GCFDirectoryInfo2Entry] = []
        self.directory_copy_entries: List[GCFDirectoryCopyEntry] = []
        self.directory_local_entries: List[GCFDirectoryLocalEntry] = []
        self.directory_map_header: Optional[GCFDirectoryMapHeader] = None
        self.directory_map_entries: List[GCFDirectoryMapEntry] = []
        self.checksum_header: Optional[GCFChecksumHeader] = None
        self.checksum_map_header: Optional[GCFChecksumMapHeader] = None
        self.checksum_map_entries: List[GCFChecksumMapEntry] = []
        self.checksum_entries: List[GCFChecksumEntry] = []
        self.data_block_header: Optional[GCFDataBlockHeader] = None
        self._version: Optional[int] = None

        # Directory tree storage populated in step 3.
        self.directory_items: List[Optional[DirectoryItem]] = []
        self.root: Optional[DirectoryFolder] = None

        self.map_data_structures()
        self.build_directory_tree()

    # ------------------------------------------------------------------
    # Mapping / unmapping
    # ------------------------------------------------------------------
    def map_data_structures(self) -> None:
        """Parse header structures from the stream."""
        self.stream.seek(0)

        self.header = GCFHeader.read(self.stream)
        if (
            self.header.major_version != 1
            or self.header.minor_version not in (1, 3, 5, 6)
        ):
            raise ValueError(
                f"Unsupported GCF version {self.header.major_version}.{self.header.minor_version}"
            )
        self._version = self.header.minor_version

        self.block_entry_header = GCFBlockEntryHeader.read(self.stream)
        self.block_entries = [
            GCFBlockEntry.read(self.stream)
            for _ in range(self.block_entry_header.block_count)
        ]

        self.fragmentation_map_header = GCFFragmentationMapHeader.read(self.stream)
        self.fragmentation_map = [
            GCFFragmentationMap.read(self.stream)
            for _ in range(self.fragmentation_map_header.block_count)
        ]

        if self._version < 6:
            self.block_entry_map_header = GCFBlockEntryMapHeader.read(self.stream)
            self.block_entry_map = [
                GCFBlockEntryMap.read(self.stream)
                for _ in range(self.block_entry_map_header.block_count)
            ]
        else:
            self.block_entry_map_header = None
            self.block_entry_map = []

        self.directory_header = GCFDirectoryHeader.read(self.stream)
        self.directory_entries = [
            GCFDirectoryEntry.read(self.stream)
            for _ in range(self.directory_header.item_count)
        ]
        self.directory_names = self.stream.read(self.directory_header.name_size)
        self.directory_info1_entries = [
            GCFDirectoryInfo1Entry.read(self.stream)
            for _ in range(self.directory_header.info1_count)
        ]
        self.directory_info2_entries = [
            GCFDirectoryInfo2Entry.read(self.stream)
            for _ in range(self.directory_header.item_count)
        ]
        self.directory_copy_entries = [
            GCFDirectoryCopyEntry.read(self.stream)
            for _ in range(self.directory_header.copy_count)
        ]
        self.directory_local_entries = [
            GCFDirectoryLocalEntry.read(self.stream)
            for _ in range(self.directory_header.local_count)
        ]

        if self._version >= 5:
            self.directory_map_header = GCFDirectoryMapHeader.read(self.stream)
        else:
            self.directory_map_header = None

        self.directory_map_entries = [
            GCFDirectoryMapEntry.read(self.stream)
            for _ in range(self.directory_header.item_count)
        ]

        if self._version > 1:
            self.checksum_header = GCFChecksumHeader.read(self.stream)
            self.checksum_map_header = GCFChecksumMapHeader.read(self.stream)
            self.checksum_map_entries = [
                GCFChecksumMapEntry.read(self.stream)
                for _ in range(self.checksum_map_header.item_count)
            ]
            self.checksum_entries = [
                GCFChecksumEntry.read(self.stream)
                for _ in range(self.checksum_map_header.checksum_count)
            ]
        else:
            self.checksum_header = None
            self.checksum_map_header = None
            self.checksum_map_entries = []
            self.checksum_entries = []

        self.data_block_header = GCFDataBlockHeader.read(self.stream, self._version)

    def unmap_data_structures(self) -> None:
        self.header = None
        self.block_entry_header = None
        self.block_entries = []
        self.fragmentation_map_header = None
        self.fragmentation_map = []
        self.block_entry_map_header = None
        self.block_entry_map = []
        self.directory_header = None
        self.directory_entries = []
        self.directory_names = None
        self.directory_info1_entries = []
        self.directory_info2_entries = []
        self.directory_copy_entries = []
        self.directory_local_entries = []
        self.directory_map_header = None
        self.directory_map_entries = []
        self.checksum_header = None
        self.checksum_map_header = None
        self.checksum_map_entries = []
        self.checksum_entries = []
        self.data_block_header = None
        self._version = None
        self.directory_items = []
        self.root = None

    def close(self) -> None:
        self.unmap_data_structures()
        if self._owns_stream:
            self.stream.close()

    # ------------------------------------------------------------------
    # Step 3: Directory tree construction
    # ------------------------------------------------------------------
    def build_directory_tree(self) -> None:
        if not self.directory_header:
            return
        count = self.directory_header.item_count
        self.directory_items = [None] * count

        self.root = DirectoryFolder("root", 0, 0)
        self.directory_items[0] = self.root
        self._build_folder(self.root)

    def _read_name(self, offset: int) -> str:
        if self.directory_names is None:
            return ""
        end = self.directory_names.find(b"\x00", offset)
        if end == -1:
            end = len(self.directory_names)
        return self.directory_names[offset:end].decode("utf-8", "replace")

    def _build_folder(self, folder: DirectoryFolder) -> None:
        entry = self.directory_entries[folder.index]
        index = entry.first_index
        while index and index != 0xFFFFFFFF:
            child_entry = self.directory_entries[index]
            name = self._read_name(child_entry.name_offset)
            if (child_entry.directory_flags & HL_GCF_FLAG_FILE) == 0:
                child = folder.add_folder(name, index, child_entry.directory_flags)
                self.directory_items[index] = child
                self._build_folder(child)
            else:
                file = folder.add_file(name, index, child_entry.item_size, child_entry.directory_flags)
                self.directory_items[index] = file
            index = child_entry.next_index

    # ------------------------------------------------------------------
    # Step 4: Basic item utilities
    # ------------------------------------------------------------------
    def get_file_extractable(self, file_index: int) -> bool:
        entry = self.directory_entries[file_index]
        if entry.directory_flags & HL_GCF_FLAG_ENCRYPTED:
            return False
        size = 0
        block_index = self.directory_map_entries[file_index].first_block_index
        while block_index != self.data_block_header.block_count:
            block_entry = self.block_entries[block_index]
            size += block_entry.file_data_size
            block_index = block_entry.next_block_entry_index
        return size >= entry.item_size

    def get_item_fragmentation(self, index: int) -> tuple[int, int]:
        blocks_fragmented = 0
        blocks_used = 0

        entry = self.directory_entries[index]
        if (entry.directory_flags & HL_GCF_FLAG_FILE) == 0:
            idx = entry.first_index
            while idx and idx != 0xFFFFFFFF:
                f, u = self.get_item_fragmentation(idx)
                blocks_fragmented += f
                blocks_used += u
                idx = self.directory_entries[idx].next_index
            return blocks_fragmented, blocks_used

        data_block_terminator = (
            0x0000FFFF if self.fragmentation_map_header and self.fragmentation_map_header.terminator == 0 else 0xFFFFFFFF
        )
        last_block_index = self.data_block_header.block_count
        block_entry_index = self.directory_map_entries[index].first_block_index
        while block_entry_index != self.data_block_header.block_count:
            block_entry_size = 0
            data_block_index = self.block_entries[block_entry_index].first_data_block_index
            while (
                data_block_index < data_block_terminator
                and block_entry_size < self.block_entries[block_entry_index].file_data_size
            ):
                if last_block_index != self.data_block_header.block_count and last_block_index + 1 != data_block_index:
                    blocks_fragmented += 1
                blocks_used += 1
                last_block_index = data_block_index
                data_block_index = self.fragmentation_map[data_block_index].next_data_block_index
                block_entry_size += self.data_block_header.block_size
            block_entry_index = self.block_entries[block_entry_index].next_block_entry_index
        return blocks_fragmented, blocks_used

    # ------------------------------------------------------------------
    # Defragmentation utilities
    # ------------------------------------------------------------------
    def defragment(self, force: bool = False) -> bool:
        """Rewrite data blocks sequentially to eliminate fragmentation.

        This mirrors ``CGCFFile::DefragmentInternal`` from HLLib.  The
        implementation is intentionally conservative: all data blocks are read
        into memory before any writes occur to avoid overwriting blocks whose
        contents have not yet been copied.

        Parameters
        ----------
        force:
            If ``True`` the file will be rewritten even if no fragmentation is
            detected.  HLLib exposes a similar flag to force lexicographical
            ordering.

        Returns
        -------
        bool
            ``True`` if the operation completed, ``False`` otherwise.
        """

        if not self.stream.writable():
            raise IOError("underlying stream is not writable; defragmentation requires write access")

        if not self.fragmentation_map_header or not self.data_block_header:
            return False

        # Determine current fragmentation state.
        blocks_fragmented = 0
        blocks_used = 0
        for i, entry in enumerate(self.directory_entries):
            if entry.directory_flags & HL_GCF_FLAG_FILE:
                f, u = self.get_item_fragmentation(i)
                blocks_fragmented += f
                blocks_used += u

        if (blocks_fragmented == 0 and not force) or blocks_used == 0:
            return True

        terminator = (
            0x0000FFFF
            if self.fragmentation_map_header.terminator == 0
            else 0xFFFFFFFF
        )

        # ------------------------------------------------------------------
        # Build a mapping from old data block index -> new sequential index.
        # ------------------------------------------------------------------
        mapping: dict[int, int] = {}
        next_index = 0
        for i, entry in enumerate(self.directory_entries):
            if entry.directory_flags & HL_GCF_FLAG_FILE:
                block_entry_index = self.directory_map_entries[i].first_block_index
                while block_entry_index != self.data_block_header.block_count:
                    block_entry = self.block_entries[block_entry_index]
                    remaining = block_entry.file_data_size
                    data_block_index = block_entry.first_data_block_index
                    while remaining > 0 and data_block_index < terminator:
                        mapping[data_block_index] = next_index
                        next_index += 1
                        remaining -= self.data_block_header.block_size
                        data_block_index = self.fragmentation_map[data_block_index].next_data_block_index
                    block_entry_index = block_entry.next_block_entry_index

        # ------------------------------------------------------------------
        # Read all used data blocks into memory then write them sequentially.
        # ------------------------------------------------------------------
        block_size = self.data_block_header.block_size
        first_block_offset = self.data_block_header.first_block_offset
        data_cache: dict[int, bytes] = {}
        for old_index in sorted(mapping):
            self.stream.seek(first_block_offset + old_index * block_size)
            data_cache[old_index] = self.stream.read(block_size)

        for old_index, new_index in mapping.items():
            if old_index == new_index:
                continue
            self.stream.seek(first_block_offset + new_index * block_size)
            self.stream.write(data_cache[old_index])

        # ------------------------------------------------------------------
        # Rebuild block entries and the fragmentation map using the new layout
        # ------------------------------------------------------------------
        block_count = self.fragmentation_map_header.block_count
        new_fragmentation_map = [
            GCFFragmentationMap(block_count) for _ in range(block_count)
        ]

        for i, entry in enumerate(self.directory_entries):
            if entry.directory_flags & HL_GCF_FLAG_FILE:
                block_entry_index = self.directory_map_entries[i].first_block_index
                while block_entry_index != self.data_block_header.block_count:
                    block_entry = self.block_entries[block_entry_index]
                    remaining = block_entry.file_data_size
                    first_old = block_entry.first_data_block_index
                    block_entry.first_data_block_index = mapping[first_old]

                    data_block_index = first_old
                    while remaining > 0 and data_block_index < terminator:
                        new_index = mapping[data_block_index]
                        next_old = self.fragmentation_map[data_block_index].next_data_block_index
                        if remaining <= self.data_block_header.block_size or next_old >= terminator:
                            new_next = terminator
                        else:
                            new_next = mapping[next_old]
                        new_fragmentation_map[new_index].next_data_block_index = new_next
                        data_block_index = next_old
                        remaining -= self.data_block_header.block_size

                    block_entry_index = block_entry.next_block_entry_index

        for i in range(next_index, block_count):
            new_fragmentation_map[i].next_data_block_index = block_count

        self.fragmentation_map = new_fragmentation_map
        self.fragmentation_map_header.first_unused_entry = next_index
        self.fragmentation_map_header.checksum = (
            self.fragmentation_map_header.block_count
            + self.fragmentation_map_header.first_unused_entry
            + self.fragmentation_map_header.terminator
        ) & 0xFFFFFFFF

        # ------------------------------------------------------------------
        # Write updated tables back to the stream.
        # ------------------------------------------------------------------
        block_entries_offset = 44 + 32
        frag_header_offset = (
            block_entries_offset
            + 28 * self.block_entry_header.block_count
        )
        frag_map_offset = frag_header_offset + 16

        for i, entry in enumerate(self.block_entries):
            self.stream.seek(block_entries_offset + i * 28)
            self.stream.write(
                struct.pack(
                    "<7I",
                    entry.entry_flags,
                    entry.file_data_offset,
                    entry.file_data_size,
                    entry.first_data_block_index,
                    entry.next_block_entry_index,
                    entry.previous_block_entry_index,
                    entry.directory_index,
                )
            )

        self.stream.seek(frag_header_offset)
        self.stream.write(
            struct.pack(
                "<4I",
                self.fragmentation_map_header.block_count,
                self.fragmentation_map_header.first_unused_entry,
                self.fragmentation_map_header.terminator,
                self.fragmentation_map_header.checksum,
            )
        )

        for i, fm in enumerate(self.fragmentation_map):
            self.stream.seek(frag_map_offset + i * 4)
            self.stream.write(struct.pack("<I", fm.next_data_block_index))

        self.stream.flush()

        return True

    # ------------------------------------------------------------------
    # Step 5: File data access and validation
    # ------------------------------------------------------------------
    def get_file_size(self, file_index: int) -> int:
        return self.directory_entries[file_index].item_size

    def get_file_size_on_disk(self, file_index: int) -> int:
        size = 0
        block_index = self.directory_map_entries[file_index].first_block_index
        while block_index != self.data_block_header.block_count:
            block = self.block_entries[block_index]
            size += ((block.file_data_size + self.data_block_header.block_size - 1) // self.data_block_header.block_size) * self.data_block_header.block_size
            block_index = block.next_block_entry_index
        return size

    def read_file(self, file_index: int) -> bytes:
        entry = self.directory_entries[file_index]
        output = bytearray()
        block_entry_index = self.directory_map_entries[file_index].first_block_index
        data_block_terminator = (
            0x0000FFFF
            if self.fragmentation_map_header and self.fragmentation_map_header.terminator == 0
            else 0xFFFFFFFF
        )
        while block_entry_index != self.data_block_header.block_count:
            block_entry = self.block_entries[block_entry_index]
            remaining = block_entry.file_data_size
            data_block_index = block_entry.first_data_block_index
            while remaining > 0 and data_block_index < data_block_terminator:
                to_read = min(self.data_block_header.block_size, remaining)
                offset = self.data_block_header.first_block_offset + data_block_index * self.data_block_header.block_size
                self.stream.seek(offset)
                output.extend(self.stream.read(to_read))
                remaining -= to_read
                data_block_index = self.fragmentation_map[data_block_index].next_data_block_index
            block_entry_index = block_entry.next_block_entry_index
        return bytes(output[: entry.item_size])

    def open_stream(self, file_index: int) -> "GCFStream":
        """Return a :class:`GCFStream` for the given file index."""
        from gcfstream import GCFStream

        return GCFStream(self, file_index)

    def validate_file(self, file_index: int) -> str:
        entry = self.directory_entries[file_index]

        # Ensure we have all data blocks required for the file.
        size = 0
        block_index = self.directory_map_entries[file_index].first_block_index
        while block_index != self.data_block_header.block_count:
            size += self.block_entries[block_index].file_data_size
            block_index = self.block_entries[block_index].next_block_entry_index
        if size != entry.item_size:
            return "incomplete"

        if entry.directory_flags & HL_GCF_FLAG_ENCRYPTED:
            return "assumed-ok"
        if entry.checksum_index == 0xFFFFFFFF or not self.checksum_map_entries:
            return "assumed-ok"

        data = self.read_file(file_index)
        map_entry = self.checksum_map_entries[entry.checksum_index]
        for i in range(map_entry.checksum_count):
            start = i * HL_GCF_CHECKSUM_LENGTH
            end = start + HL_GCF_CHECKSUM_LENGTH
            chunk = data[start:end]
            checksum = (zlib.adler32(chunk) ^ binascii.crc32(chunk)) & 0xFFFFFFFF
            stored = self.checksum_entries[map_entry.first_checksum_index + i].checksum
            if checksum != stored:
                return "corrupt"
        return "ok"

    # ------------------------------------------------------------------
    # Package and item attribute helpers
    # ------------------------------------------------------------------
    def get_package_attributes(self) -> dict[str, int]:
        if not self.header or not self.data_block_header:
            return {}
        return {
            PACKAGE_ATTRIBUTE_NAMES[0]: self.header.minor_version,
            PACKAGE_ATTRIBUTE_NAMES[1]: self.header.cache_id,
            PACKAGE_ATTRIBUTE_NAMES[2]: self.data_block_header.block_count,
            PACKAGE_ATTRIBUTE_NAMES[3]: self.data_block_header.blocks_used,
            PACKAGE_ATTRIBUTE_NAMES[4]: self.data_block_header.block_size,
            PACKAGE_ATTRIBUTE_NAMES[5]: self.header.last_version_played,
        }

    def get_item_attributes(self, index: int) -> dict[str, object]:
        entry = self.directory_entries[index]
        attrs = {
            ITEM_ATTRIBUTE_NAMES[4]: entry.directory_flags,
        }
        if entry.directory_flags & HL_GCF_FLAG_FILE:
            attrs.update(
                {
                    ITEM_ATTRIBUTE_NAMES[0]: bool(entry.directory_flags & HL_GCF_FLAG_ENCRYPTED),
                    ITEM_ATTRIBUTE_NAMES[1]: bool(entry.directory_flags & HL_GCF_FLAG_COPY_LOCAL),
                    ITEM_ATTRIBUTE_NAMES[2]: not bool(entry.directory_flags & HL_GCF_FLAG_COPY_LOCAL_NO_OVERWRITE),
                    ITEM_ATTRIBUTE_NAMES[3]: bool(entry.directory_flags & HL_GCF_FLAG_BACKUP_LOCAL),
                }
            )
        else:
            attrs.update(
                {
                    ITEM_ATTRIBUTE_NAMES[0]: False,
                    ITEM_ATTRIBUTE_NAMES[1]: False,
                    ITEM_ATTRIBUTE_NAMES[2]: True,
                    ITEM_ATTRIBUTE_NAMES[3]: False,
                }
            )
        blocks_fragmented, blocks_used = self.get_item_fragmentation(index)
        attrs[ITEM_ATTRIBUTE_NAMES[5]] = (
            0.0 if blocks_used == 0 else (blocks_fragmented / blocks_used) * 100.0
        )
        return attrs


__all__ = [
    "PACKAGE_ATTRIBUTE_NAMES",
    "ITEM_ATTRIBUTE_NAMES",
    "GCFHeader",
    "GCFBlockEntryHeader",
    "GCFBlockEntry",
    "GCFFragmentationMapHeader",
    "GCFFragmentationMap",
    "GCFBlockEntryMapHeader",
    "GCFBlockEntryMap",
    "GCFDirectoryHeader",
    "GCFDirectoryEntry",
    "GCFDirectoryInfo1Entry",
    "GCFDirectoryInfo2Entry",
    "GCFDirectoryCopyEntry",
    "GCFDirectoryLocalEntry",
    "GCFDirectoryMapHeader",
    "GCFDirectoryMapEntry",
    "GCFChecksumHeader",
    "GCFChecksumMapHeader",
    "GCFChecksumMapEntry",
    "GCFChecksumEntry",
    "GCFDataBlockHeader",
    "DirectoryItem",
    "DirectoryFile",
    "DirectoryFolder",
    "GCFFile",
]
