
import struct
import os
import zlib

from pysteam.fs import DirectoryFolder, DirectoryFile, FilesystemPackage
from math import ceil
from zlib import adler32

# For Python 3 compatibility, use io.BytesIO instead of the removed cStringIO module.
from io import BytesIO

try:  # Optional dependency for AES decryption
    from Crypto.Cipher import AES  # type: ignore
except Exception:  # pragma: no cover - handled at runtime
    AES = None

CACHE_CHECKSUM_LENGTH = 0x8000


STEAM_TERMINATOR = "\\"  # Archive path separator
MAX_FILENAME = 0


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
    """Pack an iterable of integers into little-endian DWORD bytes."""
    values = list(values)
    if not values:
        return b""
    return struct.pack(f"<{len(values)}L", *values)

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

    # Main methods.

    @classmethod
    def parse(cls, stream):
        self = cls()

        try:
            self.filename = os.path.split(os.path.realpath(stream.name))[1]
        except AttributeError:
            pass

        # Header
        self.stream = stream
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
        self.checksum_map = CacheFileChecksumMap(self)
        self.checksum_map.parse(stream)
        self.checksum_map.validate()

        if self.is_gcf():
            # Data Header.
            self.data_header = CacheFileSectorHeader(self)
            self.data_header.parse(stream.read(24)) # size of BlockDataHeader (6 longs)
            self.data_header.validate()

        self.is_parsed = True
        self._read_directory()
        return self

    def convert_version(self, target_version: int, out_path: str) -> None:
        """Convert this cache file to a different GCF format version.

        Parameters
        ----------
        target_version:
            The format version to convert to (e.g. ``1`` or ``6``).
        out_path:
            Destination path for the converted archive.

        Notes
        -----
        This is an initial implementation that rewrites the header and core
        tables for ``target_version``.  Data blocks are copied verbatim.  Only
        GCF archives are supported.
        """

        if not self.is_parsed:
            raise ValueError("Cache file needs to be read first.")
        if not self.is_gcf():
            raise ValueError("Only GCF archives can be converted")
        if target_version not in (1, 3, 5, 6):
            raise ValueError("Unsupported GCF version: %d" % target_version)

        # Preserve original state so the in-memory representation remains
        # unchanged after conversion.
        original_version = self.header.format_version
        original_block_entry_map = self.block_entry_map
        original_map_entries = list(self.manifest.manifest_map_entries)
        self.header.format_version = target_version

        # Adjust mapping semantics based on the requested version.  Versions
        # prior to 6 require a block entry map where manifest indices point to
        # that map instead of direct block numbers.  Newer versions store block
        # numbers directly and omit the block entry map entirely.
        if target_version < 6:
            if self.block_entry_map is None:
                bemap = CacheFileBlockEntryMap(self)
                bemap.block_count = self.blocks.block_count
                bemap.entries = list(range(self.blocks.block_count))
                self.block_entry_map = bemap
            inverse = {blk: idx for idx, blk in enumerate(self.block_entry_map.entries)}
            self.manifest.manifest_map_entries = [inverse.get(i, i) for i in original_map_entries]
        else:
            # Convert manifest map entries back to raw block indices and drop
            # the block entry map from the output.
            if self.block_entry_map is not None:
                self.manifest.manifest_map_entries = [
                    self.block_entry_map.entries[i] for i in original_map_entries
                ]
            self.block_entry_map = None

        with open(out_path, "wb") as out:
            out.write(self.header.serialize())
            out.write(self.blocks.serialize())
            out.write(self.alloc_table.serialize())

            if target_version < 6 and self.block_entry_map is not None:
                out.write(self.block_entry_map.serialize())

            # Manifest bytes were buffered during parsing so we can simply
            # replay them.
            out.write(self.manifest.header_data)
            out.write(self.manifest.manifest_stream.getvalue())

            out.write(self.checksum_map.serialize())

            if self.data_header is not None:
                out.write(self.data_header.serialize())

                # Copy raw sector data directly from the original stream.
                self.stream.seek(self.data_header.first_sector_offset)
                out.write(self.stream.read())

        # Restore original state in memory
        self.header.format_version = original_version
        self.block_entry_map = original_block_entry_map
        self.manifest.manifest_map_entries = original_map_entries


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
        # Entries of sectors
        entry.sectors = []
        # Number of blocks in this entry.
        entry.num_of_blocks = ceil(float(entry.size()) / float(self.data_header.sector_size))

        for block in entry._manifest_entry.blocks:
            if block is None:
                entry.sectors = []
                entry.is_fragmented = False
            else:
                # Sector
                entry.is_fragmented = block.is_fragmented
                entry.sectors = block.sectors

            self.complete_available += block.file_data_size

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
        return self.manifest.manifest_entries[file.index].item_size

    @raise_parse_error
    @raise_ncf_error
    def _open_file(self, file, mode, key=None):
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

    # ------------------------------------------------------------------
    def is_fragmented(self) -> bool:
        """Return ``True`` if any data blocks are marked as fragmented.

        Only meaningful for GCF archives; NCF files do not store file data.
        """

        if not self.is_parsed or not self.is_gcf() or not self.blocks:
            return False
        return any(block.is_fragmented for block in self.blocks.blocks)

    # ------------------------------------------------------------------
    def validate(self):
        """Validate file data and return a list of error strings.

        Each file contained in the archive is read and the number of bytes
        retrieved is compared against the size recorded in the manifest.  If
        any errors are encountered or the sizes do not match, a descriptive
        message is appended to the returned list.  An empty list indicates
        the archive appears to be valid.
        """

        errors = []
        if not self.is_parsed:
            return ["Cache file not parsed"]

        for entry in self.root.all_files():
            try:
                stream = entry.open("rb")
                data = stream.readall()
                stream.close()
                if len(data) != entry.size():
                    errors.append(f"{entry.path()}: size mismatch")
            except Exception as exc:  # pragma: no cover - validation errors
                errors.append(f"{entry.path()}: {exc}")

        return errors

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
        self.checksum = sum(data)
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

    FLAG_DATA    = 0x200F8000
    FLAG_DATA_2  = 0x200FC000
    FLAG_NO_DATA = 0x200F0000

    def __init__(self, owner):
        self.owner = owner

    def parse(self, stream):
        # Block Entry
        (self.flags,
         self.dummy1,
         self.file_data_offset,
         self.file_data_size,
         self._first_sector_index,
         self._next_block_index,
         self._prev_block_index,
         self.manifest_index) = struct.unpack("<2H6L", stream.read(28))

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
        return CacheFileSector(self, self._first_sector_index)

    def _set_first_sector(self, value):
        self._first_sector_index = value.inde

    def _get_is_fragmented(self):
        return (self.owner.owner.alloc_table[self._first_sector_index] - self._first_sector_index) != -1

    next_block = property(_get_next_block, _set_next_block)
    prev_block = property(_get_prev_block, _set_prev_block)
    first_sector = property(_get_first_sector, _set_first_sector)
    sectors = property(_get_sector_iterator)
    is_fragmented = property(_get_is_fragmented)

    def serialize(self):
        return struct.pack("<2H6L", self.flags, self.dummy1, self.file_data_offset, self.file_data_size, self._first_sector_index, self._next_block_index, self._prev_block_index, self.manifest_index)

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
        (self.sector_count,
         self.first_unused_entry,
         self.is_long_terminator) = struct.unpack("<3L", stream.read(12))
        self.checksum = sum(stream.read(4))

        self.terminator = 0xFFFFFFFF if self.owner.alloc_table.is_long_terminator == 1 else 0xFFFF
        self.entries = unpack_dword_list(stream, self.sector_count)

    def serialize(self):
        data = struct.pack("<3L", self.sector_count, self.first_unused_entry, self.is_long_terminator)
        self.checksum = sum(data)
        return data + struct.pack("<L", self.checksum) + pack_dword_list(self.entries)

    def calculate_checksum(self):
        return sum(self.serialize()[:12])

    def validate(self):
        if self.owner.header.sector_count != self.sector_count:
            raise ValueError("Invalid Cache Allocation Table [SectorCounts do not match]")
        if self.checksum != self.calculate_checksum():
            raise ValueError("Invalid Cache Allocation Table [Checksums do not match]")

class CacheFileBlockEntryMap:

    def __init__(self, owner):
        self.owner = owner
        self.entries = []

    def parse(self, stream):
        # Header contains block count followed by a checksum field
        (self.block_count,) = struct.unpack("<L", stream.read(4))
        self.checksum = sum(stream.read(4))
        self.entries = unpack_dword_list(stream, self.block_count)

    def serialize(self):
        data = struct.pack("<L", self.block_count)
        self.checksum = sum(data)
        return data + struct.pack("<L", self.checksum) + pack_dword_list(self.entries)


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
        self.user_config_entries = unpack_dword_list(self.manifest_stream, self.num_of_user_config_files)

        # Manifest Map Header
        (self.map_header_version,
         self.map_dummy1) = struct.unpack("<2L", stream.read(8))

        # Manifest Map Entries (FirstBlockIndex)
        self.manifest_map_entries = unpack_dword_list(stream, self.node_count)

    def serialize(self):
        # 56 = size of Header
        # 32 = size of ManifestEntry + size of DWORD for HashTableIndices
        self.name_size = len(self.filename_table)
        self.binary_size = 56 + 32*self.node_count + self.name_size + 4*(self.hash_table_key_count+self.num_of_user_config_files+self.num_of_minimum_footprint_files)
        self.header_data = struct.pack("<9L",
          self.header_version,
          self.application_id,
          self.application_version,
          self.node_count,
          self.file_count,
          self.compression_block_size,
          self.binary_size,
          self.name_size,
          self.depot_info)

        manifest_data = []
        for i in self.manifest_entries:
            manifest_data.append(i.serialize())

        manifest_data.append(self.filename_table)
        manifest_data.append(pack_dword_list(self.hash_table_keys))
        manifest_data.append(pack_dword_list(self.hash_table_indices))
        manifest_data.append(pack_dword_list(self.user_config_entries))
        manifest_data.append(pack_dword_list(self.hash_table_keys))
        manifest_data.append(struct.pack("<2L", self.map_header_version, self.map_dummy1))
        manifest_data.append(pack_dword_list(self.manifest_map_entries))
        manifest_data = b"".join(manifest_data)

        self.checksum = adler32(self.header_data + b"\0\0\0\0\0\0\0\0" + manifest_data, 0)
        return self.header_data + struct.pack("<2L", self.fingerprint, self.checksum) + manifest_data

    def validate(self):
        if self.owner.header.application_id != self.application_id:
            raise ValueError("Invalid Cache File Manifest [Application ID mismatch]")
        if self.owner.header.application_version != self.application_version:
            raise ValueError("Invalid Cache File Manifest [Application version mismatch]")
        #if self.checksum != self.calculate_checksum():
        #    raise ValueError, "Invalid Cache File Manifest [Checksum mismatch]"
        if self.map_header_version != 1:
            raise ValueError("Invalid Cache File Manifest [ManifestHeaderMap's HeaderVersion is not 1]")
        if self.map_dummy1 != 0:
            raise ValueError("Invalid Cache File Manifest [ManifestHeaderMap's Dummy1 is not 0]")

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

    def serialize(self):
        data = [struct.pack("<6L", self.header_version, self.checksum_size, self.format_code, self.version, self.file_id_count, self.checksum_count)]
        data += [struct.pack("<2L", *i) for i in self.entries]
        data.append(pack_dword_list(self.checksums))
        data.append(self.signature)
        return b"".join(data)

    def validate(self):
        pass
        # NOTE: This check is incorrect on the test file (half-life 2 game dialog.gcf) I have.
        # if self.owner.directory.file_count != self.item_count:
        #     raise ValueError, "Invalid Cache File Checksum Map [ItemCount and FileCount don't match]"

class CacheFileSectorHeader:

    def __init__(self, owner):
        self.owner = owner

    def parse(self, data):
        (self.application_version,
         self.sector_count,
         self.sector_size,
         self.first_sector_offset,
         self.sectors_used,
         self.checksum) = struct.unpack("<6L", data)


    def serialize(self):
        self.checksum = self.calculate_checksum()
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
        if self.application_version != self.owner.header.application_version:
            raise ValueError("Invalid Cache File Sector Header [ApplicationVersion mismatch]")
        if self.sector_count != self.owner.header.sector_count:
            raise ValueError("Invalid Cache File Sector Header [SectorCount mismatch]")
        if self.sector_size != self.owner.header.sector_size:
            raise ValueError("Invalid Cache File Sector Header [SectorSize mismatch]")
        if self.checksum != self.calculate_checksum():
            raise ValueError("Invalid Cache File Sector Header [Checksum mismatch]")

    def calculate_checksum(self):
        return self.sector_count + self.sector_size + self.first_sector_offset + self.sectors_used

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
        raw = b"".join(sect.get_data() for sect in self.entry.sectors)
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
                data.append(sector[offset:min(sector_size, size)])
                size -= sector_size
                offset = 0

        else:

            while read_pos < size:

                # It can't be bigger than the sector size or
                # Take the minimum of the two and get the rest of the data on the next iteration.
                read_length = min(size - read_pos, sector_size - offset)
                data.append(self.sectors[sector_index][offset:read_length])

                sector_index += 1
                offset = 0

            self.position += size
            read_pos += size

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
