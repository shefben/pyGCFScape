"""Utilities for generating legacy v1 GCF structures.

This module adapts the structure building logic from the
``v1GCF_creator`` project by shefben which faithfully recreates the
behaviour of the 2002/2003 era Steam cache generators.  The original
tool emits the manifest and copy tables as standalone files.  We reuse
the same layout rules here so that :mod:`pysteam` can emit a single
GCF container that matches the legacy format.

Only the pieces that differ from the later GCF revisions are exposed –
namely the manifest header layout, sequential file identifiers and the
minimum-footprint copy table.  The rest of the conversion pipeline is
handled by :meth:`pysteam.fs.cachefile.CacheFile.convert_version`.
"""

from __future__ import annotations

from typing import Iterable, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - imported only for type checking
    from .cachefile import CacheFileManifest

# The threaded v1 generator writes manifests that advertise 0x8000 sized
# compressed blocks.  Reusing the same constant keeps the binary output
# aligned with original tooling.  (See ``threaded_manifest_generator.py``
# in shefben/v1GCF_creator.)
V1_COMPRESSION_BLOCK_SIZE = 0x8000
FLAG_IS_FILE = 0x00004000
FLAG_IS_PURGE_FILE = 0x00000080


def _iter_file_entries(manifest: "CacheFileManifest") -> Iterable[object]:
    """Yield manifest entries that represent files."""

    for entry in manifest.manifest_entries:
        if entry.directory_flags & FLAG_IS_FILE:
            yield entry


def prepare_manifest_for_v1(manifest: "CacheFileManifest") -> None:
    """Mutate ``manifest`` so it matches the layout used by v1 GCF files.

    The procedure mirrors the logic from ``threaded_manifest_generator``:

    * Manifest header version is ``3`` and ``DepotInfo`` remains ``2``.
    * Files receive sequential ``FileID`` values (``checksum_index``).
    * The copy table lists minimum-footprint files; if none are marked we
      fall back to listing every file, matching the reference tool.
    * Hash tables consist of a single bucket that chains every node,
      identical to the legacy manifests emitted by the original tool.
    * Per-file flags are synchronised with the copy table so that
      minimum-footprint entries always carry ``FLAG_IS_PURGE_FILE``.
    """

    manifest.header_version = 3
    manifest.depot_info = 2
    manifest.compression_block_size = V1_COMPRESSION_BLOCK_SIZE
    manifest.map_header_version = 1
    manifest.map_dummy1 = 0

    file_entries = list(_iter_file_entries(manifest))

    for file_id, entry in enumerate(file_entries, start=1):
        entry.checksum_index = file_id

    manifest.file_count = len(file_entries)
    manifest.node_count = len(manifest.manifest_entries)

    # v1 manifests always shipped with a single hash bucket whose chain
    # enumerates every manifest entry in order.  Recreating that behaviour
    # keeps lookups identical to the original tool.
    if manifest.node_count:
        head = 1 if manifest.node_count > 1 else 0
        manifest.hash_table_keys = [head]
        manifest.hash_table_indices = list(range(manifest.node_count))
        manifest.hash_table_indices[-1] |= 0x8000_0000
    else:
        manifest.hash_table_keys = []
        manifest.hash_table_indices = []

    # Normalise and validate the minimum-footprint list.  The legacy
    # generator defaults to copying every file when no explicit list is
    # provided.  We adopt the same fallback so the copy table remains
    # populated even if the GUI user did not mark files manually.
    if manifest.minimum_footprint_entries:
        footprint = sorted({
            idx for idx in manifest.minimum_footprint_entries
            if 0 <= idx < manifest.node_count
        })
        if not footprint:
            footprint = [entry.index for entry in file_entries]
    else:
        footprint = [entry.index for entry in file_entries]

    manifest.minimum_footprint_entries = footprint
    manifest.user_config_entries = []

    footprint_set = set(footprint)
    for entry in file_entries:
        if entry.index in footprint_set:
            entry.directory_flags |= FLAG_IS_PURGE_FILE
        else:
            entry.directory_flags &= ~FLAG_IS_PURGE_FILE
