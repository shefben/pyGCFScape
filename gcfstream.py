from __future__ import annotations

import os
from typing import List, Tuple

from cachefile import GCFFile


class GCFStream:
    """Stream interface for reading file data from a ``GCFFile``."""

    def __init__(self, gcf: GCFFile, index: int) -> None:
        self.gcf = gcf
        self.index = index
        self.length = gcf.directory_entries[index].item_size
        self.position = 0
        self.block_size = gcf.data_block_header.block_size

        self._segments: List[Tuple[int, int, int]] = []
        self._build_segments()
        self._segment_index = 0

    def _build_segments(self) -> None:
        """Pre-compute the data block sequence for this file."""
        terminator = (
            0xFFFF if self.gcf.fragmentation_map_header.terminator == 0 else 0xFFFFFFFF
        )
        block_entry_index = self.gcf.directory_map_entries[self.index].first_block_index
        block_entry_terminator = self.gcf.data_block_header.block_count
        offset = 0
        while (
            block_entry_index != block_entry_terminator
            and block_entry_index < len(self.gcf.block_entries)
        ):
            block_entry = self.gcf.block_entries[block_entry_index]
            data_block_index = block_entry.first_data_block_index
            data_block_offset = 0
            while (
                data_block_offset < block_entry.file_data_size
                and data_block_index < terminator
            ):
                length = min(
                    self.block_size, block_entry.file_data_size - data_block_offset
                )
                self._segments.append((offset, data_block_index, length))
                offset += length
                data_block_offset += length
                if data_block_offset < block_entry.file_data_size:
                    data_block_index = self.gcf.fragmentation_map[
                        data_block_index
                    ].next_data_block_index
            block_entry_index = block_entry.next_block_entry_index

    # ------------------------------------------------------------------
    # Basic file API
    # ------------------------------------------------------------------
    def tell(self) -> int:
        return self.position

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            new_pos = offset
        elif whence == os.SEEK_CUR:
            new_pos = self.position + offset
        elif whence == os.SEEK_END:
            new_pos = self.length + offset
        else:
            raise ValueError("Invalid whence")

        if new_pos < 0 or new_pos > self.length:
            raise ValueError("Attempting to seek outside file bounds")

        self.position = new_pos
        self._segment_index = 0
        while (
            self._segment_index < len(self._segments)
            and self.position
            >= self._segments[self._segment_index][0] + self._segments[self._segment_index][2]
        ):
            self._segment_index += 1
        return self.position

    def read(self, size: int = -1) -> bytes:
        if size < 0 or self.position + size > self.length:
            size = self.length - self.position
        if size <= 0:
            return b""

        remaining = size
        pieces: List[bytes] = []
        while remaining > 0 and self.position < self.length and self._segment_index < len(
            self._segments
        ):
            seg_offset, block_index, seg_len = self._segments[self._segment_index]
            offset_in_seg = self.position - seg_offset
            take = min(seg_len - offset_in_seg, remaining)
            file_offset = (
                self.gcf.data_block_header.first_block_offset
                + block_index * self.block_size
                + offset_in_seg
            )
            self.gcf.stream.seek(file_offset)
            pieces.append(self.gcf.stream.read(take))

            self.position += take
            remaining -= take
            if offset_in_seg + take >= seg_len:
                self._segment_index += 1

        return b"".join(pieces)


__all__ = ["GCFStream"]
