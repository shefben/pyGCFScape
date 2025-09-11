from __future__ import annotations

import os
import io
import struct
import zipfile
import tarfile
import gzip
import shutil
import tempfile

import vpk
from pathlib import Path

from . import DirectoryFile, DirectoryFolder


class ArchivePackage:
    """Generic archive container providing a filesystem-like interface."""

    def __init__(self) -> None:
        self.root = DirectoryFolder(self)
        self.root.package = self
        self.filename: str | None = None
        self._path: str | None = None

    # ------------------------------------------------------------------
    @classmethod
    def parse(cls, path: os.PathLike[str] | str):
        self = cls()
        self.filename = os.path.basename(os.fspath(path))
        self._path = os.fspath(path)
        self._parse()
        return self

    # ------------------------------------------------------------------
    def close(self) -> None:  # pragma: no cover - consistency with CacheFile
        pass

    # ------------------------------------------------------------------
    def count_complete_files(self):
        files = self.root.all_files()
        total = len(files)
        return total, total

    # ------------------------------------------------------------------
    def _join_path(self, *args):
        return "/".join(filter(None, args))

    # ------------------------------------------------------------------
    def _extract_file(self, entry, where, keep_folder_structure=True, key=None):
        if keep_folder_structure:
            path = os.path.join(where, entry.path().lstrip("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
        else:
            path = os.path.join(where, entry.name)
        with entry.open("rb") as src, open(path, "wb") as dst:
            shutil.copyfileobj(src, dst)
        return path

    # ------------------------------------------------------------------
    def _extract_folder(self, folder, where, recursive, keep_folder_structure, filter=None, key=None):
        for entry in folder:
            if entry.is_file():
                entry.extract(where, keep_folder_structure=keep_folder_structure)
            elif recursive:
                self._extract_folder(entry, where, recursive, keep_folder_structure, filter, key)

    # ------------------------------------------------------------------
    def _add_file(self, path, size, loader):
        parts = [p for p in path.split("/") if p]
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

    # ------------------------------------------------------------------
    def _size(self, entry):
        return getattr(entry, "item_size", 0)

    # ------------------------------------------------------------------
    def add_file(self, src_path: str, dest_dir: str = "") -> None:
        name = os.path.basename(src_path)
        dest_path = self._join_path(dest_dir, name)
        self._add_file(dest_path, os.path.getsize(src_path), ("fs", src_path))

    def add_folder(self, dest_dir: str, name: str) -> None:
        path = self._join_path(dest_dir, name)
        parts = [p for p in path.split("/") if p]
        folder = self.root
        for part in parts:
            child = folder.items.get(part)
            if not child:
                child = DirectoryFolder(folder, part, self)
                child.flags = 0
                folder.items[part] = child
            folder = child

    def remove_file(self, path: str) -> None:
        parts = [p for p in path.split("/") if p]
        folder = self.root
        for part in parts[:-1]:
            folder = folder.items.get(part)
            if folder is None:
                return
        folder.items.pop(parts[-1], None)

    def move_file(self, old_path: str, new_path: str) -> None:
        parts = [p for p in old_path.split("/") if p]
        folder = self.root
        for part in parts[:-1]:
            folder = folder.items.get(part)
            if folder is None:
                return
        entry = folder.items.pop(parts[-1], None)
        if not entry:
            return
        dest_parts = [p for p in new_path.split("/") if p]
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


class PakFile(ArchivePackage):
    """Quake/Half-Life PAK archive."""

    def _parse(self) -> None:
        with open(self._path, "rb") as f:
            magic, dir_offset, dir_size = struct.unpack("<4sII", f.read(12))
            if magic != b"PACK":
                raise ValueError("Not a PAK file")
            f.seek(dir_offset)
            count = dir_size // 64
            for _ in range(count):
                data = f.read(64)
                name = data[:56].split(b"\0", 1)[0].decode("latin1")
                offset, size = struct.unpack("<II", data[56:])
                self._add_file(name, size, (offset, size))

    def _open_file(self, entry, mode="rb", key=None):
        offset, size = entry._loader
        with open(self._path, "rb") as f:
            f.seek(offset)
            data = f.read(size)
        return io.BytesIO(data)


class WadFile(ArchivePackage):
    """WAD2/3 texture archive."""

    def _parse(self) -> None:
        with open(self._path, "rb") as f:
            ident, num_lumps, info_offset = struct.unpack("<4sII", f.read(12))
            if ident not in (b"WAD2", b"WAD3", b"IWAD", b"PWAD"):
                raise ValueError("Not a WAD file")
            f.seek(info_offset)
            for _ in range(num_lumps):
                lump = f.read(32)
                offset, disk_size, size, _type, _comp, _pad, name = struct.unpack(
                    "<IIIbbH16s", lump
                )
                name = name.split(b"\0", 1)[0].decode("latin1")
                self._add_file(name, size, (offset, size))

    def _open_file(self, entry, mode="rb", key=None):
        offset, size = entry._loader
        with open(self._path, "rb") as f:
            f.seek(offset)
            data = f.read(size)
        return io.BytesIO(data)


class ZipArchive(ArchivePackage):
    """ZIP archive using :mod:`zipfile`."""

    def _parse(self) -> None:
        self.zip = zipfile.ZipFile(self._path, "r")
        for info in self.zip.infolist():
            if info.is_dir():
                self._add_file(info.filename.rstrip("/"), 0, None)
            else:
                self._add_file(info.filename, info.file_size, info)

    def close(self) -> None:
        self.zip.close()

    def _open_file(self, entry, mode="rb", key=None):
        return self.zip.open(entry._loader, "r")


class TarArchive(ArchivePackage):
    """TAR (optionally compressed) archive."""

    def _parse(self) -> None:
        self.tar = tarfile.open(self._path, "r")
        for member in self.tar.getmembers():
            if member.isdir():
                self._add_file(member.name.rstrip("/"), 0, None)
            elif member.isfile():
                self._add_file(member.name, member.size, member)

    def close(self) -> None:
        self.tar.close()

    def _open_file(self, entry, mode="rb", key=None):
        fileobj = self.tar.extractfile(entry._loader)
        if fileobj is None:
            return io.BytesIO(b"")
        return fileobj


class GzipArchive(ArchivePackage):
    """GZIP single-file archive."""

    def _parse(self) -> None:
        name = Path(self._path).stem
        with open(self._path, "rb") as f:
            f.seek(-4, os.SEEK_END)
            size = struct.unpack("<I", f.read(4))[0]
        self._add_file(name, size, None)

    def _open_file(self, entry, mode="rb", key=None):
        return gzip.open(self._path, "rb")


class SevenZipArchive(ArchivePackage):
    """7z archive using :mod:`py7zr`."""

    def _parse(self) -> None:
        try:
            import py7zr
        except ModuleNotFoundError as exc:  # pragma: no cover
            raise ModuleNotFoundError("py7zr is required for 7z support") from exc
        self.seven = py7zr.SevenZipFile(self._path, "r")
        for info in self.seven.list():
            if info.is_directory:
                continue
            self._add_file(info.filename, info.uncompressed, info.filename)

    def close(self) -> None:
        self.seven.close()

    def _open_file(self, entry, mode="rb", key=None):
        data = self.seven.read([entry._loader])[entry._loader].read()
        return io.BytesIO(data)


class RarArchive(ArchivePackage):
    """RAR archive using :mod:`rarfile`."""

    def _parse(self) -> None:
        try:
            import rarfile
        except ModuleNotFoundError as exc:  # pragma: no cover
            raise ModuleNotFoundError("rarfile is required for RAR support") from exc
        self.rar = rarfile.RarFile(self._path, "r")
        for info in self.rar.infolist():
            if info.is_dir():
                continue
            self._add_file(info.filename, info.file_size, info)

    def close(self) -> None:
        self.rar.close()

    def _open_file(self, entry, mode="rb", key=None):
        return self.rar.open(entry._loader)


class VpkArchive(ArchivePackage):
    """Valve VPK package using :mod:`vpk`."""
    def __init__(self) -> None:
        super().__init__()
        self.vpk = None

    def _parse(self) -> None:
        self.vpk = vpk.VPK(self._path, read_header_only=False)
        for path in self.vpk:
            file = self.vpk.get_file(path)
            self._add_file(path.replace("\\", "/"), file.length, path)

    def _open_file(self, entry, mode="rb", key=None):
        loader = getattr(entry, "_loader", None)
        if isinstance(loader, tuple) and loader[0] == "fs":
            return open(loader[1], mode)
        vfile = self.vpk.get_file(loader)
        return io.BytesIO(vfile.read())

    def save(self, output_path: str | None = None) -> None:
        if output_path is None:
            output_path = self._path
        temp_dir = tempfile.mkdtemp()
        try:
            for entry in self.root.all_files():
                dest = os.path.join(temp_dir, entry.path().lstrip("/"))
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                loader = getattr(entry, "_loader", None)
                if isinstance(loader, tuple) and loader and loader[0] == "fs":
                    shutil.copyfile(loader[1], dest)
                else:
                    vfile = self.vpk.get_file(loader)
                    with open(dest, "wb") as f:
                        f.write(vfile.read())
            newvpk = vpk.new(temp_dir)
            newvpk.save(output_path)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class XzpArchive(ArchivePackage):
    """Placeholder for Half-Life 2 Xbox XZP archives."""

    def _parse(self) -> None:  # pragma: no cover - future work
        raise NotImplementedError("XZP archives are not yet supported")


EXTENSION_MAP = {
    ".pak": PakFile,
    ".wad": WadFile,
    ".zip": ZipArchive,
    ".tar": TarArchive,
    ".gz": GzipArchive,
    ".tgz": TarArchive,
    ".tar.gz": TarArchive,
    ".7z": SevenZipArchive,
    ".rar": RarArchive,
    ".xzp": XzpArchive,
    ".vpk": VpkArchive,
}


def open_archive(path: Path):
    full_ext = "".join(path.suffixes).lower()
    cls = EXTENSION_MAP.get(full_ext)
    if cls is None:
        cls = EXTENSION_MAP.get(path.suffix.lower())
    if not cls:
        raise ValueError(f"Unsupported archive format: {path.suffix}")
    return cls.parse(path)
