import zlib

from pysteam.fs.cachefile import CacheFile


def test_manifest_checksum(tmp_path):
    data = {"a.txt": b"hello"}
    cf = CacheFile.build(data, app_id=1, app_version=1)
    out = tmp_path / "test.gcf"
    cf.convert_version(6, out)
    rebuilt = CacheFile.parse(out)
    manifest = rebuilt.manifest.serialize()
    body_end = rebuilt.manifest.binary_size
    calc = (
        zlib.adler32(manifest[:0x30] + b"\x00" * 8 + manifest[0x38:body_end], 0)
        & 0xFFFFFFFF
    )
    assert calc == rebuilt.manifest.checksum

