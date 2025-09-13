from py_gcf_validator.v6_validator import validate_v6
from pysteam.fs.cachefile import CacheFile


def test_v6_validator_detects_signature(tmp_path):
    cf = CacheFile.build({"a.txt": b"hello"}, app_id=1, app_version=1)
    out = tmp_path / "test.gcf"
    cf.convert_version(6, out)
    cf.close()

    parsed = CacheFile.parse(out)
    assert validate_v6(parsed) == []

    # Corrupt the checksum signature and ensure validation fails
    parsed.checksum_map.signature = b"\x00" * 128
    errors = validate_v6(parsed)
    assert any("signature mismatch" in e for e in errors)
