import subprocess
import sys
from pathlib import Path

from pysteam.fs.cachefile import CacheFile


def test_convert_v1_to_v6_has_required_tables(tmp_path):
    data = {
        "a.txt": b"hello world",
        "b.txt": b"B" * (0x4000 + 123),
    }
    # Build latest version then write as v1 and parse again
    cf = CacheFile.build(data, app_id=1, app_version=1)
    v1_path = tmp_path / "test_v1.gcf"
    cf.convert_version(1, v1_path)

    cf_v1 = CacheFile.parse(v1_path)
    v6_path = tmp_path / "roundtrip_v6.gcf"
    cf_v1.convert_version(6, v6_path)

    # Parsed v6 should expose all modern tables
    rebuilt = CacheFile.parse(v6_path)
    assert rebuilt.block_entry_map is not None
    assert rebuilt.checksum_map is not None
    assert rebuilt.alloc_table.is_long_terminator == 1

    # Validate structure using reference validator
    validator = (
        Path(__file__).resolve().parents[1] / "py_gcf_validator" / "gcfparser.py"
    )
    res = subprocess.run(
        [sys.executable, str(validator), str(v6_path)], capture_output=True, text=True
    )
    assert res.returncode == 0, res.stdout + res.stderr
    assert "crc error" not in res.stdout.lower()
    assert "checksum mismatch" not in res.stdout.lower()
