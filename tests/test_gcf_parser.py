import subprocess
import sys
from pathlib import Path

from pysteam.fs.cachefile import CacheFile


def test_gcfparser_handles_generated_files(tmp_path):
    data = {
        "a.txt": b"hello",
        "big.bin": b"A" * (0x8000 * 2 + 100),
    }
    cf = CacheFile.build(data, app_id=1, app_version=1)
    out_v6 = tmp_path / "test_v6.gcf"
    out_v1 = tmp_path / "test_v1.gcf"
    cf.convert_version(6, out_v6)
    cf.convert_version(1, out_v1)

    validator = (
        Path(__file__).resolve().parents[1] / "py_gcf_validator" / "gcfparser.py"
    )
    res_v6 = subprocess.run(
        [sys.executable, str(validator), str(out_v6)], capture_output=True, text=True
    )
    assert res_v6.returncode == 0, res_v6.stdout + res_v6.stderr
    assert "crc error" not in res_v6.stdout.lower()
    assert "checksum mismatch" not in res_v6.stdout.lower()

    res_v1 = subprocess.run(
        [sys.executable, str(validator), str(out_v1)], capture_output=True, text=True
    )
    assert res_v1.returncode == 0, res_v1.stdout + res_v1.stderr
