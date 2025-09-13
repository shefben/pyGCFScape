import subprocess
import sys
from pathlib import Path

from pysteam.fs.cachefile import CacheFile


def test_validate_gcf(tmp_path):
    gcf = CacheFile.build({"a.txt": b"hello"}, app_id=1)
    out = tmp_path / "test.gcf"
    gcf.convert_version(6, str(out))
    gcf.close()

    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parents[1] / "validate_gcf.py"), str(out)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Validation succeeded" in result.stdout
