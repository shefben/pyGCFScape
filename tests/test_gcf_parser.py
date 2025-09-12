import subprocess
import sys
from pathlib import Path

from pysteam.fs.cachefile import CacheFile


def test_gcfparser_handles_generated_files(tmp_path):
    data = {"a.txt": b"hello"}
    cf = CacheFile.build(data, app_id=1, app_version=1)
    out_v6 = tmp_path / "test_v6.gcf"
    out_v1 = tmp_path / "test_v1.gcf"
    cf.convert_version(6, out_v6)
    cf.convert_version(1, out_v1)

    validator = Path(__file__).resolve().parents[1] / "py_gcf_validator" / "gcfparser.py"
    subprocess.check_call([sys.executable, str(validator), str(out_v6)])
    subprocess.check_call([sys.executable, str(validator), str(out_v1)])
