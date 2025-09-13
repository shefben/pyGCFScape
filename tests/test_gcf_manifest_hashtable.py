import sys
from pathlib import Path
from io import BytesIO
from pysteam.fs.cachefile import CacheFile


def test_manifest_hashtable(tmp_path):
    data = {"a.txt": b"hello"}
    cf = CacheFile.build(data, app_id=1, app_version=1)
    sys.path.append(str(Path(__file__).resolve().parents[1] / "py_gcf_validator"))
    from manifest import Manifest

    out_v6 = tmp_path / "test_v6.gcf"
    cf.convert_version(6, out_v6)
    rebuilt_v6 = CacheFile.parse(out_v6)
    Manifest(BytesIO(rebuilt_v6.manifest.serialize()), adjust_size=True)

    out_v1 = tmp_path / "test_v1.gcf"
    cf.convert_version(1, out_v1)
    rebuilt_v1 = CacheFile.parse(out_v1)
    Manifest(BytesIO(rebuilt_v1.manifest.serialize()), adjust_size=True)
