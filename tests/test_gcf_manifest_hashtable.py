import sys
from pathlib import Path
from io import BytesIO
from pysteam.fs.cachefile import CacheFile


def test_manifest_hashtable(tmp_path):
    data = {"a.txt": b"hello"}
    cf = CacheFile.build(data, app_id=1, app_version=1)
    out = tmp_path / "test.gcf"
    cf.convert_version(6, out)
    rebuilt = CacheFile.parse(out)
    sys.path.append(str(Path(__file__).resolve().parents[1] / "py_gcf_validator"))
    from manifest import Manifest

    Manifest(BytesIO(rebuilt.manifest.serialize()), adjust_size=True)
