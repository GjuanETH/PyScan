"""Pruebas del Fetcher: extracción segura (anti Zip Slip) y parseo de metadatos.

No requieren red. La prueba de integración contra PyPI vive en
test_integration.py y se omite automáticamente si no hay conexión.
"""

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from pyscan.fetcher import FetchError, parse_metadata, safe_extract


# --- safe_extract ---------------------------------------------------------
def _make_tar(path: Path, members: dict[str, bytes]):
    with tarfile.open(path, "w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


def test_safe_extract_normal_tar(tmp_path: Path):
    archive = tmp_path / "pkg.tar.gz"
    _make_tar(archive, {"pkg/__init__.py": b"x = 1\n", "pkg/setup.py": b"# setup\n"})
    dest = tmp_path / "out"
    safe_extract(archive, dest)
    assert (dest / "pkg" / "__init__.py").read_text() == "x = 1\n"


def test_safe_extract_blocks_path_traversal_tar(tmp_path: Path):
    archive = tmp_path / "evil.tar.gz"
    _make_tar(archive, {"../../etc/evil": b"owned"})
    with pytest.raises(FetchError, match="Zip Slip"):
        safe_extract(archive, tmp_path / "out")


def test_safe_extract_blocks_symlink_tar(tmp_path: Path):
    archive = tmp_path / "link.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        info = tarfile.TarInfo(name="evil_link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)
    with pytest.raises(FetchError, match="Enlace no permitido"):
        safe_extract(archive, tmp_path / "out")


def test_safe_extract_blocks_zip_slip_zip(tmp_path: Path):
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../../escape.txt", "owned")
    with pytest.raises(FetchError, match="Zip Slip"):
        safe_extract(archive, tmp_path / "out")


def test_safe_extract_normal_zip(tmp_path: Path):
    archive = tmp_path / "pkg.whl"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("pkg/mod.py", "y = 2\n")
    dest = tmp_path / "out"
    safe_extract(archive, dest)
    assert (dest / "pkg" / "mod.py").read_text() == "y = 2\n"


def test_safe_extract_rejects_unknown_format(tmp_path: Path):
    bad = tmp_path / "file.rar"
    bad.write_bytes(b"not an archive")
    with pytest.raises(FetchError, match="no soportado"):
        safe_extract(bad, tmp_path / "out")


def test_safe_extract_blocks_real_bytes_bomb(tmp_path: Path, monkeypatch):
    """El límite debe aplicarse sobre los bytes reales descomprimidos."""
    import pyscan.config as config
    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.bin", b"\x00" * 100_000)  # 100 KB reales
    monkeypatch.setattr(config, "MAX_EXTRACT_BYTES", 10_000)  # límite 10 KB
    with pytest.raises(FetchError, match="tamaño máximo"):
        safe_extract(archive, tmp_path / "out")


def test_safe_extract_blocks_device_file_tar(tmp_path: Path):
    archive = tmp_path / "dev.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        info = tarfile.TarInfo(name="evil_dev")
        info.type = tarfile.CHRTYPE
        tar.addfile(info)
    with pytest.raises(FetchError, match="dispositivo"):
        safe_extract(archive, tmp_path / "out")


def test_download_size_cap(tmp_path: Path, monkeypatch):
    """La descarga se aborta si el artefacto supera MAX_DOWNLOAD_BYTES."""
    import pyscan.config as config
    from pyscan.fetcher import download_archive

    monkeypatch.setattr(config, "MAX_DOWNLOAD_BYTES", 1_000)

    class FakeResponse:
        def raise_for_status(self): ...
        def iter_content(self, chunk_size):
            for _ in range(10):
                yield b"x" * 500  # 5 KB en total
        def __enter__(self): return self
        def __exit__(self, *a): return False

    class FakeSession:
        def get(self, *a, **kw): return FakeResponse()

    with pytest.raises(FetchError, match="descarga"):
        download_archive("https://x/pkg.tar.gz", tmp_path, session=FakeSession())


# --- parse_metadata -------------------------------------------------------
def test_parse_metadata_selects_sdist():
    data = {
        "info": {
            "name": "demo", "version": "1.2.3", "author": "Jane",
            "summary": "A demo", "author_email": "jane@example.com",
            "description": "long text", "requires_dist": ["requests>=2"],
            "project_urls": {"Home": "https://example.com"},
        },
        "urls": [
            {"packagetype": "bdist_wheel", "url": "https://x/demo.whl", "digests": {"sha256": "aaa"}},
            {"packagetype": "sdist", "url": "https://x/demo.tar.gz",
             "digests": {"sha256": "bbb"}, "upload_time_iso_8601": "2024-01-01T00:00:00Z"},
        ],
        "releases": {"1.2.3": [], "1.2.2": []},
    }
    package, metadata, chosen = parse_metadata(data)
    assert package.name == "demo"
    assert chosen["packagetype"] == "sdist"
    assert package.sha256 == "bbb"
    assert metadata.has_long_description is True
    assert set(metadata.releases) == {"1.2.3", "1.2.2"}
