"""Identidad de muestra (nombre, versión) usada en entrenamiento y auditoría."""

import multiprocessing
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import train_model as tm  # noqa: E402

DD = "data/malicious/datadog"
MR = "data/malicious/malregistry"


@pytest.mark.parametrize(
    "path, expected",
    [
        # Datadog: la muestra puede ser un subdirectorio de importación.
        (
            f"{DD}/2025-04-23-s3transfer-sl-v0.12.4/tmp/t/s3transfer-sl/s3transfer",
            ("s3transfer-sl", "0.12.4"),
        ),
        (
            f"{DD}/2025-12-28-aiogram-types-v3-v3.9.7/tmp/t/sources/aiogram-types-v3/docs",
            ("aiogram-types-v3", "3.9.7"),
        ),
        (f"{DD}/2022-11-07-python-dateuti-0.1/x/python-dateuti-0.1", ("python-dateuti", "0.1")),
        (f"{DD}/2023-01-08-reqsystem", ("reqsystem", "")),
        # Malregistry: <nombre>/<versión>/<archivo>.
        (f"{MR}/requests-2022/3.22.6/requests-2022-3.22.6.tar.gz", ("requests-2022", "3.22.6")),
        (
            f"{MR}/artifact-lab-3-package-4c04b1a2/1.0.4/a.tar.gz",
            ("artifact-lab-3-package-4c04b1a2", "1.0.4"),
        ),
        # Benignos: nombre del archivo normalizado.
        ("data/benign/aio-pika-10.0.1/aio_pika-10.0.1.tar.gz", ("aio-pika", "10.0.1")),
        ("data/benign/pypi_random/mscz-0.0.1/mscz-0.0.1-py3.8.egg", ("mscz", "0.0.1")),
    ],
)
def test_sample_identity(path, expected):
    assert tm.sample_identity(path) == expected


needs_fork = pytest.mark.skipif(
    "fork" not in multiprocessing.get_all_start_methods(), reason="requiere fork (Linux)"
)


@needs_fork
def test_extract_isolated_returns_features(tmp_path):
    pkg = tmp_path / "demo-1.0"
    pkg.mkdir()
    (pkg / "setup.py").write_text("from setuptools import setup\nsetup(name='demo')\n")
    feats = tm.extract_isolated(pkg, "dir", tm.MetadataExtractor(["requests"]), 1024, 60)
    assert set(tm.feature_names()) <= set(feats)


@needs_fork
def test_extract_isolated_contains_memory_blowup(tmp_path, monkeypatch):
    def greedy(*_a, **_k):
        return bytearray(4 * 1024**3)  # 4 GB, por encima del límite de 256 MB

    monkeypatch.setattr(tm, "extract_row", greedy)
    with pytest.raises(RuntimeError, match="MemoryError"):
        tm.extract_isolated(tmp_path, "dir", None, 256, 60)
    assert tm.classify_exclusion("RuntimeError: MemoryError: x") == "excede límites de recursos"


@needs_fork
def test_extract_isolated_survives_dead_child(tmp_path, monkeypatch):
    monkeypatch.setattr(tm, "extract_row", lambda *_a, **_k: os._exit(9))
    with pytest.raises(RuntimeError):
        tm.extract_isolated(tmp_path, "dir", None, 256, 60)
