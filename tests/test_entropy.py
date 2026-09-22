"""Pruebas del extractor de entropía de Shannon."""

import os
from pathlib import Path

from pyscan.extractors.entropy import EntropyExtractor, iter_windows, shannon_entropy


def test_entropy_uniform_is_zero():
    assert shannon_entropy(b"A" * 256) == 0.0


def test_entropy_empty_is_zero():
    assert shannon_entropy(b"") == 0.0


def test_entropy_random_is_high():
    h = shannon_entropy(os.urandom(8192))
    assert h > 7.5


def test_entropy_code_is_moderate():
    h = shannon_entropy(b"def foo():\n    return 42\n" * 20)
    assert 2.0 < h < 6.0


def test_iter_windows_blocks():
    blocks = list(iter_windows(b"x" * 600, 256))
    assert [len(b) for b in blocks] == [256, 256, 88]


def test_extractor_flags_suspicious_window(tmp_path: Path):
    # Archivo con un bloque de alta entropía (datos aleatorios) embebido.
    f = tmp_path / "evil.py"
    f.write_bytes(b"# normal code header\n" + os.urandom(512))
    rep = EntropyExtractor().extract(tmp_path)
    assert rep.max > 7.0
    assert rep.suspicious_windows >= 1


def test_extractor_clean_code_no_suspicious(tmp_path: Path):
    f = tmp_path / "clean.py"
    f.write_text("def add(a, b):\n    return a + b\n" * 50, encoding="utf-8")
    rep = EntropyExtractor().extract(tmp_path)
    assert rep.suspicious_windows == 0
    assert rep.max < 7.0


def test_extractor_empty_dir_returns_zero_report(tmp_path: Path):
    rep = EntropyExtractor().extract(tmp_path)
    assert rep.max == 0.0 and rep.suspicious_windows == 0
