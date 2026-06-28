"""Pruebas de la CLI con CliRunner, sin tocar la red (fetch monkeypatched)."""

from pathlib import Path

from typer.testing import CliRunner

import pyscan.cli as cli
from pyscan.cli import app
from pyscan.fetcher import FetchError, FetchResult
from pyscan.models import Package, PackageMetadata

runner = CliRunner()


def test_version():
    res = runner.invoke(app, ["version"])
    assert res.exit_code == 0
    assert "pyscan" in res.stdout


def test_scan_typosquat_json(monkeypatch):
    def fake_fetch(name, version=None, **kw):
        return FetchResult(
            package=Package(name="reqursts", version="1.0", sha256="abc"),
            metadata=PackageMetadata(author_email="x@y.z", maintainers=["x"]),
            extracted_path=Path("."), archive_path=Path("."),
        )
    monkeypatch.setattr(cli, "fetch", fake_fetch)
    res = runner.invoke(app, ["scan", "reqursts", "--json"])
    assert res.exit_code == 0
    assert '"is_typosquat": true' in res.stdout


def test_scan_handles_fetch_error(monkeypatch):
    def boom(name, version=None, **kw):
        raise FetchError("no existe")
    monkeypatch.setattr(cli, "fetch", boom)
    res = runner.invoke(app, ["scan", "nope"])
    assert res.exit_code == 1


def test_check_name_typosquat():
    res = runner.invoke(app, ["check-name", "reqursts"])
    assert res.exit_code == 0
    assert "SOSPECHOSO" in res.stdout or "typosquat" in res.stdout


def test_scan_with_entropy_human(monkeypatch, tmp_path):
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    (extracted / "mod.py").write_text("def f():\n    return 1\n" * 30, encoding="utf-8")

    def fake_fetch(name, version=None, **kw):
        return FetchResult(
            package=Package(name="six", version="1.17.0", sha256="abc"),
            metadata=PackageMetadata(author_email="x@y.z", maintainers=["x"]),
            extracted_path=extracted, archive_path=tmp_path,
        )
    monkeypatch.setattr(cli, "fetch", fake_fetch)
    res = runner.invoke(app, ["scan", "six"])
    assert res.exit_code == 0
    assert "entropía" in res.stdout
