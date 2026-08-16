"""Pruebas de la CLI con CliRunner, sin tocar la red (fetch monkeypatched)."""

from pathlib import Path

from typer.testing import CliRunner

import pyscan.cli as cli
from pyscan.cli import app
from pyscan.fetcher import FetchError, FetchResult
from pyscan.models import Package, PackageMetadata

runner = CliRunner()


def _fake_result(extracted: Path) -> FetchResult:
    return FetchResult(
        package=Package(name="reqursts", version="1.0", sha256="abc"),
        metadata=PackageMetadata(author_email="x@y.z", maintainers=["x"]),
        extracted_path=extracted, archive_path=extracted,
    )


def test_version():
    res = runner.invoke(app, ["version"])
    assert res.exit_code == 0
    assert "pyscan" in res.stdout


def test_check_name_typosquat():
    res = runner.invoke(app, ["check-name", "reqursts"])
    assert res.exit_code == 0
    assert "SOSPECHOSO" in res.stdout or "typosquat" in res.stdout


def test_scan_typosquat_json(monkeypatch, tmp_path):
    (tmp_path / "mod.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(cli, "fetch", lambda *a, **k: _fake_result(tmp_path))
    res = runner.invoke(app, ["scan", "reqursts", "--json"])
    assert res.exit_code == 0
    assert '"is_typosquat": true' in res.stdout


def test_scan_with_entropy_and_ast_human(monkeypatch, tmp_path):
    (tmp_path / "mod.py").write_text(
        "import os\nos.system('x')\n" + "def f():\n    return 1\n" * 20,
        encoding="utf-8")
    monkeypatch.setattr(cli, "fetch", lambda *a, **k: _fake_result(tmp_path))
    res = runner.invoke(app, ["scan", "reqursts"])
    assert res.exit_code == 0
    assert "entropía" in res.stdout
    assert "AST" in res.stdout


def test_scan_handles_fetch_error(monkeypatch):
    def boom(*a, **k):
        raise FetchError("no existe")
    monkeypatch.setattr(cli, "fetch", boom)
    res = runner.invoke(app, ["scan", "nope"])
    assert res.exit_code == 1


def test_scan_without_model_shows_note(monkeypatch, tmp_path):
    """Sin modelo entrenado el scan degrada con aviso y exit code 0."""
    (tmp_path / "mod.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(cli, "fetch", lambda *a, **k: _fake_result(tmp_path))
    res = runner.invoke(app, ["scan", "reqursts",
                              "--model", str(tmp_path / "no_existe.joblib")])
    assert res.exit_code == 0
    assert "sin veredicto" in res.stdout


def test_scan_with_model_and_sarif(monkeypatch, tmp_path):
    """Con modelo entrenado: veredicto ML, SARIF escrito y exit code 2."""
    import pytest as _pytest
    _pytest.importorskip("sklearn")
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    from pyscan.classifier import feature_names
    from pyscan.models import FeatureVector

    names = feature_names()
    mal = FeatureVector(name_min_distance=1.0, is_typosquat=1.0,
                        ast_dangerous_calls=3.0).to_row()
    ben = FeatureVector(name_min_distance=99.0, release_count=40.0).to_row()
    Xs = [[mal[n] for n in names]] * 10 + [[ben[n] for n in names]] * 10
    ys = [1] * 10 + [0] * 10
    model = RandomForestClassifier(n_estimators=10, random_state=0).fit(Xs, ys)
    model_file = tmp_path / "model.joblib"
    joblib.dump({"model": model, "features": names, "threshold": 0.5}, model_file)

    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "mod.py").write_text(
        "import os, base64\nexec(base64.b64decode('eA=='))\nos.system('curl http://x.io')\n"
        * 30, encoding="utf-8")
    monkeypatch.setattr(cli, "fetch", lambda *a, **k: _fake_result(pkg))

    sarif_file = tmp_path / "out.sarif"
    res = runner.invoke(app, ["scan", "reqursts",
                              "--model", str(model_file),
                              "--sarif", str(sarif_file)])
    assert res.exit_code == 2  # veredicto MALICIOSO
    assert "MALICIOSO" in res.stdout
    assert sarif_file.exists()
    import json
    doc = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert any(r["ruleId"] == "PS100" for r in doc["runs"][0]["results"])
