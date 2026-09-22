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
        extracted_path=extracted,
        archive_path=extracted,
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
        "import os\nos.system('x')\n" + "def f():\n    return 1\n" * 20, encoding="utf-8"
    )
    monkeypatch.setattr(cli, "fetch", lambda *a, **k: _fake_result(tmp_path))
    # --model inexistente: aísla la prueba de cualquier modelo entrenado en disco;
    # aquí se valida la SALIDA del análisis (entropía/AST), no el veredicto.
    res = runner.invoke(app, ["scan", "reqursts", "--model", str(tmp_path / "no_existe.joblib")])
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
    res = runner.invoke(app, ["scan", "reqursts", "--model", str(tmp_path / "no_existe.joblib")])
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
    mal = FeatureVector(name_min_distance=1.0, is_typosquat=1.0, ast_dangerous_calls=3.0).to_row()
    ben = FeatureVector(name_min_distance=99.0, release_count=40.0).to_row()
    Xs = [[mal[n] for n in names]] * 10 + [[ben[n] for n in names]] * 10
    ys = [1] * 10 + [0] * 10
    model = RandomForestClassifier(n_estimators=10, random_state=0).fit(Xs, ys)
    model_file = tmp_path / "model.joblib"
    joblib.dump({"model": model, "features": names, "threshold": 0.5}, model_file)

    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "mod.py").write_text(
        "import os, base64\nexec(base64.b64decode('eA=='))\nos.system('curl http://x.io')\n" * 30,
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "fetch", lambda *a, **k: _fake_result(pkg))

    sarif_file = tmp_path / "out.sarif"
    res = runner.invoke(
        app, ["scan", "reqursts", "--model", str(model_file), "--sarif", str(sarif_file)]
    )
    assert res.exit_code == 2  # veredicto MALICIOSO
    assert "MALICIOSO" in res.stdout
    assert sarif_file.exists()
    import json

    doc = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert any(r["ruleId"] == "PS100" for r in doc["runs"][0]["results"])


# --- Modos de escaneo múltiple / requirements / local -------------------
def test_parse_requirements(tmp_path):
    from pyscan.cli import _parse_requirements

    req = tmp_path / "requirements.txt"
    req.write_text(
        "# comentario\n"
        "requests==2.31.0\n"
        "flask>=2,<3\n"
        "numpy\n"
        "django[argon2]==4.2  # inline\n"
        "-e .\n"
        "pywin32 ; sys_platform == 'win32'\n"
        "\n",
        encoding="utf-8",
    )
    names = _parse_requirements(req)
    assert names == ["requests", "flask", "numpy", "django", "pywin32"]


def test_scan_multiple_with_summary(monkeypatch, tmp_path):
    (tmp_path / "mod.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(cli, "fetch", lambda *a, **k: _fake_result(tmp_path))
    res = runner.invoke(app, ["scan", "reqursts", "djnago"])
    assert res.exit_code == 0
    assert "RESUMEN: 2 analizados" in res.stdout


def test_scan_requirements_file(monkeypatch, tmp_path):
    (tmp_path / "mod.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(cli, "fetch", lambda *a, **k: _fake_result(tmp_path))
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\nflask\n", encoding="utf-8")
    res = runner.invoke(app, ["scan", "-r", str(req)])
    assert res.exit_code == 0
    assert "RESUMEN: 2 analizados" in res.stdout


def test_scan_local_directory(tmp_path):
    pkg = tmp_path / "reqursts-1.0"
    pkg.mkdir()
    (pkg / "mod.py").write_text("import os\nos.system('x')\n", encoding="utf-8")
    # --model inexistente: la prueba valida el análisis local, no el veredicto ML,
    # y así no depende de si hay un modelo entrenado en data/models/.
    res = runner.invoke(
        app, ["scan", "--local", str(pkg), "--model", str(tmp_path / "no_existe.joblib")]
    )
    assert res.exit_code == 0
    assert "reqursts" in res.stdout
    assert "os.system" in res.stdout


def test_scan_no_target_errors():
    res = runner.invoke(app, ["scan"])
    assert res.exit_code == 2


def test_scan_suggests_legit_package(monkeypatch, tmp_path):
    """Ante un typosquat, sugiere el paquete legítimo más parecido."""
    (tmp_path / "mod.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(cli, "fetch", lambda *a, **k: _fake_result(tmp_path))
    res = runner.invoke(app, ["scan", "reqursts"])
    assert res.exit_code == 0
    assert "requests" in res.stdout  # sugerencia de alternativa segura


def test_precommit_blocks_typosquat(monkeypatch, tmp_path):
    """El hook de pre-commit bloquea (exit != 0) ante un nombre sospechoso."""

    def boom(*a, **k):
        raise FetchError("no existe")

    monkeypatch.setattr(cli, "fetch", boom)
    req = tmp_path / "requirements.txt"
    req.write_text("reqursts\n", encoding="utf-8")
    res = runner.invoke(app, ["precommit", str(req)])
    assert res.exit_code == 1


def test_precommit_clean_passes(monkeypatch, tmp_path):
    """Dependencia analizada con veredicto benigno: el hook no bloquea."""
    from pyscan.models import MLPrediction, Verdict

    (tmp_path / "mod.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    monkeypatch.setattr(
        cli,
        "fetch",
        lambda *a, **k: FetchResult(
            package=Package(name="flask", version="3.0", sha256="abc"),
            metadata=PackageMetadata(),
            extracted_path=tmp_path,
            archive_path=tmp_path,
        ),
    )
    monkeypatch.setattr(
        cli, "predict", lambda *a, **k: MLPrediction(score=0.1, verdict=Verdict.BENIGN)
    )
    req = tmp_path / "requirements.txt"
    req.write_text("flask\n", encoding="utf-8")
    res = runner.invoke(app, ["precommit", str(req)])
    assert res.exit_code == 0


def test_precommit_blocks_unscanned(monkeypatch, tmp_path):
    """Si una dependencia no se pudo analizar, el hook falla en seguro (bloquea)."""

    def boom(*a, **k):
        raise FetchError("offline")

    monkeypatch.setattr(cli, "fetch", boom)
    req = tmp_path / "requirements.txt"
    req.write_text("flask\n", encoding="utf-8")
    res = runner.invoke(app, ["precommit", str(req)])
    assert res.exit_code == 1
    assert "NO se pudieron" in res.output


def test_precommit_allow_unscanned(monkeypatch, tmp_path):
    """Con --allow-unscanned, lo no analizado se avisa pero no bloquea."""

    def boom(*a, **k):
        raise FetchError("offline")

    monkeypatch.setattr(cli, "fetch", boom)
    req = tmp_path / "requirements.txt"
    req.write_text("flask\n", encoding="utf-8")
    res = runner.invoke(app, ["precommit", "--allow-unscanned", str(req)])
    assert res.exit_code == 0
    assert "NO se pudieron" in res.output


def test_scan_parallel_preserves_order(monkeypatch, tmp_path):
    """Con varios paquetes y --workers > 1 el reporte conserva el orden de entrada."""
    import json
    import threading
    import time

    seen_threads = set()

    def fake_fetch(name, *a, **k):
        seen_threads.add(threading.get_ident())
        time.sleep(0.05 if name == "alpha" else 0.0)  # el primero termina de último
        return FetchResult(
            package=Package(name=name, version="1.0", sha256="abc"),
            metadata=PackageMetadata(),
            extracted_path=tmp_path,
            archive_path=tmp_path,
        )

    monkeypatch.setattr(cli, "fetch", fake_fetch)
    res = runner.invoke(app, ["scan", "alpha", "beta", "gamma", "--json", "--workers", "3"])
    data = json.loads(res.output)
    assert [r["package"]["name"] for r in data] == ["alpha", "beta", "gamma"]
    assert len(seen_threads) > 1


def test_scan_many_sequential_equals_parallel(monkeypatch, tmp_path):
    """El resultado por paquete es el mismo en modo secuencial y paralelo."""
    (tmp_path / "mod.py").write_text("import os\nos.system('x')\n", encoding="utf-8")
    monkeypatch.setattr(
        cli,
        "fetch",
        lambda name, *a, **k: FetchResult(
            package=Package(name=name, version="1.0", sha256="abc"),
            metadata=PackageMetadata(),
            extracted_path=tmp_path,
            archive_path=tmp_path,
        ),
    )
    names = ["reqursts", "flask", "numpy"]
    seq = cli._scan_many(names, None, None, workers=1)
    par = cli._scan_many(names, None, None, workers=3)
    assert [r.features for r, _ in seq] == [r.features for r, _ in par]
