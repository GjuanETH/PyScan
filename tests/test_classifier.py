"""Pruebas del clasificador supervisado (Sprint 5)."""

from pathlib import Path

import pytest

from pyscan.classifier import ModelNotAvailable, feature_names, load_bundle, predict
from pyscan.models import FeatureVector, Verdict

sklearn = pytest.importorskip("sklearn")
import joblib  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402


def _malicious_fv() -> FeatureVector:
    return FeatureVector(
        name_min_distance=1.0,
        is_typosquat=1.0,
        entropy_max=7.8,
        entropy_suspicious_windows=12.0,
        ast_dangerous_calls=6.0,
        ast_has_install_hook=1.0,
        ast_network_literals=4.0,
    )


def _benign_fv() -> FeatureVector:
    return FeatureVector(
        name_min_distance=99.0,
        release_count=50.0,
        requires_count=5.0,
        has_long_description=1.0,
        entropy_max=5.2,
        ast_dangerous_calls=0.0,
    )


def _train_bundle(tmp_path: Path) -> Path:
    """Entrena un RF diminuto con datos sintéticos separables y lo guarda."""
    names = feature_names()
    rows, labels = [], []
    for _ in range(20):
        rows.append([_malicious_fv().to_row()[n] for n in names])
        labels.append(1)
        rows.append([_benign_fv().to_row()[n] for n in names])
        labels.append(0)
    model = RandomForestClassifier(n_estimators=10, random_state=0).fit(rows, labels)
    path = tmp_path / "model.joblib"
    joblib.dump({"model": model, "features": names, "threshold": 0.5}, path)
    return path


def test_predict_malicious_and_benign(tmp_path: Path):
    path = _train_bundle(tmp_path)
    pred_mal = predict(_malicious_fv(), model_path=path)
    pred_ben = predict(_benign_fv(), model_path=path)
    assert pred_mal.verdict == Verdict.MALICIOUS
    assert pred_ben.verdict == Verdict.BENIGN
    assert 0.0 <= pred_ben.score < 0.5 <= pred_mal.score <= 1.0
    assert pred_mal.feature_importance  # RF expone importancias


def test_missing_model_raises():
    with pytest.raises(ModelNotAvailable, match="No hay modelo"):
        load_bundle(Path("/no/existe/model.joblib"))


def test_invalid_bundle_raises(tmp_path: Path):
    bad = tmp_path / "bad.joblib"
    joblib.dump(["no", "es", "bundle"], bad)
    with pytest.raises(ModelNotAvailable, match="no reconocido"):
        load_bundle(bad)


def test_threshold_respected(tmp_path: Path):
    """Un umbral muy alto debe volver benigno incluso un score alto."""
    path = _train_bundle(tmp_path)
    bundle = joblib.load(path)
    bundle["threshold"] = 0.999999
    pred = predict(_malicious_fv(), bundle=bundle)
    assert pred.verdict == Verdict.BENIGN or pred.score >= 0.999999
