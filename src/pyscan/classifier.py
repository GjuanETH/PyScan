"""Clasificador supervisado (Sprint 5).

Carga el modelo entrenado por `scripts/train_model.py` (bundle joblib con el
estimador, el orden de las características y el umbral de decisión ajustado)
y produce un MLPrediction a partir de un FeatureVector.

La decisión final del veredicto la toma el MODELO (no reglas fijas), conforme
al alcance del trabajo de grado. Si el modelo no existe o las dependencias ML
no están instaladas, se lanza ModelNotAvailable y el CLI degrada con un aviso.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from . import config
from .models import FeatureVector, MLPrediction, Verdict


class ModelNotAvailable(Exception):
    """No hay modelo entrenado o faltan dependencias de ML."""


def feature_names() -> list[str]:
    """Orden canónico de las características (mismo que FeatureVector)."""
    return list(FeatureVector.model_fields.keys())


def load_bundle(path: Optional[Path] = None) -> dict:
    """Carga el bundle {model, features, threshold, ...} desde disco."""
    model_path = Path(path) if path else config.MODEL_FILE
    if not model_path.exists():
        raise ModelNotAvailable(
            f"No hay modelo entrenado en {model_path}. " "Ejecuta: python scripts/train_model.py"
        )
    try:
        import joblib
    except ImportError as exc:  # pragma: no cover
        raise ModelNotAvailable(
            "Dependencias ML no instaladas. Ejecuta: pip install -e '.[ml]'"
        ) from exc
    bundle = joblib.load(model_path)
    if not isinstance(bundle, dict) or "model" not in bundle:
        raise ModelNotAvailable(f"Formato de modelo no reconocido en {model_path}.")
    return bundle


def _positive_index(model) -> int:
    """Índice de la clase 'maliciosa' en predict_proba (clase positiva = 1)."""
    classes = list(getattr(model, "classes_", [0, 1]))
    for positive in (1, 1.0, "malicious", True):
        if positive in classes:
            return classes.index(positive)
    return len(classes) - 1


def predict(
    fv: FeatureVector, bundle: Optional[dict] = None, model_path: Optional[Path] = None
) -> MLPrediction:
    """Clasifica un FeatureVector y devuelve score, veredicto e importancias."""
    bundle = bundle if bundle is not None else load_bundle(model_path)
    model = bundle["model"]
    names = list(bundle.get("features") or feature_names())
    threshold = float(bundle.get("threshold", config.ML_DEFAULT_THRESHOLD))

    row = fv.to_row()
    X = [[float(row.get(n, 0.0)) for n in names]]

    if hasattr(model, "predict_proba"):
        score = float(model.predict_proba(X)[0][_positive_index(model)])
    else:  # estimadores sin probabilidad: la etiqueta actúa como score 0/1
        score = float(model.predict(X)[0])

    verdict = Verdict.MALICIOUS if score >= threshold else Verdict.BENIGN

    importance: dict[str, float] = {}
    if hasattr(model, "feature_importances_"):
        importance = {n: round(float(v), 4) for n, v in zip(names, model.feature_importances_)}

    return MLPrediction(score=round(score, 4), verdict=verdict, feature_importance=importance)
