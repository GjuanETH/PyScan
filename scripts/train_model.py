#!/usr/bin/env python3
"""Entrenamiento del clasificador supervisado (Sprint 5).

Flujo completo:
  1. Lee data/train.csv (generado por scripts/build_dataset.py).
  2. Extrae el FeatureVector de cada artefacto con los extractores del MVP
     (extracción segura; NUNCA ejecuta el código). Caché por sha256 en
     data/features_train.csv para no repetir trabajo.
  3. Validación cruzada estratificada (k=5 por defecto) con predicciones
     out-of-fold. Desbalance de clases tratado con:
       - class_weight="balanced" (Random Forest),
       - scale_pos_weight (XGBoost, si está instalado),
       - SMOTE aplicado SOLO dentro de cada fold de entrenamiento
         (si imbalanced-learn está instalado; --no-smote lo desactiva).
  4. Ajuste del umbral de decisión sobre las predicciones out-of-fold:
     se elige el que maximiza F1 sujeto a Recall >= --target-recall.
  5. Reentrena el mejor modelo con todo el conjunto de entrenamiento y guarda:
       data/models/model.joblib   (bundle: modelo + features + umbral)
       data/models/metrics.json   (métricas para la sección de Resultados)

Uso:
    python scripts/train_model.py [--k 5] [--target-recall 0.90] [--no-smote]
    python scripts/train_model.py --holdout       # evalúa también en holdout.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pyscan import config  # noqa: E402
from pyscan.classifier import feature_names  # noqa: E402
from pyscan.extractors import (ASTExtractor, EntropyExtractor,  # noqa: E402
                               MetadataExtractor)
from pyscan.features import build_features  # noqa: E402
from pyscan.fetcher import FetchError, safe_extract  # noqa: E402

FEATURES_CACHE = config.DATA_DIR / "features_train.csv"
_NAME_RE = re.compile(r"^(?P<name>.+?)-\d")


# --- 1/2: extracción de características -----------------------------------
def _package_name_from_file(path: Path) -> str:
    """'requests-2.31.0.tar.gz' -> 'requests' (heurística de nombre)."""
    stem = path.name
    for ext in (".tar.gz", ".tgz", ".whl", ".zip", ".egg", ".tar"):
        if stem.lower().endswith(ext):
            stem = stem[: -len(ext)]
            break
    m = _NAME_RE.match(stem)
    return (m.group("name") if m else stem).lower()


def _features_from_dir(name: str, root: Path,
                       meta_extractor: MetadataExtractor) -> dict[str, float]:
    typo = meta_extractor.extract(name)
    entropy = EntropyExtractor().extract(root)
    ast_rep = ASTExtractor().extract(root)
    return build_features(typosquat=typo, entropy=entropy, ast=ast_rep).to_row()


def _package_name_from_dir(path: Path) -> str:
    """Deriva el nombre del paquete desde el nombre de la carpeta de la muestra."""
    stem = path.name
    m = _NAME_RE.match(stem)
    return (m.group("name") if m else stem).lower().replace("_", "-")


def extract_row(sample: Path, kind: str,
                meta_extractor: MetadataExtractor) -> dict[str, float]:
    """Extrae el FeatureVector de una muestra local, de forma segura.

    `kind` = "archive" (se extrae en un tmp) o "dir" (código ya extraído).
    """
    name = _package_name_from_file(sample) if kind == "archive" else _package_name_from_dir(sample)
    if kind == "dir":
        return _features_from_dir(name, sample, meta_extractor)
    with tempfile.TemporaryDirectory(prefix="pyscan_feat_") as tmp:
        extracted = safe_extract(sample, Path(tmp) / "x")
        return _features_from_dir(name, extracted, meta_extractor)


def load_or_extract_features(manifest: Path, cache: Path) -> tuple[list[list[float]], list[int]]:
    """Devuelve (X, y) del manifiesto CSV, usando/actualizando la caché."""
    names = feature_names()
    cached: dict[str, dict] = {}
    if cache.exists():
        with open(cache, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                cached[row["sha256"]] = row

    with open(manifest, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        raise SystemExit(f"{manifest} está vacío. Corre antes scripts/build_dataset.py")

    meta_extractor = MetadataExtractor()
    X: list[list[float]] = []
    y: list[int] = []
    new_cache_rows: list[dict] = []
    skipped = 0
    for i, row in enumerate(rows, 1):
        sha, label = row["sha256"], row["label"]
        if sha in cached:
            feats = {n: float(cached[sha][n]) for n in names}
        else:
            sample = ROOT / row["path"]
            kind = row.get("kind", "archive")
            if not sample.exists():
                print(f"  [AVISO] no existe: {sample}", file=sys.stderr)
                skipped += 1
                continue
            try:
                feats = extract_row(sample, kind, meta_extractor)
            except (FetchError, OSError) as exc:
                print(f"  [AVISO] {sample.name}: {exc}", file=sys.stderr)
                skipped += 1
                continue
            print(f"  [{i}/{len(rows)}] {sample.name}")
        cached[sha] = {**{n: feats[n] for n in names}, "sha256": sha, "label": label}
        new_cache_rows.append(cached[sha])
        X.append([feats[n] for n in names])
        y.append(1 if label == "malicious" else 0)

    with open(cache, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["sha256", "label"] + names)
        w.writeheader()
        w.writerows(new_cache_rows)
    if skipped:
        print(f"  Omitidos {skipped} artefactos con error.", file=sys.stderr)
    return X, y


# --- 3: validación cruzada con OOF ----------------------------------------
def make_models(y, use_xgb: bool = True) -> dict:
    from sklearn.ensemble import RandomForestClassifier
    n_pos = sum(y) or 1
    n_neg = len(y) - n_pos or 1
    models = {
        "random_forest": RandomForestClassifier(
            n_estimators=300, class_weight="balanced", random_state=42, n_jobs=-1),
    }
    if use_xgb:
        try:
            from xgboost import XGBClassifier
            models["xgboost"] = XGBClassifier(
                n_estimators=300, max_depth=6, learning_rate=0.1,
                scale_pos_weight=n_neg / n_pos, eval_metric="logloss",
                random_state=42, n_jobs=-1)
        except ImportError:
            print("  xgboost no instalado: se evalúa solo Random Forest.")
    return models


def oof_probabilities(model_factory, X, y, k: int, use_smote: bool):
    """Predicciones out-of-fold: prob. de clase positiva para cada muestra."""
    import numpy as np
    from sklearn.base import clone
    from sklearn.model_selection import StratifiedKFold

    X = np.asarray(X, dtype=float)
    y = np.asarray(y, dtype=int)
    oof = np.zeros(len(y), dtype=float)
    skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=42)
    smote = None
    if use_smote:
        try:
            from imblearn.over_sampling import SMOTE
            smote = SMOTE(random_state=42)
        except ImportError:
            print("  imbalanced-learn no instalado: se entrena sin SMOTE "
                  "(class_weight/scale_pos_weight siguen activos).")
    for train_idx, val_idx in skf.split(X, y):
        X_tr, y_tr = X[train_idx], y[train_idx]
        if smote is not None:
            # SMOTE SOLO sobre el fold de entrenamiento: evita fuga de datos.
            try:
                X_tr, y_tr = smote.fit_resample(X_tr, y_tr)
            except ValueError as exc:  # p. ej. muy pocas muestras minoritarias
                print(f"  SMOTE omitido en un fold: {exc}")
        m = clone(model_factory)
        m.fit(X_tr, y_tr)
        classes = list(m.classes_)
        pos = classes.index(1) if 1 in classes else -1
        oof[val_idx] = m.predict_proba(X[val_idx])[:, pos]
    return oof


# --- 4: umbral y métricas ---------------------------------------------------
def tune_threshold(y, probs, target_recall: float) -> tuple[float, dict]:
    """Umbral que maximiza F1 sujeto a Recall >= target (si es alcanzable)."""
    from sklearn.metrics import (average_precision_score, confusion_matrix,
                                 f1_score, precision_score, recall_score)
    import numpy as np

    y = np.asarray(y)
    best = None
    for t in np.arange(0.05, 0.96, 0.01):
        pred = (probs >= t).astype(int)
        r = recall_score(y, pred, zero_division=0)
        f = f1_score(y, pred, zero_division=0)
        meets = r >= target_recall
        key = (meets, f)  # prioriza cumplir recall; luego F1
        # `>=`: ante empate en (recall, F1) se prefiere el umbral MÁS ALTO,
        # que reduce los falsos positivos sin sacrificar recall.
        if best is None or key >= best[0]:
            best = (key, float(t))
    threshold = best[1]
    pred = (probs >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    metrics = {
        "threshold": round(threshold, 2),
        "recall": round(float(recall_score(y, pred, zero_division=0)), 4),
        "precision": round(float(precision_score(y, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y, pred, zero_division=0)), 4),
        "pr_auc": round(float(average_precision_score(y, probs)), 4),
        "false_positive_rate": round(float(fp / (fp + tn)) if (fp + tn) else 0.0, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }
    return threshold, metrics


# --- 5: orquestación --------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--k", type=int, default=5, help="folds de la validación cruzada")
    ap.add_argument("--target-recall", type=float, default=0.90,
                    help="recall mínimo objetivo (KPI de la tesis)")
    ap.add_argument("--no-smote", action="store_true", help="desactiva SMOTE")
    ap.add_argument("--no-xgb", action="store_true", help="evalúa solo Random Forest")
    ap.add_argument("--holdout", action="store_true",
                    help="evalúa el modelo final también en data/holdout.csv")
    args = ap.parse_args()

    train_csv = config.DATA_DIR / "train.csv"
    if not train_csv.exists():
        print("No existe data/train.csv. Corre antes scripts/build_dataset.py")
        return 1

    print("== 1/4 Extracción de características ==")
    X, y = load_or_extract_features(train_csv, FEATURES_CACHE)
    n_pos, n_neg = sum(y), len(y) - sum(y)
    print(f"Muestras: {len(y)} (maliciosas={n_pos}, benignas={n_neg})")
    if n_pos < args.k or n_neg < args.k:
        print(f"Muy pocas muestras por clase para k={args.k}.")
        return 1

    print(f"\n== 2/4 Validación cruzada estratificada (k={args.k}) ==")
    results = {}
    for name, model in make_models(y, use_xgb=not args.no_xgb).items():
        probs = oof_probabilities(model, X, y, args.k, use_smote=not args.no_smote)
        threshold, metrics = tune_threshold(y, probs, args.target_recall)
        results[name] = {"metrics": metrics, "model": model, "threshold": threshold}
        print(f"  {name}: recall={metrics['recall']} f1={metrics['f1']} "
              f"pr_auc={metrics['pr_auc']} fp_rate={metrics['false_positive_rate']} "
              f"umbral={metrics['threshold']}")

    # Selección: cumple recall objetivo primero, luego mayor F1.
    def sort_key(item):
        m = item[1]["metrics"]
        return (m["recall"] >= args.target_recall, m["f1"])
    best_name, best = max(results.items(), key=sort_key)
    print(f"\n== 3/4 Mejor modelo: {best_name} ==")

    print("== 4/4 Reentrenando con todo el conjunto y guardando ==")
    import joblib
    import numpy as np
    X_arr, y_arr = np.asarray(X, dtype=float), np.asarray(y, dtype=int)
    if not args.no_smote:
        try:
            from imblearn.over_sampling import SMOTE
            X_arr, y_arr = SMOTE(random_state=42).fit_resample(X_arr, y_arr)
        except (ImportError, ValueError):
            pass
    final_model = best["model"]
    final_model.fit(X_arr, y_arr)

    config.MODEL_DIR.mkdir(parents=True, exist_ok=True)
    bundle = {
        "model": final_model,
        "features": feature_names(),
        "threshold": best["threshold"],
        "model_name": best_name,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "n_samples": len(y),
    }
    joblib.dump(bundle, config.MODEL_FILE)

    report = {
        "trained_at": bundle["trained_at"],
        "k_folds": args.k,
        "smote": not args.no_smote,
        "target_recall": args.target_recall,
        "n_samples": len(y), "n_malicious": n_pos, "n_benign": n_neg,
        "selected_model": best_name,
        "cv_results": {n: r["metrics"] for n, r in results.items()},
    }

    if hasattr(final_model, "feature_importances_"):
        report["feature_importance"] = {
            n: round(float(v), 4)
            for n, v in sorted(zip(feature_names(), final_model.feature_importances_),
                               key=lambda x: -x[1])}

    if args.holdout:
        holdout_csv = config.DATA_DIR / "holdout.csv"
        if holdout_csv.exists():
            print("\n== Evaluación en hold-out ==")
            Xh, yh = load_or_extract_features(holdout_csv,
                                              config.DATA_DIR / "features_holdout.csv")
            classes = list(final_model.classes_)
            pos = classes.index(1) if 1 in classes else -1
            probs_h = final_model.predict_proba(np.asarray(Xh, dtype=float))[:, pos]
            _, hm = tune_threshold(yh, probs_h, args.target_recall)
            # Métricas de holdout con el umbral YA fijado en CV (sin re-ajustar):
            from sklearn.metrics import f1_score, precision_score, recall_score
            pred_h = (probs_h >= best["threshold"]).astype(int)
            report["holdout"] = {
                "recall": round(float(recall_score(yh, pred_h, zero_division=0)), 4),
                "precision": round(float(precision_score(yh, pred_h, zero_division=0)), 4),
                "f1": round(float(f1_score(yh, pred_h, zero_division=0)), 4),
                "n_samples": len(yh),
            }
            print(f"  holdout: {report['holdout']}")
        else:
            print("No existe data/holdout.csv; se omite la evaluación final.")

    metrics_file = config.MODEL_DIR / "metrics.json"
    metrics_file.write_text(json.dumps(report, indent=2, ensure_ascii=False),
                            encoding="utf-8")
    print(f"\nModelo:   {config.MODEL_FILE}")
    print(f"Métricas: {metrics_file}")
    kpi = report["cv_results"][best_name]
    ok_r = "✅" if kpi["recall"] >= 0.90 else "❌"
    ok_f = "✅" if kpi["f1"] >= 0.85 else "❌"
    ok_fp = "✅" if kpi["false_positive_rate"] <= 0.10 else "❌"
    print(f"KPI tesis: Recall>=0.90 {ok_r} | F1>=0.85 {ok_f} | FP<=10% {ok_fp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
