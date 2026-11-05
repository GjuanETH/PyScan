#!/usr/bin/env python3
"""Entrenamiento del clasificador supervisado con protocolo congelado.

Flujo (todos los parámetros salen de config.yaml):
  1. Lee los manifiestos de entrenamiento y hold-out (config.yaml -> manifests).
  2. Extrae el FeatureVector de cada artefacto con los extractores del MVP
     (extracción segura; NUNCA ejecuta el código). Caché única por sha256 en
     data/features_all.csv. Con --refresh-features se reextrae todo con el
     extractor actual y se cuenta qué muestras cambiaron (corrección 1.2).
     Cada muestra excluida queda en data/analysis/exclusiones.csv con su motivo.
  3. Validación cruzada estratificada (agrupada con StratifiedGroupKFold si el
     manifiesto trae group_id) con predicciones out-of-fold. Desbalance:
     class_weight / scale_pos_weight + SMOTENC (o SMOTE) SOLO dentro de cada
     partición de entrenamiento.
  4. Umbral: F1 máximo sujeto a Recall >= target, elegido SOLO con las
     predicciones out-of-fold.
  5. Reentrena el mejor modelo con todo el entrenamiento, lo guarda con su
     sha256 y evalúa UNA vez en el hold-out con el umbral ya fijado.

Salidas:
  data/models/model.joblib (+ .sha256)    data/models/metrics.json
  data/analysis/pred_oof.csv              data/analysis/pred_holdout.csv
  data/analysis/exclusiones.csv           data/analysis/feature_refresh.json (si --refresh-features)

Uso:
    python scripts/train_model.py                      # protocolo de config.yaml
    python scripts/train_model.py --refresh-features   # reextrae con el extractor actual
    python scripts/train_model.py --sampler smote --tag comparacion_smote   # variante, no pisa el modelo
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pyscan import config  # noqa: E402
from pyscan.classifier import feature_names  # noqa: E402
from pyscan.extractors import (  # noqa: E402
    ASTExtractor,
    EntropyExtractor,
    MetadataExtractor,
    name_from_filename,
    normalize_name,
)
from pyscan.features import build_features  # noqa: E402
from pyscan.fetcher import safe_extract  # noqa: E402

CONFIG_FILE = ROOT / "config.yaml"
ANALYSIS_DIR = config.DATA_DIR / "analysis"
_DATADOG_TOP = re.compile(r"^\d{4}-\d{2}-\d{2}-(?P<rest>.+)$")
_DATADOG_VER = re.compile(r"^(?P<name>.+)-v(?P<ver>\d[^/]*)$")


# --- Configuración y trazabilidad ------------------------------------------
def load_config(path: Path = CONFIG_FILE) -> dict:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("Falta PyYAML: pip install -e '.[ml]'") from exc
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


CFG = load_config() if CONFIG_FILE.exists() else {}
FEATURES_CACHE = ROOT / CFG.get("features_cache", "data/features_all.csv")


def manifest_path(split: str) -> Path:
    """Ruta del manifiesto 'train' u 'holdout' según config.yaml."""
    default = {"train": "data/train.csv", "holdout": "data/holdout.csv"}[split]
    return ROOT / CFG.get("manifests", {}).get(split, default)


def git_commit() -> str:
    try:
        sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                             text=True, timeout=10).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"],
                               cwd=ROOT, capture_output=True, text=True,
                               timeout=10).stdout.strip()
        return (sha or "desconocido") + ("-modificado" if dirty else "")
    except (OSError, subprocess.SubprocessError):
        return "desconocido"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def lib_versions() -> dict:
    out = {"python": platform.python_version(), "platform": platform.platform()}
    for mod in ("sklearn", "imblearn", "xgboost", "numpy", "pandas", "joblib", "rapidfuzz"):
        try:
            out[mod] = __import__(mod).__version__
        except Exception:  # noqa: BLE001
            out[mod] = None
    return out


def tool_version(cmd: list[str]) -> str | None:
    """Primera línea de `<herramienta> --version` (para registrar la versión usada)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        out = (r.stdout or r.stderr).strip().splitlines()
        return out[0] if out else None
    except (OSError, subprocess.SubprocessError):
        return None


def run_info(extra: dict | None = None) -> dict:
    """Metadatos de ejecución de un experimento: fecha, commit, modelo y manifiesto."""
    sidecar = Path(str(config.MODEL_FILE) + ".sha256")
    model_sha = (sidecar.read_text(encoding="utf-8").split()[0] if sidecar.exists()
                 else (sha256_file(config.MODEL_FILE) if config.MODEL_FILE.exists() else None))
    holdout = str(manifest_path("holdout").relative_to(ROOT))
    info = {"fecha": datetime.now(timezone.utc).isoformat(), "git_commit": git_commit(),
            "modelo_sha256": model_sha, "manifiesto_holdout": holdout,
            "versiones": lib_versions()}
    info.update(extra or {})
    return info


# --- Extracción de características -----------------------------------------
def sample_identity(path) -> tuple[str, str]:
    """(nombre PEP 503, versión) de una muestra según la estructura de su fuente.

    - datadog/<AAAA-MM-DD>-<nombre>-v<versión>/...: el nombre sale de la carpeta
      superior; la ruta de la muestra puede ser un subdirectorio de importación
      ('s3transfer' dentro de 's3transfer-sl') y no sirve como nombre.
    - malregistry/<nombre>/<versión>/<archivo>: nombre y versión de las carpetas.
    - resto (benignos): nombre del archivo (wheel/egg o sdist, ver
      pyscan.extractors.metadata.name_from_filename).
    """
    parts = Path(str(path).replace("\\", "/")).parts
    for i, part in enumerate(parts[:-1]):
        if part == "datadog":
            top = _DATADOG_TOP.match(parts[i + 1])
            if top:
                rest = top.group("rest")
                m = _DATADOG_VER.match(rest)
                if m:
                    return normalize_name(m.group("name")), m.group("ver")
                return name_from_filename(rest)
        if part == "malregistry" and len(parts) > i + 3:
            return normalize_name(parts[i + 1]), parts[i + 2]
    return name_from_filename(parts[-1])


def _package_name_from_file(path: Path) -> str:
    """Compatibilidad: nombre normalizado de la muestra."""
    return sample_identity(path)[0]


def _package_name_from_dir(path: Path) -> str:
    return sample_identity(path)[0]


def _features_from_dir(name: str, root: Path, meta_extractor: MetadataExtractor) -> dict:
    typo = meta_extractor.extract(name)
    entropy = EntropyExtractor().extract(root)
    ast_rep = ASTExtractor().extract(root)
    return build_features(typosquat=typo, entropy=entropy, ast=ast_rep).to_row()


def extract_row(sample: Path, kind: str, meta_extractor: MetadataExtractor) -> dict:
    """FeatureVector de una muestra local, de forma segura ('archive' o 'dir')."""
    name = sample_identity(sample)[0]
    if kind == "dir":
        return _features_from_dir(name, sample, meta_extractor)
    with tempfile.TemporaryDirectory(prefix="pyscan_feat_") as tmp:
        extracted = safe_extract(sample, Path(tmp) / "x")
        return _features_from_dir(name, extracted, meta_extractor)


def classify_exclusion(message: str) -> str:
    """Motivo de exclusión normalizado (corrección 1.5)."""
    m = message.lower()
    if "no existe" in m:
        return "archivo no encontrado"
    if "ilegible" in m or "not a gzip" in m or "readerror" in m or "bad zip" in m:
        return "corrupto o ilegible"
    if any(k in m for k in ("zip slip", "dispositivo", "tamaño máximo", "número máximo",
                            "formato de archivo no soportado")):
        return "rechazado por extracción segura"
    return "otro error"


def _read_cache(path: Path) -> dict[str, dict]:
    cached: dict[str, dict] = {}
    if path.exists():
        with open(path, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                cached[row["sha256"]] = row
    return cached


def _write_cache(path: Path, cached: dict[str, dict]) -> None:
    names = feature_names()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["sha256", "label", "extractor_commit"] + names,
                           extrasaction="ignore")
        w.writeheader()
        for row in cached.values():
            w.writerow(row)


def load_dataset(manifest: Path, cache: Path = FEATURES_CACHE,
                 refresh: bool = False) -> tuple[list[list[float]], list[int], list[dict]]:
    """Devuelve (X, y, meta) del manifiesto; meta = una fila por muestra usada.

    Con refresh=True ignora la caché y vuelve a extraer todo con el código actual.
    """
    names = feature_names()
    cached = {} if refresh else _read_cache(cache)
    previous: dict[str, dict] = {}
    if refresh:  # caché anterior: la única nueva y las antiguas por partición
        for old in (config.DATA_DIR / "features_train.csv",
                    config.DATA_DIR / "features_holdout.csv", cache):
            previous.update(_read_cache(old))
    commit = git_commit()

    with open(manifest, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        raise SystemExit(f"{manifest} está vacío. Corre antes scripts/build_dataset.py")

    meta_extractor = MetadataExtractor()
    X: list[list[float]] = []
    y: list[int] = []
    meta: list[dict] = []
    exclusions: list[dict] = []
    for i, row in enumerate(rows, 1):
        sha, label = row["sha256"], row["label"]
        if sha in cached:
            feats = {n: float(cached[sha][n]) for n in names}
        else:
            sample = ROOT / row["path"]
            kind = row.get("kind", "archive")
            try:
                if not sample.exists():
                    raise FileNotFoundError(f"no existe: {sample}")
                feats = extract_row(sample, kind, meta_extractor)
            except Exception as exc:  # noqa: BLE001 - robustez ante muestras corruptas
                exclusions.append({"sha256": sha, "path": row["path"], "label": label,
                                   "source": row.get("source", ""),
                                   "motivo": classify_exclusion(f"{type(exc).__name__}: {exc}"),
                                   "error": f"{type(exc).__name__}: {exc}"[:300]})
                continue
            if i % 200 == 0:
                print(f"  [{i}/{len(rows)}] extraídas")
            cached[sha] = {**{n: feats[n] for n in names}, "sha256": sha, "label": label,
                           "extractor_commit": commit}
        X.append([feats[n] for n in names])
        y.append(1 if label == "malicious" else 0)
        meta.append({"sha256": sha, "label": label, "source": row.get("source", ""),
                     "path": row.get("path", ""), "group_id": row.get("group_id", "")})

    # La caché es única para todos los manifiestos: se fusiona, no se pisa.
    merged = {**_read_cache(cache), **cached}
    for e in exclusions:  # una muestra excluida no puede quedar con un vector viejo
        merged.pop(e["sha256"], None)
    _write_cache(cache, merged)
    _append_exclusions(manifest, exclusions)
    if refresh:
        _report_refresh(manifest, previous, cached, exclusions, names, commit)
    if exclusions:
        print(f"  Excluidas {len(exclusions)} muestras de {manifest.name} "
              f"(detalle en data/analysis/exclusiones.csv)", file=sys.stderr)
    return X, y, meta


def load_or_extract_features(manifest: Path, cache: Path | None = None):
    """Compatibilidad con los scripts de experimentos: devuelve (X, y)."""
    X, y, _ = load_dataset(manifest)
    return X, y


def _append_exclusions(manifest: Path, exclusions: list[dict]) -> None:
    path = ANALYSIS_DIR / "exclusiones.csv"
    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    existing = []
    if path.exists():
        with open(path, newline="", encoding="utf-8") as fh:
            existing = [r for r in csv.DictReader(fh) if r.get("manifiesto") != manifest.name]
    fields = ["manifiesto", "sha256", "path", "label", "source", "motivo", "error"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(existing)
        for e in exclusions:
            w.writerow({"manifiesto": manifest.name, **e})


def _report_refresh(manifest, previous, fresh, exclusions, names, commit) -> None:
    """Cuántas muestras cambian de vector con el extractor actual (corrección 1.2)."""
    common = [s for s in fresh if s in previous]
    changed = 0
    per_feature = {n: 0 for n in names}
    for s in common:
        diff = [n for n in names if abs(float(previous[s][n]) - float(fresh[s][n])) > 1e-9]
        if diff:
            changed += 1
            for n in diff:
                per_feature[n] += 1
    excluded_now = {e["sha256"] for e in exclusions}
    report_path = ANALYSIS_DIR / "feature_refresh.json"
    report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {}
    report[manifest.name] = {
        "extractor_commit": commit,
        "fecha": datetime.now(timezone.utc).isoformat(),
        "muestras_reextraidas": len(fresh),
        "comparables_con_cache_anterior": len(common),
        "vectores_que_cambiaron": changed,
        "cambios_por_caracteristica": per_feature,
        "excluidas_ahora": len(excluded_now),
        "antes_excluidas_ahora_incluidas": len([s for s in fresh if s not in previous]),
        "antes_incluidas_ahora_excluidas": len([s for s in excluded_now if s in previous]),
    }
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  Reextracción: {changed} de {len(common)} vectores cambiaron "
          f"(detalle en {report_path.relative_to(ROOT)})")


# --- Modelos y validación cruzada -------------------------------------------
def make_models(y, use_xgb: bool = True, cfg: dict | None = None) -> dict:
    from sklearn.ensemble import RandomForestClassifier

    cfg = cfg or CFG
    seed = cfg.get("seed", 42)
    mcfg = cfg.get("models", {})
    rf = mcfg.get("random_forest", {"n_estimators": 300, "class_weight": "balanced"})
    n_pos = sum(y) or 1
    n_neg = len(y) - n_pos or 1
    models = {"random_forest": RandomForestClassifier(**rf, random_state=seed, n_jobs=-1)}
    if use_xgb:
        try:
            from xgboost import XGBClassifier

            xg = mcfg.get("xgboost", {"n_estimators": 300, "max_depth": 6, "learning_rate": 0.1})
            models["xgboost"] = XGBClassifier(**xg, scale_pos_weight=n_neg / n_pos,
                                              eval_metric="logloss", random_state=seed,
                                              n_jobs=-1)
        except ImportError:
            print("  xgboost no instalado: se evalúa solo Random Forest.")
    return models


def make_sampler(kind: str, categorical: list[int], n_cols: int, seed: int):
    """SMOTENC si hay columnas binarias y continuas; si no, SMOTE; o None."""
    if kind == "none":
        return None
    try:
        from imblearn.over_sampling import SMOTE, SMOTENC
    except ImportError:
        print("  imbalanced-learn no instalado: sin sobremuestreo.")
        return None
    if kind == "smotenc" and categorical and len(categorical) < n_cols:
        return SMOTENC(categorical_features=categorical, random_state=seed)
    return SMOTE(random_state=seed)


def categorical_indices(columns: list[str] | None, X=None, cfg: dict | None = None) -> list[int]:
    cfg = cfg or CFG
    binary = set(cfg.get("binary_features",
                         ["is_typosquat", "has_combo_affix", "ast_has_install_hook"]))
    if columns is not None:
        return [j for j, n in enumerate(columns) if n in binary]
    return []


def oof_probabilities(model_factory, X, y, k: int | None = None, use_smote: bool = True,
                      groups=None, sampler: str | None = None, columns: list[str] | None = None,
                      seed: int | None = None):
    """Predicciones out-of-fold: probabilidad de la clase positiva por muestra."""
    import numpy as np
    from sklearn.base import clone
    from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold

    k = k or CFG.get("k_folds", 5)
    seed = CFG.get("seed", 42) if seed is None else seed
    sampler = (sampler or CFG.get("sampler", "smotenc")) if use_smote else "none"
    X = np.asarray(X, dtype=float)
    y = np.asarray(y, dtype=int)
    cat = categorical_indices(columns)
    oof = np.zeros(len(y), dtype=float)
    if groups is not None and any(g not in ("", None) for g in groups):
        g = np.asarray([str(v) if v not in ("", None) else f"solo-{i}"
                        for i, v in enumerate(groups)])
        splits = StratifiedGroupKFold(n_splits=k, shuffle=True, random_state=seed).split(X, y, g)
    else:
        splits = StratifiedKFold(n_splits=k, shuffle=True, random_state=seed).split(X, y)
    for train_idx, val_idx in splits:
        X_tr, y_tr = X[train_idx], y[train_idx]
        smp = make_sampler(sampler, cat, X.shape[1], seed)
        if smp is not None:
            # Sobremuestreo SOLO sobre la partición de entrenamiento: evita fuga.
            try:
                X_tr, y_tr = smp.fit_resample(X_tr, y_tr)
            except ValueError as exc:
                print(f"  Sobremuestreo omitido en una partición: {exc}")
        m = clone(model_factory)
        m.fit(X_tr, y_tr)
        classes = list(m.classes_)
        pos = classes.index(1) if 1 in classes else -1
        oof[val_idx] = m.predict_proba(X[val_idx])[:, pos]
    return oof


# --- Umbral y métricas --------------------------------------------------------
def metrics_at(y, probs, threshold: float) -> dict:
    import numpy as np
    from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score,
                                 precision_score, recall_score)

    y = np.asarray(y)
    pred = (np.asarray(probs) >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "threshold": round(float(threshold), 2),
        "n_samples": int(len(y)),
        "recall": round(float(recall_score(y, pred, zero_division=0)), 4),
        "precision": round(float(precision_score(y, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y, pred, zero_division=0)), 4),
        "pr_auc": round(float(average_precision_score(y, probs)), 4),
        "false_positive_rate": round(float(fp / (fp + tn)) if (fp + tn) else 0.0, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def tune_threshold(y, probs, target_recall: float | None = None) -> tuple[float, dict]:
    """Umbral que maximiza F1 sujeto a Recall >= target (si es alcanzable)."""
    import numpy as np
    from sklearn.metrics import f1_score, recall_score

    target_recall = CFG.get("target_recall", 0.90) if target_recall is None else target_recall
    grid = CFG.get("threshold_grid", {"start": 0.05, "stop": 0.95, "step": 0.01})
    y = np.asarray(y)
    best = None
    for t in np.arange(grid["start"], grid["stop"] + 1e-9, grid["step"]):
        pred = (probs >= t).astype(int)
        key = (recall_score(y, pred, zero_division=0) >= target_recall,
               f1_score(y, pred, zero_division=0))
        # `>=`: ante empate se prefiere el umbral MÁS ALTO (menos falsos positivos).
        if best is None or key >= best[0]:
            best = (key, round(float(t), 2))
    return best[1], metrics_at(y, probs, best[1])


def _write_predictions(path: Path, meta: list[dict], probs, threshold: float) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["sha256", "source", "label", "group_id", "score", "pred_malicious"])
        for m, p in zip(meta, probs):
            w.writerow([m["sha256"], m["source"], m["label"], m.get("group_id", ""),
                        round(float(p), 6), int(p >= threshold)])


# --- Orquestación ---------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--refresh-features", action="store_true",
                    help="reextrae todas las características con el extractor actual")
    ap.add_argument("--sampler", choices=["smotenc", "smote", "none"],
                    help="sobrescribe el sobremuestreo de config.yaml (variante)")
    ap.add_argument("--no-xgb", action="store_true", help="evalúa solo Random Forest")
    ap.add_argument("--tag", help="nombre de una VARIANTE: guarda métricas en "
                    "data/analysis/variante_<tag>.json y NO reemplaza el modelo oficial")
    args = ap.parse_args()

    cfg = dict(CFG)
    if args.sampler:
        cfg["sampler"] = args.sampler
    seed, k, target = cfg.get("seed", 42), cfg.get("k_folds", 5), cfg.get("target_recall", 0.90)
    train_csv, holdout_csv = manifest_path("train"), manifest_path("holdout")
    if not train_csv.exists():
        print(f"No existe {train_csv}. Corre antes scripts/build_dataset.py")
        return 1

    print(f"== 1/5 Características ({train_csv.name}) ==")
    X, y, meta = load_dataset(train_csv, refresh=args.refresh_features)
    n_pos, n_neg = sum(y), len(y) - sum(y)
    groups = [m["group_id"] for m in meta]
    grouped = any(groups)
    print(f"Muestras: {len(y)} (maliciosas={n_pos}, benignas={n_neg}); "
          f"validación {'agrupada' if grouped else 'estratificada'}")

    print(f"\n== 2/5 Validación cruzada (k={k}, sobremuestreo={cfg['sampler']}) ==")
    names = feature_names()
    results = {}
    for name, model in make_models(y, use_xgb=not args.no_xgb, cfg=cfg).items():
        probs = oof_probabilities(model, X, y, k, groups=groups if grouped else None,
                                  sampler=cfg["sampler"], columns=names, seed=seed)
        threshold, m = tune_threshold(y, probs, target)
        results[name] = {"metrics": m, "model": model, "threshold": threshold, "oof": probs}
        print(f"  {name}: recall={m['recall']} f1={m['f1']} pr_auc={m['pr_auc']} "
              f"fp={m['false_positive_rate']} umbral={threshold}")

    def sort_key(item):  # cumple el Recall objetivo primero, luego mayor F1
        mm = item[1]["metrics"]
        return (mm["recall"] >= target, mm["f1"])

    best_name, best = max(results.items(), key=sort_key)
    print(f"\n== 3/5 Mejor modelo: {best_name} (umbral {best['threshold']}) ==")

    print("== 4/5 Reentrenando con todo el entrenamiento ==")
    import joblib
    import numpy as np

    X_arr, y_arr = np.asarray(X, dtype=float), np.asarray(y, dtype=int)
    smp = make_sampler(cfg["sampler"], categorical_indices(names, cfg=cfg), X_arr.shape[1], seed)
    if smp is not None:
        X_arr, y_arr = smp.fit_resample(X_arr, y_arr)
    final_model = best["model"]
    final_model.fit(X_arr, y_arr)

    report = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": git_commit(),
        "config": cfg,
        "versions": lib_versions(),
        "manifests": {"train": str(train_csv.relative_to(ROOT)),
                      "train_sha256": sha256_file(train_csv),
                      "holdout": str(holdout_csv.relative_to(ROOT)),
                      "holdout_sha256": sha256_file(holdout_csv) if holdout_csv.exists() else None},
        "grouped_cv": grouped,
        "k_folds": k, "smote": cfg["sampler"] != "none", "sampler": cfg["sampler"],
        "target_recall": target,
        "n_samples": len(y), "n_malicious": n_pos, "n_benign": n_neg,
        "selected_model": best_name,
        "cv_results": {n: r["metrics"] for n, r in results.items()},
    }
    if hasattr(final_model, "feature_importances_"):
        report["feature_importance"] = {
            n: round(float(v), 4)
            for n, v in sorted(zip(names, final_model.feature_importances_), key=lambda x: -x[1])}

    official = args.tag is None
    out_dir = ANALYSIS_DIR if official else ANALYSIS_DIR / f"variante_{args.tag}"
    _write_predictions(out_dir / "pred_oof.csv", meta, best["oof"], best["threshold"])

    print("== 5/5 Evaluación única en el hold-out (umbral fijado en CV) ==")
    if holdout_csv.exists():
        Xh, yh, meta_h = load_dataset(holdout_csv, refresh=args.refresh_features)
        classes = list(final_model.classes_)
        pos = classes.index(1) if 1 in classes else -1
        probs_h = final_model.predict_proba(np.asarray(Xh, dtype=float))[:, pos]
        report["holdout"] = metrics_at(yh, probs_h, best["threshold"])
        _write_predictions(out_dir / "pred_holdout.csv", meta_h, probs_h, best["threshold"])
        h = report["holdout"]
        print(f"  hold-out: recall={h['recall']} f1={h['f1']} fp={h['false_positive_rate']} "
              f"matriz={h['confusion_matrix']}")
    else:
        print(f"  No existe {holdout_csv}; se omite.")

    if official:
        bundle = {"model": final_model, "features": names, "threshold": best["threshold"],
                  "model_name": best_name, "trained_at": report["trained_at"],
                  "n_samples": len(y), "git_commit": report["git_commit"]}
        config.MODEL_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(bundle, config.MODEL_FILE)
        digest = sha256_file(config.MODEL_FILE)
        Path(str(config.MODEL_FILE) + ".sha256").write_text(digest + "\n", encoding="utf-8")
        report["model_sha256"] = digest
        metrics_file = config.MODEL_DIR / "metrics.json"
    else:
        metrics_file = out_dir / "metrics.json"
    metrics_file.parent.mkdir(parents=True, exist_ok=True)
    metrics_file.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nMétricas: {metrics_file.relative_to(ROOT)}")
    if official:
        print(f"Modelo:   {config.MODEL_FILE.relative_to(ROOT)} (sha256 {report['model_sha256'][:16]}…)")
    kpi = report.get("holdout") or report["cv_results"][best_name]
    print(f"KPI (hold-out): Recall>=0.90 {'OK' if kpi['recall'] >= 0.90 else 'NO'} | "
          f"F1>=0.85 {'OK' if kpi['f1'] >= 0.85 else 'NO'} | "
          f"FP<=10% {'OK' if kpi['false_positive_rate'] <= 0.10 else 'NO'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
