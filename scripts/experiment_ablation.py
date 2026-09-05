#!/usr/bin/env python3
"""Experimento de fuga de datos y estudio de ablación de características.

Responde dos preguntas del análisis crítico del modelo:

  (1) FUGA DE DATOS: ¿el modelo depende demasiado de las señales de NOMBRE
      (name_min_distance, is_typosquat, has_combo_affix)? Como los benignos
      provienen del Top de PyPI —la misma lista usada como referencia—, su
      distancia de nombre tiende a cero y podría inflar el desempeño.

  (2) ABLACIÓN: ¿cuánto aporta CADA grupo de características (nombre, otros
      metadatos, entropía, AST) al desempeño del clasificador?

Para ambas, reentrena el modelo con distintos subconjuntos de características
—reutilizando la misma validación cruzada estratificada y el mismo ajuste de
umbral que el entrenamiento principal— y compara las métricas. Usa la caché de
características ya calculada (data/features_train.csv), por lo que es rápido y
NO requiere volver a extraer nada del corpus.

Interpretación esperada:
  - Si "Solo nombre" ≈ "Todas": hay fuga (el nombre domina la decisión).
  - Si "Sin nombre" mantiene buen Recall: las señales de código discriminan
    por sí solas (resultado deseable, robustez frente a evasión de nombre).

Uso:
    python scripts/experiment_ablation.py --k 5 --target-recall 0.90
    python scripts/experiment_ablation.py --xgb        # usa XGBoost en vez de RF
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from pyscan import config  # noqa: E402
from pyscan.classifier import feature_names  # noqa: E402
# Reutiliza la lógica ya validada del entrenamiento principal.
import train_model as tm  # noqa: E402

OUT_DIR = config.DATA_DIR / "analysis"

# Grupos de características (deben coincidir con FeatureVector, 9 características).
GROUPS = {
    "nombre": ["name_min_distance", "is_typosquat", "has_combo_affix"],
    "entropia": ["entropy_max", "entropy_mean", "entropy_suspicious_windows"],
    "ast": ["ast_dangerous_calls", "ast_network_literals", "ast_has_install_hook"],
}

# Configuraciones a evaluar: nombre -> lista de grupos incluidos.
CONFIGS = {
    "Todas (baseline)": ["nombre", "entropia", "ast"],
    "Solo nombre": ["nombre"],
    "Sin nombre (solo código)": ["entropia", "ast"],
    "Solo AST": ["ast"],
    "Solo entropía": ["entropia"],
}


def _columns_for(groups: list[str], names: list[str]) -> list[int]:
    keep = set()
    for g in groups:
        keep.update(GROUPS[g])
    return [i for i, n in enumerate(names) if n in keep]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--target-recall", type=float, default=0.90)
    ap.add_argument("--no-smote", action="store_true")
    ap.add_argument("--xgb", action="store_true", help="usa XGBoost (por defecto Random Forest)")
    args = ap.parse_args()

    train_csv = config.DATA_DIR / "train.csv"
    if not train_csv.exists():
        print("No existe data/train.csv. Corre antes scripts/build_dataset.py")
        return 1

    names = feature_names()
    print("== Extracción de características (usa caché si existe) ==")
    X_full, y = tm.load_or_extract_features(train_csv, tm.FEATURES_CACHE)
    X_full = np.asarray(X_full, dtype=float)
    y = np.asarray(y, dtype=int)
    n_pos, n_neg = int(y.sum()), int(len(y) - y.sum())
    print(f"Muestras: {len(y)} (maliciosas={n_pos}, benignas={n_neg})\n")

    results = {}
    print(f"== Ablación (algoritmo: {'XGBoost' if args.xgb else 'Random Forest'}, k={args.k}) ==")
    for label, groups in CONFIGS.items():
        cols = _columns_for(groups, names)
        Xc = X_full[:, cols]
        # Un solo algoritmo consistente en todas las configuraciones para aislar
        # el efecto de las características (no del modelo).
        model = tm.make_models(y, use_xgb=args.xgb)
        model = model["xgboost"] if args.xgb and "xgboost" in model else model["random_forest"]
        probs = tm.oof_probabilities(model, Xc, y, args.k, use_smote=not args.no_smote)
        _, metrics = tm.tune_threshold(y, probs, args.target_recall)
        results[label] = {"n_features": len(cols), "metrics": metrics}
        print(f"  {label:<32} recall={metrics['recall']:.4f} "
              f"f1={metrics['f1']:.4f} pr_auc={metrics['pr_auc']:.4f} "
              f"fp={metrics['false_positive_rate']:.4f} (nfeat={len(cols)})")

    # --- Salidas ---
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "ablation.json").write_text(
        json.dumps({"n_samples": len(y), "algorithm": "xgboost" if args.xgb else "random_forest",
                    "configs": results}, indent=2, ensure_ascii=False), encoding="utf-8")
    with open(OUT_DIR / "ablation.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["configuracion", "n_features", "recall", "precision", "f1",
                    "pr_auc", "false_positive_rate"])
        for label, r in results.items():
            m = r["metrics"]
            w.writerow([label, r["n_features"], m["recall"], m["precision"],
                        m["f1"], m["pr_auc"], m["false_positive_rate"]])

    # --- Tabla e interpretación automática ---
    base = results["Todas (baseline)"]["metrics"]["f1"]
    solo_nombre = results["Solo nombre"]["metrics"]["f1"]
    sin_nombre = results["Sin nombre (prueba de fuga)"]["metrics"]
    print("\n| Configuración | Recall | F1 | FP |")
    print("|---|---|---|---|")
    for label, r in results.items():
        m = r["metrics"]
        print(f"| {label} | {m['recall']:.4f} | {m['f1']:.4f} | {m['false_positive_rate']:.4f} |")

    print("\n== Interpretación automática ==")
    if solo_nombre >= base - 0.02:
        print(f"  ⚠ FUGA CONFIRMADA: 'Solo nombre' (F1={solo_nombre:.3f}) iguala casi al "
              f"baseline (F1={base:.3f}). El nombre domina la decisión.")
    else:
        print(f"  ✓ 'Solo nombre' (F1={solo_nombre:.3f}) queda por debajo del baseline "
              f"(F1={base:.3f}): el nombre no lo explica todo.")
    if sin_nombre["recall"] >= 0.85:
        print(f"  ✓ Sin las señales de nombre, el modelo mantiene Recall="
              f"{sin_nombre['recall']:.3f}: las señales de código discriminan por sí solas.")
    else:
        print(f"  ⚠ Sin nombre, el Recall cae a {sin_nombre['recall']:.3f}: el modelo "
              f"depende fuertemente del nombre.")

    # --- Gráfico opcional ---
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        labels = list(results.keys())
        f1s = [results[l]["metrics"]["f1"] for l in labels]
        recalls = [results[l]["metrics"]["recall"] for l in labels]
        x = np.arange(len(labels)); wbar = 0.38
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.bar(x - wbar/2, recalls, wbar, label="Recall", color="#1F3864")
        ax.bar(x + wbar/2, f1s, wbar, label="F1", color="#8FAADC")
        ax.set_ylabel("Métrica"); ax.set_ylim(0, 1.05)
        ax.set_title("Ablación de características: Recall y F1 por configuración")
        ax.set_xticks(x); ax.set_xticklabels(labels, rotation=25, ha="right", fontsize=8)
        ax.legend(); ax.grid(axis="y", alpha=0.3); fig.tight_layout()
        fig.savefig(OUT_DIR / "ablation.png", dpi=150)
        print(f"\nGráfico: {OUT_DIR/'ablation.png'}")
    except ImportError:
        print("\n(matplotlib no instalado: se omite el gráfico)")

    print(f"Datos:   {OUT_DIR/'ablation.json'}  |  {OUT_DIR/'ablation.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
