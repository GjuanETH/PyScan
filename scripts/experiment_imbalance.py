#!/usr/bin/env python3
"""Evaluación del modelo bajo prevalencia realista (desbalance de clases).

El dataset se entrena y evalúa con un balance ~1:1 (malicioso:benigno), pero en
el mundo real el malware es rarísimo (~1:100 a 1:1000). A esa prevalencia, aunque
el Recall y la especificidad no cambian, la PRECISIÓN se desploma: como los
benignos son mayoría abrumadora, incluso una tasa de falsos positivos baja genera
muchas alarmas falsas por cada acierto.

Este script NO necesita descargar más benignos. Usa un resultado estadístico:
Recall (TPR) y tasa de falsos positivos (FPR) son independientes de la
prevalencia, así que se miden en el hold-out y se PROYECTA la precisión esperada
a cualquier prevalencia π:

    precision(π) = TPR·π / ( TPR·π + FPR·(1-π) )

Produce: (a) proyección de precisión/F1/alarmas a varias prevalencias con el
umbral de operación, y (b) un barrido de umbral a prevalencia realista (1:100)
para mostrar el equilibrio precisión–recall y sugerir un punto de operación.

Uso:
    python scripts/experiment_imbalance.py
    python scripts/experiment_imbalance.py --target-prevalence 0.01
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
import train_model as tm  # noqa: E402

OUT_DIR = config.DATA_DIR / "analysis"
PREVALENCES = [(0.5, "1:1"), (0.1, "1:9"), (0.05, "1:19"),
               (0.01, "1:99"), (0.005, "1:199"), (0.001, "1:999")]


def _load_model():
    import joblib
    if not config.MODEL_FILE.exists():
        raise SystemExit("No hay modelo entrenado. Corre antes scripts/train_model.py --holdout")
    b = joblib.load(config.MODEL_FILE)
    classes = list(getattr(b["model"], "classes_", [0, 1]))
    pos = classes.index(1) if 1 in classes else len(classes) - 1
    return b["model"], list(b.get("features") or []), float(b.get("threshold", 0.5)), pos


def _rates(y, probs, thr):
    """Devuelve (TPR, FPR) al umbral thr."""
    pred = (probs >= thr).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return tpr, fpr


def _project(tpr, fpr, pi):
    """Precisión y F1 esperados a prevalencia pi, más conteos por 10.000 paquetes."""
    denom = tpr * pi + fpr * (1 - pi)
    precision = (tpr * pi / denom) if denom else 0.0
    f1 = (2 * precision * tpr / (precision + tpr)) if (precision + tpr) else 0.0
    N = 10_000
    tp = tpr * pi * N; fp = fpr * (1 - pi) * N
    return {"precision": round(precision, 4), "recall": round(tpr, 4), "f1": round(f1, 4),
            "tp_por_10k": round(tp, 1), "fp_por_10k": round(fp, 1),
            "alarmas_por_10k": round(tp + fp, 1),
            "falsas_por_acierto": round(fp / tp, 2) if tp else float("inf")}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target-prevalence", type=float, default=0.01,
                    help="prevalencia para el barrido de umbral (0.01 = 1:100)")
    args = ap.parse_args()

    holdout_csv = config.DATA_DIR / "holdout.csv"
    if not holdout_csv.exists():
        print("No existe data/holdout.csv. Corre scripts/build_dataset.py y train_model.py --holdout")
        return 1

    model, names, base_thr, pos = _load_model()
    print("== Extracción de características del hold-out (usa caché si existe) ==")
    X, y = tm.load_or_extract_features(holdout_csv, config.DATA_DIR / "features_holdout.csv")
    X = np.asarray(X, dtype=float); y = np.asarray(y, dtype=int)
    probs = model.predict_proba(X)[:, pos]
    tpr, fpr = _rates(y, probs, base_thr)
    print(f"Hold-out: {len(y)} muestras | umbral={base_thr:.2f} | "
          f"TPR(Recall)={tpr:.4f} | FPR={fpr:.4f}\n")

    # (a) Proyección a distintas prevalencias con el umbral de operación.
    print("== Desempeño proyectado a prevalencia realista (umbral de operación) ==")
    print("| Prevalencia | Precisión | Recall | F1 | Alarmas/10k | Falsas por acierto |")
    print("|---|---|---|---|---|---|")
    projection = {}
    for pi, label in PREVALENCES:
        m = _project(tpr, fpr, pi)
        projection[label] = m
        print(f"| {label} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} "
              f"| {m['alarmas_por_10k']:.0f} | {m['falsas_por_acierto']} |")

    # (b) Barrido de umbral a prevalencia objetivo (1:100 por defecto).
    pi = args.target_prevalence
    print(f"\n== Barrido de umbral a prevalencia {pi:.4f} "
          f"(1:{round((1-pi)/pi)}) ==")
    print("| Umbral | Recall | Precisión (proy.) | F1 (proy.) | FPR |")
    print("|---|---|---|---|---|")
    sweep = []
    best = None
    for thr in np.round(np.arange(0.20, 0.96, 0.05), 2):
        tp_r, fp_r = _rates(y, probs, float(thr))
        m = _project(tp_r, fp_r, pi)
        sweep.append({"threshold": float(thr), "fpr": round(fp_r, 4), **m})
        print(f"| {thr:.2f} | {m['recall']:.3f} | {m['precision']:.3f} | {m['f1']:.3f} | {fp_r:.4f} |")
        if m["recall"] >= 0.80 and (best is None or m["f1"] > best["f1"]):
            best = {"threshold": float(thr), **m}

    # --- Salidas ---
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    report = {"n_holdout": int(len(y)), "operating_threshold": base_thr,
              "measured": {"tpr": round(tpr, 4), "fpr": round(fpr, 4)},
              "projection_by_prevalence": projection,
              "target_prevalence": pi, "threshold_sweep": sweep,
              "suggested_operating_point": best}
    (OUT_DIR / "imbalance.json").write_text(json.dumps(report, indent=2, ensure_ascii=False),
                                            encoding="utf-8")
    with open(OUT_DIR / "imbalance_projection.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["prevalencia", "precision", "recall", "f1",
                                        "alarmas_por_10k", "falsas_por_acierto"])
        for label, m in projection.items():
            w.writerow([label, m["precision"], m["recall"], m["f1"],
                        m["alarmas_por_10k"], m["falsas_por_acierto"]])

    if best:
        print(f"\nPunto de operación sugerido a 1:{round((1-pi)/pi)}: umbral={best['threshold']:.2f} "
              f"→ Recall={best['recall']:.3f}, Precisión≈{best['precision']:.3f}, F1≈{best['f1']:.3f}")

    # --- Gráfico ---
    try:
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        labels = [l for _, l in PREVALENCES]
        precs = [projection[l]["precision"] for l in labels]
        recs = [projection[l]["recall"] for l in labels]
        x = np.arange(len(labels))
        fig, ax = plt.subplots(figsize=(9, 5))
        ax.plot(x, precs, "o-", color="#C55A11", label="Precisión (proyectada)")
        ax.plot(x, recs, "s-", color="#1F3864", label="Recall (constante)")
        ax.set_xticks(x); ax.set_xticklabels(labels)
        ax.set_xlabel("Prevalencia de malware (malicioso:benigno)")
        ax.set_ylabel("Métrica"); ax.set_ylim(0, 1.05); ax.grid(alpha=0.3); ax.legend()
        ax.set_title("Efecto de la prevalencia realista sobre la precisión")
        for xi, pr in zip(x, precs):
            ax.annotate(f"{pr:.2f}", (xi, pr), textcoords="offset points", xytext=(0, 8), fontsize=8)
        fig.tight_layout(); fig.savefig(OUT_DIR / "imbalance.png", dpi=150)
        print(f"Gráfico: {OUT_DIR/'imbalance.png'}")
    except ImportError:
        print("(matplotlib no instalado: se omite el gráfico)")

    print(f"Datos: {OUT_DIR/'imbalance.json'} | {OUT_DIR/'imbalance_projection.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
