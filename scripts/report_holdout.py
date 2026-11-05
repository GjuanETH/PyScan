#!/usr/bin/env python3
"""Reporte del hold-out: matriz de confusión, métricas por fuente con intervalo de
confianza de Wilson y prevalencia como escenario condicionado.

Corrige: 2.1 (matriz del hold-out), 2.7 (prevalencia con FPR por fuente y su
supuesto declarado) y 2.8 (Recall y FPR por fuente con IC 95 %).
Lee data/analysis/pred_holdout.csv y pred_oof.csv (los escribe train_model.py).

Uso:  python scripts/report_holdout.py
Salida: data/analysis/holdout_report.json (+ tablas en pantalla)
"""

from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from report_utils import norm_source, project_precision, prop  # noqa: E402

ANALYSIS = ROOT / "data" / "analysis"
PREVALENCES = [0.5, 0.10, 0.05, 0.01, 0.005, 0.001]


def load(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def summarize(rows: list[dict]) -> dict:
    tp = sum(1 for r in rows if r["label"] == "malicious" and r["pred_malicious"] == "1")
    fn = sum(1 for r in rows if r["label"] == "malicious" and r["pred_malicious"] == "0")
    fp = sum(1 for r in rows if r["label"] == "benign" and r["pred_malicious"] == "1")
    tn = sum(1 for r in rows if r["label"] == "benign" and r["pred_malicious"] == "0")
    out = {"n": len(rows), "matriz": {"vp": tp, "fn": fn, "fp": fp, "vn": tn},
           "recall": prop(tp, tp + fn), "fpr": prop(fp, fp + tn),
           "precision": prop(tp, tp + fp)}
    p, r = out["precision"]["valor"] or 0, out["recall"]["valor"] or 0
    out["f1"] = round(2 * p * r / (p + r), 4) if p + r else 0.0
    by = defaultdict(list)
    for row in rows:
        by[norm_source(row["label"], row["source"])].append(row)
    per_source = {}
    for src, rs in sorted(by.items()):
        if rs[0]["label"] == "malicious":
            k = sum(1 for x in rs if x["pred_malicious"] == "1")
            per_source[src] = {"clase": "maliciosa", "recall": prop(k, len(rs))}
        else:
            k = sum(1 for x in rs if x["pred_malicious"] == "1")
            per_source[src] = {"clase": "benigna", "fpr": prop(k, len(rs))}
    out["por_fuente"] = per_source
    return out


def prevalence_scenarios(s: dict) -> dict:
    tpr = s["recall"]["valor"]
    scen = {"global (hold-out)": s["fpr"]["valor"],
            "FPR límite superior IC95": s["fpr"]["ic95"][1]}
    ps = s["por_fuente"]
    if "top" in ps:
        scen["optimista: FPR de paquetes Top"] = ps["top"]["fpr"]["valor"]
    if "aleatoria" in ps:
        scen["pesimista: FPR de paquetes aleatorios"] = ps["aleatoria"]["fpr"]["valor"]
    out = {"supuesto": "La proyección asume que Recall y FPR no cambian con la prevalencia; "
                       "como el FPR difiere entre fuentes, se dan escenarios.",
           "recall_usado": tpr, "escenarios": {}}
    for name, fpr in scen.items():
        rows = {}
        for pi in PREVALENCES:
            prec = project_precision(tpr, fpr, pi)
            per1000 = {"alertas": round(1000 * (tpr * pi + fpr * (1 - pi)), 1),
                       "falsas": round(1000 * fpr * (1 - pi), 1)}
            rows[f"{pi:.1%} maliciosos"] = {"precision": prec, "por_1000_dependencias": per1000}
        out["escenarios"][f"{name} (FPR={fpr})"] = rows
    return out


def main() -> int:
    metrics = json.loads((ROOT / "data" / "models" / "metrics.json").read_text(encoding="utf-8"))
    report = {"umbral": metrics.get("holdout", {}).get("threshold"),
              "modelo_sha256": metrics.get("model_sha256"),
              "git_commit": metrics.get("git_commit")}
    hold = ANALYSIS / "pred_holdout.csv"
    if not hold.exists():
        print("No existe data/analysis/pred_holdout.csv. Corre antes scripts/train_model.py")
        return 1
    report["holdout"] = summarize(load(hold))
    if (ANALYSIS / "pred_oof.csv").exists():
        report["validacion_cruzada_oof"] = summarize(load(ANALYSIS / "pred_oof.csv"))
    report["prevalencia"] = prevalence_scenarios(report["holdout"])
    # Variantes (p. ej. SMOTE clásico frente a SMOTENC, corrección 1.4).
    variants = {}
    for vm in sorted(ANALYSIS.glob("variante_*/metrics.json")):
        d = json.loads(vm.read_text(encoding="utf-8"))
        sel = d.get("selected_model")
        variants[vm.parent.name] = {"sobremuestreo": d.get("sampler"),
                                    "cv": d.get("cv_results", {}).get(sel),
                                    "holdout": d.get("holdout")}
    if variants:
        sel = metrics.get("selected_model")
        variants["oficial"] = {"sobremuestreo": metrics.get("sampler"),
                               "cv": metrics.get("cv_results", {}).get(sel),
                               "holdout": metrics.get("holdout")}
        report["variantes"] = variants
    (ANALYSIS / "holdout_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    h = report["holdout"]
    m = h["matriz"]
    print(f"Hold-out (n={h['n']}, umbral {report['umbral']})")
    print(f"  Matriz: VP={m['vp']} FN={m['fn']} FP={m['fp']} VN={m['vn']}")
    for k in ("recall", "fpr", "precision"):
        print(f"  {k}: {h[k]['valor']} (IC95 {h[k]['ic95'][0]}–{h[k]['ic95'][1]})")
    print(f"  F1: {h['f1']}")
    print("\n| Fuente | Clase | Métrica | Valor | IC 95 % | n |")
    print("|---|---|---|---|---|---|")
    for src, d in h["por_fuente"].items():
        key = "recall" if d["clase"] == "maliciosa" else "fpr"
        v = d[key]
        print(f"| {src} | {d['clase']} | {key} | {v['valor']} | {v['ic95'][0]}–{v['ic95'][1]} | "
              f"{v['n']} |")
    print("\nPrecisión proyectada por escenario:")
    for name, rows in report["prevalencia"]["escenarios"].items():
        vals = ", ".join(f"{k}: {v['precision']}" for k, v in rows.items())
        print(f"  {name}: {vals}")
    for name, v in report.get("variantes", {}).items():
        cv, ho = v["cv"] or {}, v["holdout"] or {}
        print(f"  Variante {name} ({v['sobremuestreo']}): CV F1={cv.get('f1')} "
              f"Recall={cv.get('recall')} | hold-out F1={ho.get('f1')} Recall={ho.get('recall')}")
    print("\nDatos: data/analysis/holdout_report.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
