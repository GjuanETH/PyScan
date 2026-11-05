#!/usr/bin/env python3
"""Comparativas con denominadores explícitos (corrección 2.5).

Relee los CSV por muestra de las comparaciones y reporta, para cada herramienta:
  - política A: errores de la herramienta EXCLUIDOS (denominador reducido),
  - política B: error = "no alertó" (FN si es malicioso, VN si es benigno),
  - política C: error = clasificación errónea (peor caso),
con IC 95 % de Wilson, y para VirusTotal el desglose por clase de las muestras
encontradas y no registradas en su base (si el CSV trae la columna vt_found).

Uso:  python scripts/report_comparisons.py
Salida: data/analysis/comparisons_report.json
"""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from report_utils import norm_source, prop  # noqa: E402

ANALYSIS = ROOT / "data" / "analysis"
TOOLS = [("guarddog", "compare_guarddog", "guarddog_malicious"),
         ("clamav", "compare_antivirus", "clamav_malicious"),
         ("virustotal", "compare_virustotal", "vt_malicious")]


def as_bool(v: str):
    v = (v or "").strip().lower()
    if v in ("true", "1"):
        return True
    if v in ("false", "0"):
        return False
    return None  # error / sin veredicto


def score(rows, col, policy):
    tp = fp = tn = fn = 0
    for r in rows:
        mal = r["label"] == "malicious"
        pred = as_bool(r[col])
        if pred is None:
            if policy == "A":
                continue
            pred = False if policy == "B" else (not mal)
        if mal and pred:
            tp += 1
        elif mal:
            fn += 1
        elif pred:
            fp += 1
        else:
            tn += 1
    rec, fpr = prop(tp, tp + fn), prop(fp, fp + tn)
    prec = prop(tp, tp + fp)
    p, r_ = prec["valor"] or 0, rec["valor"] or 0
    return {"n": tp + fp + tn + fn, "vp": tp, "fp": fp, "vn": tn, "fn": fn,
            "recall": rec, "fpr": fpr, "precision": prec,
            "f1": round(2 * p * r_ / (p + r_), 4) if p + r_ else 0.0}


def main() -> int:
    report = {}
    for tool, stem, col in TOOLS:
        path = ANALYSIS / f"{stem}_per_sample.csv"
        if not path.exists():
            continue
        with open(path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        errors = [r for r in rows if as_bool(r[col]) is None]
        meta = {}
        jpath = ANALYSIS / f"{stem}.json"
        if jpath.exists():
            meta = json.loads(jpath.read_text(encoding="utf-8")).get("ejecucion", {})
        entry = {
            "muestras": len(rows),
            "por_clase_y_fuente": dict(Counter(
                f"{r['label']}/{norm_source(r['label'], r['source'])}" for r in rows)),
            "errores_herramienta": len(errors),
            "errores_por_clase": dict(Counter(r["label"] for r in errors)),
            "ejecucion": meta or "sin registrar (reejecutar el experimento para guardarla)",
            "pyscan": score(rows, "pyscan_malicious", "B"),
        }
        for pol in ("A", "B", "C"):
            entry[f"{tool}_politica_{pol}"] = score(rows, col, pol)
        if tool == "virustotal":
            if "vt_found" in rows[0]:
                entry["vt_registradas_por_clase"] = dict(Counter(
                    f"{r['label']}/{'registrada' if as_bool(r['vt_found']) else 'no registrada'}"
                    for r in rows))
                found = [r for r in rows if as_bool(r["vt_found"])]
                entry["virustotal_solo_registradas"] = score(found, col, "A")
                entry["pyscan_solo_registradas"] = score(found, "pyscan_malicious", "B")
            else:
                entry["vt_registradas_por_clase"] = ("el CSV no trae vt_found: reejecutar "
                                                     "experiment_compare_virustotal.py")
        report[tool] = entry

    report["nota"] = ("Política A excluye los errores de la herramienta; B los cuenta como "
                      "'no alertó'; C como error de clasificación. pyscan se cuenta siempre "
                      "con B (si falla, no alerta). Las conclusiones se limitan a estas muestras.")
    out = ANALYSIS / "comparisons_report.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    for tool, e in report.items():
        if tool == "nota":
            continue
        print(f"\n== {tool} ({e['muestras']} muestras, {e['errores_herramienta']} errores) ==")
        print("| Detector | n | Recall (IC95) | FPR (IC95) | F1 |")
        print("|---|---|---|---|---|")
        for label, m in [("pyscan", e["pyscan"])] + [
                (f"{tool} {p}", e[f"{tool}_politica_{p}"]) for p in ("A", "B", "C")]:
            print(f"| {label} | {m['n']} | {m['recall']['valor']} ({m['recall']['ic95'][0]}–"
                  f"{m['recall']['ic95'][1]}) | {m['fpr']['valor']} ({m['fpr']['ic95'][0]}–"
                  f"{m['fpr']['ic95'][1]}) | {m['f1']} |")
        if tool == "virustotal":
            print(f"  Registradas en VT por clase: {e['vt_registradas_por_clase']}")
    print(f"\nDatos: {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
