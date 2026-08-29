#!/usr/bin/env python3
"""Comparación empírica de pyscan frente a GuardDog sobre el mismo conjunto.

Evalúa ambos detectores sobre un subconjunto del hold-out (muestras que el
modelo de pyscan NO vio en entrenamiento, para una comparación justa) y calcula
Recall, Precisión, F1 y tasa de falsos positivos de cada uno. Desglosa además por
fuente del malware (DataDog vs Malregistry), porque las heurísticas de GuardDog
fueron desarrolladas a partir del dataset de DataDog y podrían tener ventaja en
esas muestras.

Decisión de cada detector:
  - pyscan: veredicto del clasificador supervisado (probabilidad ≥ umbral).
  - GuardDog: se marca como malicioso si activa ≥1 regla de amenaza (threat-*).
    Las reglas de "capability-*" (neutras) no cuentan por sí solas.

Requisitos en la VM:
    pip install guarddog
GuardDog usa un sandbox de kernel por defecto; si no está disponible, este
script pasa --no-sandbox automáticamente.

Uso:
    python scripts/experiment_compare_guarddog.py --limit-per-class 150
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from pyscan import config  # noqa: E402
from pyscan.classifier import load_bundle, predict  # noqa: E402
from pyscan.models import FeatureVector, Verdict  # noqa: E402
import train_model as tm  # noqa: E402

OUT_DIR = config.DATA_DIR / "analysis"
_GUARDDOG_BIN = ""  # ruta al binario de GuardDog (se fija desde --guarddog-bin)


def _guarddog_cmd() -> list[str]:
    if _GUARDDOG_BIN:
        return [_GUARDDOG_BIN]
    if shutil.which("guarddog"):
        return ["guarddog"]
    return [sys.executable, "-m", "guarddog"]


def _guarddog_flag(path: Path, threat_min: int, no_sandbox: bool) -> tuple[int, dict]:
    """Corre GuardDog sobre un paquete local; devuelve (nº reglas threat, info)."""
    cmd = _guarddog_cmd() + ["pypi", "scan", str(path), "--output-format", "json"]
    if no_sandbox:
        cmd.append("--no-sandbox")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        data = json.loads(r.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, ValueError):
        return -1, {}
    results = data.get("results", {})
    threats = [k for k, v in results.items() if k.startswith("threat-") and v]
    info = {"issues": data.get("issues", 0),
            "risk_label": data.get("risk_score", {}).get("label"),
            "risk_score": data.get("risk_score", {}).get("score"),
            "threat_rules": threats}
    return len(threats), info


def _metrics(tp, fp, tn, fn) -> dict:
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {"recall": round(recall, 4), "precision": round(precision, 4),
            "f1": round(f1, 4), "false_positive_rate": round(fpr, 4),
            "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--limit-per-class", type=int, default=150,
                    help="muestras por clase (malicioso/benigno). Menos = más rápido.")
    ap.add_argument("--threat-min", type=int, default=1,
                    help="nº mínimo de reglas threat-* para que GuardDog marque malicioso")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--from-csv", type=Path, default=None,
                    help="manifiesto a usar (por defecto data/holdout.csv)")
    ap.add_argument("--sandbox", action="store_true", help="no pasar --no-sandbox a GuardDog")
    ap.add_argument("--guarddog-bin", default="",
                    help="ruta al binario de guarddog (p. ej. ~/.local/bin/guarddog)")
    args = ap.parse_args()

    global _GUARDDOG_BIN
    if args.guarddog_bin:
        _GUARDDOG_BIN = str(Path(args.guarddog_bin).expanduser())

    manifest = args.from_csv or (config.DATA_DIR / "holdout.csv")
    if not manifest.exists():
        print(f"No existe {manifest}. Corre scripts/build_dataset.py y train_model.py --holdout")
        return 1

    with open(manifest, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    rng = random.Random(args.seed)
    mal = [r for r in rows if r["label"] == "malicious"]; rng.shuffle(mal)
    ben = [r for r in rows if r["label"] == "benign"]; rng.shuffle(ben)
    mal = mal[:args.limit_per_class]; ben = ben[:args.limit_per_class]
    sample = mal + ben
    print(f"Comparando sobre {len(sample)} muestras "
          f"({len(mal)} maliciosas, {len(ben)} benignas)\n")

    bundle = load_bundle()
    meta = tm.MetadataExtractor()

    # Contadores globales y por fuente.
    def zero(): return {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    py = zero(); gd = zero()
    gd_by_src = defaultdict(zero); py_by_src = defaultdict(zero)
    gd_errors = 0
    per_sample = []

    for i, row in enumerate(sample, 1):
        p = ROOT / row["path"]; kind = row.get("kind", "archive")
        is_mal = row["label"] == "malicious"
        src = row.get("source", "?")
        if not p.exists():
            continue

        # pyscan
        try:
            fv = FeatureVector(**tm.extract_row(p, kind, meta))
            py_mal = predict(fv, bundle=bundle).verdict == Verdict.MALICIOUS
        except Exception:  # noqa: BLE001
            py_mal = False

        # GuardDog
        n_threat, info = _guarddog_flag(p, args.threat_min, no_sandbox=not args.sandbox)
        if n_threat < 0:
            gd_errors += 1
            gd_mal = None
        else:
            gd_mal = n_threat >= args.threat_min

        # Tabulación
        def tally(bucket, pred_mal):
            if pred_mal is None:
                return
            if is_mal and pred_mal: bucket["tp"] += 1
            elif is_mal and not pred_mal: bucket["fn"] += 1
            elif not is_mal and pred_mal: bucket["fp"] += 1
            else: bucket["tn"] += 1
        tally(py, py_mal); tally(gd, gd_mal)
        if is_mal:  # el desglose por fuente aplica al malware
            tally(py_by_src[src], py_mal); tally(gd_by_src[src], gd_mal)

        per_sample.append({"package": p.name, "label": row["label"], "source": src,
                           "pyscan_malicious": bool(py_mal),
                           "guarddog_malicious": None if gd_mal is None else bool(gd_mal),
                           "guarddog_threat_rules": info.get("threat_rules", [])})
        if i % 25 == 0:
            print(f"  {i}/{len(sample)} procesados...")

    py_m = _metrics(**py); gd_m = _metrics(**gd)

    print("\n== Resultados globales ==")
    print("| Detector | Recall | Precisión | F1 | FP |")
    print("|---|---|---|---|---|")
    print(f"| pyscan (ML) | {py_m['recall']:.3f} | {py_m['precision']:.3f} | "
          f"{py_m['f1']:.3f} | {py_m['false_positive_rate']:.3f} |")
    print(f"| GuardDog (reglas) | {gd_m['recall']:.3f} | {gd_m['precision']:.3f} | "
          f"{gd_m['f1']:.3f} | {gd_m['false_positive_rate']:.3f} |")
    if gd_errors:
        print(f"\n(GuardDog no pudo analizar {gd_errors} muestras; se excluyeron de su conteo.)")

    print("\n== Recall sobre malware por fuente ==")
    print("| Fuente | pyscan | GuardDog |")
    print("|---|---|---|")
    for src in sorted(set(list(py_by_src) + list(gd_by_src))):
        pr = _metrics(**py_by_src[src])["recall"] if py_by_src[src] else 0
        gr = _metrics(**gd_by_src[src])["recall"] if gd_by_src[src] else 0
        print(f"| {src} | {pr:.3f} | {gr:.3f} |")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    report = {"n_samples": len(sample), "n_malicious": len(mal), "n_benign": len(ben),
              "threat_min": args.threat_min, "guarddog_errors": gd_errors,
              "pyscan": py_m, "guarddog": gd_m,
              "recall_by_source": {
                  src: {"pyscan": _metrics(**py_by_src[src])["recall"] if py_by_src[src] else None,
                        "guarddog": _metrics(**gd_by_src[src])["recall"] if gd_by_src[src] else None}
                  for src in sorted(set(list(py_by_src) + list(gd_by_src)))}}
    (OUT_DIR / "compare_guarddog.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    with open(OUT_DIR / "compare_guarddog_per_sample.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["package", "label", "source",
                           "pyscan_malicious", "guarddog_malicious", "guarddog_threat_rules"])
        w.writeheader()
        for r in per_sample:
            r = dict(r); r["guarddog_threat_rules"] = ";".join(r["guarddog_threat_rules"])
            w.writerow(r)
    print(f"\nDatos: {OUT_DIR/'compare_guarddog.json'} | {OUT_DIR/'compare_guarddog_per_sample.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
