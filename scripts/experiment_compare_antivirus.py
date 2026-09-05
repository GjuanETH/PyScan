#!/usr/bin/env python3
"""Comparación empírica de pyscan frente a un antivirus tradicional (ClamAV).

Evalúa ambos detectores sobre un subconjunto del hold-out y calcula Recall,
Precisión, F1 y tasa de falsos positivos, con desglose por fuente del malware.

Motivación (observación del director): verificar cuál tiene más efectividad.
Nota metodológica: los antivirus tradicionales detectan malware por firmas
conocidas (troyanos, virus de ejecutable), no patrones de la cadena de
suministro en paquetes de PyPI; por ello se espera un Recall bajo de ClamAV.
Ese resultado, lejos de ser negativo, evidencia la necesidad de una herramienta
especializada como pyscan.

Decisión de cada detector:
  - pyscan: veredicto del clasificador supervisado.
  - ClamAV: se marca malicioso si clamscan reporta al menos un archivo infectado.

Requisitos en la VM:
    sudo apt-get install -y clamav
    sudo freshclam            # actualiza la base de firmas

Uso:
    python scripts/experiment_compare_antivirus.py --limit-per-class 150
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
_CLAMSCAN = "clamscan"


def _clamav_flag(path: Path) -> tuple[int, dict]:
    """Corre clamscan sobre un paquete local; devuelve (nº infectados, info).

    clamscan: exit 0 = limpio, 1 = infectado, 2 = error.
    """
    cmd = [_CLAMSCAN, "-r", "--infected", "--no-summary", str(path)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return -1, {}
    if r.returncode == 2:  # error de escaneo
        return -1, {}
    found = [ln for ln in r.stdout.splitlines() if ln.strip().endswith("FOUND")]
    return len(found), {"n_infected": len(found), "signatures": found[:5]}


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
    ap.add_argument("--limit-per-class", type=int, default=150)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--from-csv", type=Path, default=None)
    ap.add_argument("--clamscan-bin", default="", help="ruta a clamscan (si no está en PATH)")
    args = ap.parse_args()

    global _CLAMSCAN
    if args.clamscan_bin:
        _CLAMSCAN = str(Path(args.clamscan_bin).expanduser())
    if not (args.clamscan_bin or shutil.which("clamscan")):
        print("No se encontró clamscan. Instala ClamAV: sudo apt-get install -y clamav")
        return 1

    manifest = args.from_csv or (config.DATA_DIR / "holdout.csv")
    if not manifest.exists():
        print(f"No existe {manifest}. Corre build_dataset.py y train_model.py --holdout")
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

    def zero(): return {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    py = zero(); av = zero()
    av_by_src = defaultdict(zero); py_by_src = defaultdict(zero)
    av_errors = 0
    per_sample = []

    for i, row in enumerate(sample, 1):
        p = ROOT / row["path"]; kind = row.get("kind", "archive")
        is_mal = row["label"] == "malicious"; src = row.get("source", "?")
        if not p.exists():
            continue
        # pyscan
        try:
            fv = FeatureVector(**tm.extract_row(p, kind, meta))
            py_mal = predict(fv, bundle=bundle).verdict == Verdict.MALICIOUS
        except Exception:  # noqa: BLE001
            py_mal = False
        # ClamAV
        n_inf, info = _clamav_flag(p)
        if n_inf < 0:
            av_errors += 1; av_mal = None
        else:
            av_mal = n_inf >= 1

        def tally(bucket, pred):
            if pred is None: return
            if is_mal and pred: bucket["tp"] += 1
            elif is_mal and not pred: bucket["fn"] += 1
            elif not is_mal and pred: bucket["fp"] += 1
            else: bucket["tn"] += 1
        tally(py, py_mal); tally(av, av_mal)
        if is_mal:
            tally(py_by_src[src], py_mal); tally(av_by_src[src], av_mal)
        per_sample.append({"package": p.name, "label": row["label"], "source": src,
                           "pyscan_malicious": bool(py_mal),
                           "clamav_malicious": None if av_mal is None else bool(av_mal),
                           "clamav_signatures": ";".join(info.get("signatures", []))})
        if i % 25 == 0:
            print(f"  {i}/{len(sample)} procesados...")

    py_m = _metrics(**py); av_m = _metrics(**av)
    print("\n== Resultados globales ==")
    print("| Detector | Recall | Precisión | F1 | FP |")
    print("|---|---|---|---|---|")
    print(f"| pyscan (ML) | {py_m['recall']:.3f} | {py_m['precision']:.3f} | "
          f"{py_m['f1']:.3f} | {py_m['false_positive_rate']:.3f} |")
    print(f"| ClamAV (firmas) | {av_m['recall']:.3f} | {av_m['precision']:.3f} | "
          f"{av_m['f1']:.3f} | {av_m['false_positive_rate']:.3f} |")
    if av_errors:
        print(f"\n(ClamAV no pudo analizar {av_errors} muestras; excluidas de su conteo.)")

    print("\n== Recall sobre malware por fuente ==")
    print("| Fuente | pyscan | ClamAV |")
    print("|---|---|---|")
    for s in sorted(set(list(py_by_src) + list(av_by_src))):
        pr = _metrics(**py_by_src[s])["recall"] if py_by_src[s] else 0
        ar = _metrics(**av_by_src[s])["recall"] if av_by_src[s] else 0
        print(f"| {s} | {pr:.3f} | {ar:.3f} |")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    report = {"n_samples": len(sample), "n_malicious": len(mal), "n_benign": len(ben),
              "clamav_errors": av_errors, "pyscan": py_m, "clamav": av_m,
              "recall_by_source": {
                  s: {"pyscan": _metrics(**py_by_src[s])["recall"] if py_by_src[s] else None,
                      "clamav": _metrics(**av_by_src[s])["recall"] if av_by_src[s] else None}
                  for s in sorted(set(list(py_by_src) + list(av_by_src)))}}
    (OUT_DIR / "compare_antivirus.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    with open(OUT_DIR / "compare_antivirus_per_sample.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["package", "label", "source",
                           "pyscan_malicious", "clamav_malicious", "clamav_signatures"])
        w.writeheader(); w.writerows(per_sample)
    print(f"\nDatos: {OUT_DIR/'compare_antivirus.json'} | {OUT_DIR/'compare_antivirus_per_sample.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
