#!/usr/bin/env python3
"""Comparación de pyscan frente a ~60-70 antivirus a la vez (VirusTotal).

Extiende el experimento de ClamAV: en lugar de un solo motor, consulta la API
de VirusTotal, que agrega decenas de motores antivirus comerciales. Para cada
muestra del hold-out se calcula el sha256 y se consulta por hash (NO se suben
archivos): más privado y rápido. Se reportan Recall, Precisión, F1 y falsos
positivos de pyscan frente al agregado de VirusTotal, más el Recall por motor
individual de los antivirus más conocidos.

Motivación (observación del director): comparar la efectividad frente a varios
antivirus, no solo uno. Nota metodológica: los antivirus detectan por firmas de
malware tradicional; muchas muestras de la cadena de suministro de PyPI no están
en sus bases, por lo que se espera un Recall agregado bajo. Ese resultado
evidencia la necesidad de una herramienta especializada como pyscan.

Decisión de cada detector:
  - pyscan: veredicto del clasificador supervisado.
  - VirusTotal (agregado): malicioso si al menos --min-detections motores marcan
    el hash (por defecto 2, para no contar una única falsa alarma aislada).
  - Para carpetas de código (kind=dir), se consulta el hash de cada archivo
    (hasta --max-files) y se marca la muestra si algún archivo es detectado,
    igual que hace ClamAV recursivamente.

Requisitos:
  - API key gratuita de VirusTotal (https://www.virustotal.com/gui/join-us).
    Ponla en la variable de entorno VT_API_KEY, o pásala con --api-key.
  - La API gratuita permite ~4 consultas/minuto y 500/día; por eso el muestreo
    por clase es pequeño (--limit-per-class 40 por defecto) y hay un límite de
    velocidad configurable (--qpm).

Uso:
    export VT_API_KEY=tu_clave
    python scripts/experiment_compare_virustotal.py --limit-per-class 40

Las muestras NO se suben: solo se consulta el hash sha256. Si un hash no está en
VirusTotal, se cuenta como "no detectado" (medida conservadora).
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import requests  # noqa: E402

from pyscan import config  # noqa: E402
from pyscan.classifier import load_bundle, predict  # noqa: E402
from pyscan.models import FeatureVector, Verdict  # noqa: E402
import train_model as tm  # noqa: E402
from build_dataset import sha256_of_file  # noqa: E402

OUT_DIR = config.DATA_DIR / "analysis"
VT_URL = "https://www.virustotal.com/api/v3/files/{}"
CODE_EXTS = (".py", ".pyi", ".sh", ".js", ".txt", ".cfg", ".toml", ".json", ".md")


def _metrics(tp, fp, tn, fn) -> dict:
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {"recall": round(recall, 4), "precision": round(precision, 4),
            "f1": round(f1, 4), "false_positive_rate": round(fpr, 4),
            "tp": tp, "fp": fp, "tn": tn, "fn": fn}


class VTClient:
    """Consulta por hash con caché en memoria y control de velocidad."""

    def __init__(self, api_key: str, qpm: int):
        self.key = api_key
        self.delay = max(0.0, 60.0 / max(1, qpm))
        self.cache: dict[str, dict] = {}
        self._last = 0.0
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": api_key})

    def _throttle(self):
        wait = self.delay - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.time()

    def lookup(self, sha256: str) -> dict:
        """Devuelve {found, malicious, engines:[..]} para un hash."""
        if sha256 in self.cache:
            return self.cache[sha256]
        for attempt in range(4):
            self._throttle()
            try:
                r = self.session.get(VT_URL.format(sha256), timeout=30)
            except requests.RequestException:
                time.sleep(2); continue
            if r.status_code == 404:
                out = {"found": False, "malicious": 0, "engines": []}
                self.cache[sha256] = out; return out
            if r.status_code == 401:
                raise SystemExit("VT_API_KEY inválida o ausente (401). Revisa tu clave.")
            if r.status_code == 429:  # rate limit: espera y reintenta
                time.sleep(30); continue
            if r.status_code != 200:
                time.sleep(3); continue
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            results = data.get("last_analysis_results", {})
            engines = [e for e, v in results.items()
                       if v.get("category") == "malicious"]
            out = {"found": True, "malicious": int(stats.get("malicious", 0)),
                   "engines": engines}
            self.cache[sha256] = out; return out
        out = {"found": False, "malicious": 0, "engines": []}  # tras reintentos
        self.cache[sha256] = out; return out


def _sample_hashes(path: Path, kind: str, max_files: int) -> list[str]:
    """Hashes a consultar para una muestra: 1 si es archivo, varios si es carpeta."""
    if kind == "archive" or path.is_file():
        return [sha256_of_file(path)]
    files = [f for f in path.rglob("*") if f.is_file()]
    # prioriza código y archivos grandes (donde suele ir la carga maliciosa)
    files.sort(key=lambda f: (f.suffix.lower() in CODE_EXTS,
                              f.stat().st_size if f.exists() else 0), reverse=True)
    return [sha256_of_file(f) for f in files[:max_files]]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--limit-per-class", type=int, default=40)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--from-csv", type=Path, default=None)
    ap.add_argument("--api-key", default="", help="clave VT (si no usas VT_API_KEY)")
    ap.add_argument("--qpm", type=int, default=4, help="consultas por minuto (free=4)")
    ap.add_argument("--min-detections", type=int, default=2,
                    help="motores que deben marcar el hash para contarlo malicioso")
    ap.add_argument("--max-files", type=int, default=6,
                    help="máx. archivos a consultar por carpeta")
    args = ap.parse_args()

    api_key = args.api_key or os.environ.get("VT_API_KEY", "")
    if not api_key:
        print("Falta la clave de VirusTotal. Exporta VT_API_KEY o usa --api-key.\n"
              "Consíguela gratis en https://www.virustotal.com/gui/join-us")
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
          f"({len(mal)} maliciosas, {len(ben)} benignas)")
    print(f"VirusTotal: ~{args.qpm} consultas/min. Puede tardar varios minutos.\n")

    bundle = load_bundle()
    meta = tm.MetadataExtractor()
    vt = VTClient(api_key, args.qpm)

    def zero(): return {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    py = zero(); av = zero()
    av_by_src = defaultdict(zero); py_by_src = defaultdict(zero)
    engine_hits: dict[str, int] = defaultdict(int)   # motor -> maliciosos detectados
    n_found = 0; n_mal_analyzed = 0
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
        # VirusTotal (agregado por hash)
        best_mal = 0; best_engines: list[str] = []; found_any = False
        for h in _sample_hashes(p, kind, args.max_files):
            res = vt.lookup(h)
            found_any = found_any or res["found"]
            if res["malicious"] > best_mal:
                best_mal = res["malicious"]; best_engines = res["engines"]
        av_mal = best_mal >= args.min_detections
        if found_any:
            n_found += 1
        if is_mal:
            n_mal_analyzed += 1
            for e in best_engines:
                engine_hits[e] += 1

        def tally(bucket, pred):
            if is_mal and pred: bucket["tp"] += 1
            elif is_mal and not pred: bucket["fn"] += 1
            elif not is_mal and pred: bucket["fp"] += 1
            else: bucket["tn"] += 1
        tally(py, py_mal); tally(av, av_mal)
        if is_mal:
            tally(py_by_src[src], py_mal); tally(av_by_src[src], av_mal)
        per_sample.append({"package": p.name, "label": row["label"], "source": src,
                           "pyscan_malicious": bool(py_mal),
                           "vt_detections": best_mal,
                           "vt_malicious": bool(av_mal),
                           "vt_top_engines": ";".join(sorted(best_engines)[:5])})
        if i % 10 == 0:
            print(f"  {i}/{len(sample)} procesados... (hashes vistos en VT: {n_found})")

    py_m = _metrics(**py); av_m = _metrics(**av)
    print("\n== Resultados globales ==")
    print("| Detector | Recall | Precisión | F1 | FP |")
    print("|---|---|---|---|---|")
    print(f"| pyscan (ML) | {py_m['recall']:.3f} | {py_m['precision']:.3f} | "
          f"{py_m['f1']:.3f} | {py_m['false_positive_rate']:.3f} |")
    print(f"| VirusTotal (agregado, >={args.min_detections}) | {av_m['recall']:.3f} | "
          f"{av_m['precision']:.3f} | {av_m['f1']:.3f} | {av_m['false_positive_rate']:.3f} |")
    print(f"\nHashes hallados en VirusTotal: {n_found}/{len(sample)}")

    # Recall por motor individual (sobre el malware analizado)
    top_engines = sorted(engine_hits.items(), key=lambda x: -x[1])[:10]
    engines_report = {e: {"malware_detectado": n,
                          "recall": round(n / n_mal_analyzed, 4) if n_mal_analyzed else 0.0}
                      for e, n in top_engines}
    if top_engines:
        print("\n== Motores que más malware detectaron (Recall individual) ==")
        print("| Motor | Recall |")
        print("|---|---|")
        for e, n in top_engines:
            print(f"| {e} | {n/n_mal_analyzed:.3f} |" if n_mal_analyzed else f"| {e} | - |")

    print("\n== Recall sobre malware por fuente ==")
    print("| Fuente | pyscan | VirusTotal |")
    print("|---|---|---|")
    for s in sorted(set(list(py_by_src) + list(av_by_src))):
        pr = _metrics(**py_by_src[s])["recall"] if py_by_src[s] else 0
        ar = _metrics(**av_by_src[s])["recall"] if av_by_src[s] else 0
        print(f"| {s} | {pr:.3f} | {ar:.3f} |")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    report = {"n_samples": len(sample), "n_malicious": len(mal), "n_benign": len(ben),
              "min_detections": args.min_detections, "vt_hashes_found": n_found,
              "pyscan": py_m, "virustotal": av_m,
              "engines_top": engines_report,
              "recall_by_source": {
                  s: {"pyscan": _metrics(**py_by_src[s])["recall"] if py_by_src[s] else None,
                      "virustotal": _metrics(**av_by_src[s])["recall"] if av_by_src[s] else None}
                  for s in sorted(set(list(py_by_src) + list(av_by_src)))}}
    (OUT_DIR / "compare_virustotal.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    with open(OUT_DIR / "compare_virustotal_per_sample.csv", "w", newline="",
              encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["package", "label", "source",
                           "pyscan_malicious", "vt_detections", "vt_malicious",
                           "vt_top_engines"])
        w.writeheader(); w.writerows(per_sample)
    print(f"\nDatos: {OUT_DIR/'compare_virustotal.json'} | "
          f"{OUT_DIR/'compare_virustotal_per_sample.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
