#!/usr/bin/env python3
"""Benchmark de desempeño del escaneo (RNF04 tiempo, RNF05 memoria).

Mide, para un conjunto de paquetes, el tiempo de análisis y el pico de memoria
por paquete, y verifica los KPI del proyecto: tiempo <= 120 s/paquete y
RAM <= 2 GB. Puede medir sobre paquetes reales de PyPI (descargándolos) o sobre
muestras locales del dataset.

Metodología: para cada paquete se cronometra el análisis estático completo
(fetch/extracción + 3 extractores + feature builder + predicción si hay modelo)
y se mide el pico de memoria del proceso con tracemalloc y RSS. Se reportan
mínimo, mediana, media, p95 y máximo.

Uso:
    # sobre paquetes populares de PyPI (requiere red):
    python scripts/benchmark_performance.py --packages requests flask numpy rich typer
    # sobre una muestra local del dataset:
    python scripts/benchmark_performance.py --from-csv data/holdout.csv --limit 100
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pyscan import config  # noqa: E402
from pyscan.extractors import (ASTExtractor, EntropyExtractor,  # noqa: E402
                               MetadataExtractor)
from pyscan.features import build_features  # noqa: E402
from pyscan.fetcher import FetchError, fetch, safe_extract  # noqa: E402

OUT_DIR = config.DATA_DIR / "analysis"
ARCHIVE_EXTS = (".tar.gz", ".tgz", ".whl", ".zip", ".egg", ".tar")

try:
    import resource  # Unix
    def _rss_mb() -> float:
        # ru_maxrss en Linux está en KB.
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
except ImportError:  # pragma: no cover
    def _rss_mb() -> float:
        return 0.0


def _analyze_dir(name: str, root: Path, meta: MetadataExtractor) -> None:
    typo = meta.extract(name)
    entropy = EntropyExtractor().extract(root)
    ast_rep = ASTExtractor().extract(root)
    build_features(typosquat=typo, entropy=entropy, ast=ast_rep)


def _time_one(fn) -> tuple[float, float]:
    """Ejecuta fn(); devuelve (segundos, MB pico incrementales con tracemalloc)."""
    tracemalloc.start()
    t0 = time.perf_counter()
    fn()
    dt = time.perf_counter() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return dt, peak / (1024 * 1024)


def _iter_local(csv_path: Path, limit: int):
    with open(csv_path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    for row in rows[:limit] if limit else rows:
        p = ROOT / row["path"]
        yield p.name, p, row.get("kind", "archive")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--packages", nargs="*", default=[],
                    help="paquetes de PyPI a descargar y medir")
    ap.add_argument("--from-csv", type=Path, default=None,
                    help="mide sobre muestras locales de un manifiesto CSV")
    ap.add_argument("--limit", type=int, default=100)
    args = ap.parse_args()

    meta = MetadataExtractor()
    times, mems = [], []
    per_pkg = []
    rss_before = _rss_mb()

    if args.packages:
        import tempfile
        for name in args.packages:
            try:
                def run(name=name, tmp=None):
                    res = fetch(name)
                    _analyze_dir(res.package.name, res.extracted_path, meta)
                dt, peak = _time_one(run)
            except (FetchError, OSError) as exc:
                print(f"  [AVISO] {name}: {exc}", file=sys.stderr)
                continue
            times.append(dt); mems.append(peak)
            per_pkg.append({"package": name, "seg": round(dt, 3), "mem_mb": round(peak, 2)})
            print(f"  {name:<28} {dt:7.3f} s   pico {peak:7.1f} MB")
    elif args.from_csv:
        import tempfile
        for name, p, kind in _iter_local(args.from_csv, args.limit):
            if not p.exists():
                continue
            try:
                def run(p=p, kind=kind, name=name):
                    if kind == "dir":
                        _analyze_dir(name, p, meta)
                    else:
                        with tempfile.TemporaryDirectory(prefix="pyscan_bm_") as tmp:
                            ex = safe_extract(p, Path(tmp) / "x")
                            _analyze_dir(name, ex, meta)
                dt, peak = _time_one(run)
            except (FetchError, OSError) as exc:
                print(f"  [AVISO] {p.name}: {exc}", file=sys.stderr)
                continue
            times.append(dt); mems.append(peak)
            per_pkg.append({"package": name, "seg": round(dt, 3), "mem_mb": round(peak, 2)})
    else:
        print("Indica --packages <nombres> o --from-csv <manifiesto>.")
        return 1

    if not times:
        print("No se midió ningún paquete.")
        return 1

    rss_after = _rss_mb()
    def stats(v):
        return {"min": round(min(v), 3), "mediana": round(statistics.median(v), 3),
                "media": round(statistics.mean(v), 3),
                "p95": round(sorted(v)[int(len(v) * 0.95) - 1], 3) if len(v) > 1 else round(v[0], 3),
                "max": round(max(v), 3)}
    t_stats, m_stats = stats(times), stats(mems)

    report = {"n_paquetes": len(times),
              "tiempo_seg": t_stats, "memoria_pico_mb": m_stats,
              "rss_proceso_mb": {"antes": round(rss_before, 1), "despues": round(rss_after, 1)},
              "kpi": {
                  "tiempo_max_seg": t_stats["max"], "tiempo_limite_seg": 120,
                  "cumple_tiempo": t_stats["max"] <= 120,
                  "rss_max_mb": round(rss_after, 1), "rss_limite_mb": 2048,
                  "cumple_ram": rss_after <= 2048,
              }}

    print(f"\n== Resultados sobre {len(times)} paquetes ==")
    print(f"Tiempo (s):  mediana={t_stats['mediana']}  media={t_stats['media']}  "
          f"p95={t_stats['p95']}  max={t_stats['max']}")
    print(f"Memoria pico por análisis (MB):  mediana={m_stats['mediana']}  max={m_stats['max']}")
    print(f"RSS del proceso: {report['rss_proceso_mb']['despues']} MB")
    ok_t = "OK" if report["kpi"]["cumple_tiempo"] else "XX"
    ok_r = "OK" if report["kpi"]["cumple_ram"] else "XX"
    print(f"\nKPI: tiempo<=120s/paquete [{ok_t}] (max {t_stats['max']} s)  |  "
          f"RAM<=2GB [{ok_r}] (RSS {report['rss_proceso_mb']['despues']} MB)")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "benchmark.json").write_text(json.dumps(report, indent=2, ensure_ascii=False),
                                            encoding="utf-8")
    with open(OUT_DIR / "benchmark_per_package.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["package", "seg", "mem_mb"]); w.writeheader()
        w.writerows(per_pkg)
    print(f"\nDatos: {OUT_DIR/'benchmark.json'} | {OUT_DIR/'benchmark_per_package.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
