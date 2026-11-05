#!/usr/bin/env python3
"""Benchmark de desempeño del escaneo (RNF04 tiempo, RNF05 memoria) — corrección 2.6.

Mide, por paquete y por etapa, el análisis COMPLETO tal como lo hace la CLI:
  descarga (solo con --packages) -> extracción segura -> 3 extractores +
  Feature Builder -> inferencia del modelo.
Se procesa un paquete a la vez (sin concurrencia) y sin caché de características.

Memoria (dos medidas distintas, con su herramienta):
  - pico_python_mb: pico de memoria asignada por Python durante UN análisis
    (tracemalloc). No incluye bibliotecas nativas ni el modelo ya cargado.
  - rss_pico_proceso_mb: pico de memoria residente de TODO el proceso, con el
    modelo cargado (resource.getrusage ru_maxrss, en Linux).
Cada paquete que falla queda registrado con su motivo (no se descarta en silencio).

Uso:
    python scripts/benchmark_performance.py --from-csv data/holdout_grouped.csv --limit 100
    python scripts/benchmark_performance.py --packages requests flask numpy rich typer
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import platform
import statistics
import sys
import tempfile
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from pyscan import config  # noqa: E402
from pyscan.classifier import ModelNotAvailable, load_bundle, predict  # noqa: E402
from pyscan.extractors import ASTExtractor, EntropyExtractor, MetadataExtractor  # noqa: E402
from pyscan.features import build_features  # noqa: E402
from pyscan.fetcher import fetch, safe_extract  # noqa: E402
import train_model as tm  # noqa: E402

OUT_DIR = config.DATA_DIR / "analysis"

try:
    import resource  # Unix

    def _rss_peak_mb() -> float:
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0  # Linux: KB
except ImportError:  # pragma: no cover
    def _rss_peak_mb() -> float:
        return 0.0


def environment() -> dict:
    cpu = None
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    ram = None
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal"):
                ram = round(int(line.split()[1]) / 1024 / 1024, 2)
                break
    except OSError:
        pass
    os_name = platform.platform()
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                os_name = line.split("=", 1)[1].strip('"')
    except OSError:
        pass
    return {"cpu": cpu or platform.processor(), "nucleos_logicos": os.cpu_count(),
            "ram_total_gb": ram, "sistema_operativo": os_name,
            "versiones": tm.lib_versions(), "concurrencia": "secuencial (1 paquete a la vez)",
            "cache_caracteristicas": "desactivada", "fecha": datetime.now(timezone.utc).isoformat(),
            "git_commit": tm.git_commit()}


def _features(name: str, root: Path, meta: MetadataExtractor):
    typo = meta.extract(name)
    return build_features(typosquat=typo, entropy=EntropyExtractor().extract(root),
                          ast=ASTExtractor().extract(root))


def _run(stage_fn) -> tuple[dict, float]:
    """Ejecuta una función que devuelve tiempos por etapa; mide el pico Python."""
    tracemalloc.start()
    stages = stage_fn()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return stages, peak / (1024 * 1024)


def _stats(v: list[float]) -> dict:
    s = sorted(v)
    return {"min": round(s[0], 3), "mediana": round(statistics.median(s), 3),
            "media": round(statistics.mean(s), 3),
            "p95": round(s[max(0, math.ceil(0.95 * len(s)) - 1)], 3), "max": round(s[-1], 3)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--packages", nargs="*", default=[], help="paquetes de PyPI (con descarga)")
    ap.add_argument("--from-csv", type=Path, default=None, help="muestras locales de un manifiesto")
    ap.add_argument("--limit", type=int, default=100)
    args = ap.parse_args()

    env = environment()
    rss_inicio = _rss_peak_mb()
    try:
        bundle = load_bundle()
    except ModelNotAvailable as exc:
        print(f"Sin modelo: {exc}")
        return 1
    rss_con_modelo = _rss_peak_mb()
    meta = MetadataExtractor()
    ok, fails = [], []

    def record(name, stages, peak):
        stages = {k: round(v, 4) for k, v in stages.items()}
        stages["total"] = round(sum(stages.values()), 4)
        ok.append({"package": name, **stages, "pico_python_mb": round(peak, 2)})

    targets = []
    if args.packages:
        targets = [("pypi", n, None, None) for n in args.packages]
    elif args.from_csv:
        with open(args.from_csv, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        rows = rows[: args.limit] if args.limit else rows
        targets = [("local", Path(r["path"]).name, ROOT / r["path"], r.get("kind", "archive"))
                   for r in rows]
    else:
        print("Indica --packages <nombres> o --from-csv <manifiesto>.")
        return 1

    for origin, name, path, kind in targets:
        def stage_fn(origin=origin, name=name, path=path, kind=kind):
            t = {}
            with tempfile.TemporaryDirectory(prefix="pyscan_bm_") as tmp:
                t0 = time.perf_counter()
                if origin == "pypi":
                    res = fetch(name, workdir=Path(tmp))
                    t["descarga_y_extraccion"] = time.perf_counter() - t0
                    root, pname = res.extracted_path, res.package.name
                elif kind == "dir":
                    root, pname = path, name
                    t["extraccion"] = 0.0
                else:
                    root = safe_extract(path, Path(tmp) / "x")
                    t["extraccion"] = time.perf_counter() - t0
                    pname = tm._package_name_from_file(path)
                t1 = time.perf_counter()
                fv = _features(pname, root, meta)
                t["caracteristicas"] = time.perf_counter() - t1
                t2 = time.perf_counter()
                predict(fv, bundle=bundle)
                t["inferencia"] = time.perf_counter() - t2
            return t
        try:
            if origin == "local" and not path.exists():
                raise FileNotFoundError("el archivo no existe en disco")
            stages, peak = _run(stage_fn)
            record(name, stages, peak)
        except Exception as exc:  # noqa: BLE001 - se registra el motivo
            if tracemalloc.is_tracing():
                tracemalloc.stop()
            fails.append({"package": name, "motivo": tm.classify_exclusion(f"{exc}"),
                          "error": f"{type(exc).__name__}: {exc}"[:300]})
            print(f"  [FALLÓ] {name}: {type(exc).__name__}: {exc}", file=sys.stderr)

    if not ok:
        print("No se midió ningún paquete.")
        return 1
    rss_final = _rss_peak_mb()
    stage_names = [k for k in ok[0] if k not in ("package", "pico_python_mb")]
    report = {
        "entorno": env,
        "n_intentados": len(targets), "n_procesados": len(ok), "n_fallidos": len(fails),
        "fallos": fails,
        "tiempo_seg_por_etapa": {s: _stats([r[s] for r in ok]) for s in stage_names},
        "pico_python_mb": _stats([r["pico_python_mb"] for r in ok]),
        "rss_pico_proceso_mb": {"inicio": round(rss_inicio, 1),
                                "con_modelo_cargado": round(rss_con_modelo, 1),
                                "final": round(rss_final, 1)},
        "herramientas_memoria": {"pico_python_mb": "tracemalloc (por análisis)",
                                 "rss_pico_proceso_mb": "resource.getrusage ru_maxrss"},
    }
    tot = report["tiempo_seg_por_etapa"]["total"]
    report["kpi"] = {"tiempo_max_seg": tot["max"], "tiempo_limite_seg": 120,
                     "cumple_tiempo": tot["max"] <= 120, "rss_max_mb": round(rss_final, 1),
                     "rss_limite_mb": 2048, "cumple_ram": rss_final <= 2048}

    print(f"\n== {len(ok)} de {len(targets)} paquetes procesados ({len(fails)} fallidos) ==")
    for s, st in report["tiempo_seg_por_etapa"].items():
        print(f"  {s:<24} mediana={st['mediana']}  media={st['media']}  p95={st['p95']}  "
              f"max={st['max']}")
    print(f"  Pico Python por análisis (MB): mediana={report['pico_python_mb']['mediana']} "
          f"max={report['pico_python_mb']['max']}")
    print(f"  RSS pico del proceso (MB): con modelo={report['rss_pico_proceso_mb']['con_modelo_cargado']}"
          f"  final={report['rss_pico_proceso_mb']['final']}")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "benchmark.json").write_text(json.dumps(report, indent=2, ensure_ascii=False),
                                            encoding="utf-8")
    with open(OUT_DIR / "benchmark_per_package.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["package"] + stage_names + ["pico_python_mb"])
        w.writeheader()
        w.writerows(ok)
    print(f"\nDatos: {OUT_DIR/'benchmark.json'} | {OUT_DIR/'benchmark_per_package.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
