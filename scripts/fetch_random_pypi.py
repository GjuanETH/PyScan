#!/usr/bin/env python3
"""Muestra nombres ALEATORIOS del índice completo de PyPI para la segunda fuente
benigna del dataset. Reduce el sesgo de popularidad del Top de PyPI.

Descarga el índice simple de PyPI (lista de todos los proyectos) y toma una
muestra aleatoria reproducible (semilla fija). Guarda los nombres en un archivo
que luego consume collect_benign.py.

Uso:
    python scripts/fetch_random_pypi.py --limit 1000 --seed 42
    # luego, para descargarlos como fuente 'pypi_random':
    python scripts/collect_benign.py --names-file data/random_pypi_names.txt \\
        --out data/benign/pypi_random --limit 1000

Nota: requiere acceso a pypi.org. Si tu entorno lo bloquea, ejecútalo en una
máquina sin restricciones y versiona el .txt resultante.
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

import requests

SIMPLE_URL = "https://pypi.org/simple/"
OUT = Path(__file__).resolve().parents[1] / "data" / "random_pypi_names.txt"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--limit", type=int, default=1000, help="tamaño de la muestra")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()

    print(f"Descargando el índice de PyPI desde {SIMPLE_URL} ...")
    try:
        resp = requests.get(
            SIMPLE_URL,
            headers={"Accept": "application/vnd.pypi.simple.v1+json"},
            timeout=60)
        resp.raise_for_status()
    except requests.RequestException as exc:
        print(f"ERROR: no se pudo descargar el índice: {exc}", file=sys.stderr)
        print("Sugerencia: ejecútalo en una máquina sin restricciones de red.",
              file=sys.stderr)
        return 1

    names = [p["name"] for p in resp.json().get("projects", []) if p.get("name")]
    if not names:
        print("El índice llegó vacío o en un formato inesperado.", file=sys.stderr)
        return 1

    rng = random.Random(args.seed)
    sample = rng.sample(names, min(args.limit, len(names)))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(sorted(sample)) + "\n", encoding="utf-8")
    print(f"Universo de proyectos en PyPI: {len(names):,}")
    print(f"Muestra aleatoria (seed={args.seed}): {len(sample)} nombres -> {out}")
    print("Siguiente: collect_benign.py --names-file "
          f"{out} --out data/benign/pypi_random --limit {args.limit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
