#!/usr/bin/env python3
"""Descarga la lista del Top de PyPI por número de descargas y la guarda en
data/top_pypi_packages.txt (un nombre por línea).

Fuente: proyecto hugovk/top-pypi-packages (datos derivados de BigQuery).
NOTA: requiere acceso a github.io / GitHub. Si tu entorno los bloquea, ejecútalo
en tu máquina local y versiona el .txt resultante.

Uso:
    python scripts/fetch_top_pypi.py --limit 5000
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import requests

URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
OUT = Path(__file__).resolve().parents[1] / "data" / "top_pypi_packages.txt"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=5000)
    ap.add_argument("--url", default=URL)
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()

    print(f"Descargando lista desde {args.url}")
    try:
        resp = requests.get(args.url, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as exc:
        print(f"ERROR: no se pudo descargar la lista: {exc}", file=sys.stderr)
        print("Sugerencia: ejecuta este script en una máquina sin restricciones de red.",
              file=sys.stderr)
        return 1

    data = resp.json()
    rows = data.get("rows", data) if isinstance(data, dict) else data
    names = [r.get("project") or r.get("name") for r in rows][: args.limit]
    names = [n for n in names if n]

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(names) + "\n", encoding="utf-8")
    print(f"Guardados {len(names)} nombres en {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
