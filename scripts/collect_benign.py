#!/usr/bin/env python3
"""Recolecta paquetes benignos del Top de PyPI para el dataset de entrenamiento.

Descarga, para cada paquete de una lista de nombres, su sdist desde PyPI y lo
guarda en data/benign/. Usa el Fetcher seguro del MVP (extracción anti Zip Slip).

Uso:
    python scripts/collect_benign.py --limit 500
    python scripts/collect_benign.py --names-file data/top_pypi_packages.txt --limit 2000

La lista de nombres se toma (en este orden):
  1) --names-file si se indica,
  2) data/top_pypi_packages.txt si existe,
  3) la semilla embebida en el extractor de metadatos.

Para obtener la lista COMPLETA del Top de PyPI (recomendado), en una máquina con
acceso a internet sin restricciones ejecutar antes:
    python scripts/fetch_top_pypi.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import requests  # noqa: E402

from pyscan import config  # noqa: E402
from pyscan.extractors.metadata import _SEED_PACKAGES, _load_reference_names  # noqa: E402
from pyscan.fetcher import FetchError, download_archive, get_pypi_json, parse_metadata  # noqa: E402


def load_names(names_file: str | None, limit: int) -> list[str]:
    if names_file:
        p = Path(names_file)
        names = [l.strip().lower() for l in p.read_text(encoding="utf-8").splitlines()
                 if l.strip() and not l.startswith("#")]
    else:
        names = list(_load_reference_names()) or list(_SEED_PACKAGES)
    return names[:limit]


def main() -> int:
    ap = argparse.ArgumentParser(description="Recolector de paquetes benignos de PyPI.")
    ap.add_argument("--names-file", default=None)
    ap.add_argument("--limit", type=int, default=500)
    ap.add_argument("--out", default=str(config.BENIGN_DIR))
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    names = load_names(args.names_file, args.limit)
    print(f"Descargando {len(names)} paquetes benignos -> {out_dir}")

    session = requests.Session()
    ok = fail = 0
    manifest = out_dir / "manifest.csv"
    with open(manifest, "w", encoding="utf-8") as mf:
        mf.write("name,version,sha256,file,label\n")
        for i, name in enumerate(names, 1):
            try:
                data = get_pypi_json(name, session=session)
                package, _, file_desc = parse_metadata(data)
                url = file_desc.get("url")
                if not url:
                    raise FetchError("sin sdist")
                pkg_dir = out_dir / f"{package.name}-{package.version}"
                path, digest = download_archive(url, pkg_dir, session=session)
                mf.write(f"{package.name},{package.version},{digest},{path.name},benign\n")
                ok += 1
                if i % 25 == 0:
                    print(f"  {i}/{len(names)} ok={ok} fail={fail}")
            except (FetchError, Exception) as exc:  # noqa: BLE001
                fail += 1
                print(f"  [skip] {name}: {exc}", file=sys.stderr)
    print(f"Listo. ok={ok} fail={fail}. Manifiesto: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
