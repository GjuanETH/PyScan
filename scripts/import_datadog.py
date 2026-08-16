#!/usr/bin/env python3
"""Importa la parte PyPI del dataset de DataDog a data/malicious/datadog/.

DataDog guarda cada muestra como un ZIP cifrado (contraseña `infected`) bajo:
    <repo>/samples/pypi/{malicious_intent,compromised}/<pkg>/<ver>/<fecha>-<pkg>-v<ver>.zip

Este script recorre SOLO samples/pypi, descifra cada ZIP en
data/malicious/datadog/<pkg>-<ver>/ y deduplica por sha256 del ZIP. Nunca
ejecuta el código; solo descomprime para el análisis estático posterior.

Uso:
    python scripts/import_datadog.py --src <ruta_al_repo_DataDog> [--limit 3000]
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "data" / "malicious" / "datadog"
PASSWORD = b"infected"


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", required=True, type=Path,
                    help="ruta a la carpeta clonada del repo DataDog")
    ap.add_argument("--limit", type=int, default=0,
                    help="máximo de muestras a importar (0 = todas)")
    ap.add_argument("--only-intent", action="store_true",
                    help="importa solo 'malicious_intent' (excluye 'compromised')")
    args = ap.parse_args()

    pypi_dir = args.src / "samples" / "pypi"
    if not pypi_dir.is_dir():
        print(f"No existe {pypi_dir}. ¿La ruta --src apunta al repo DataDog?")
        return 1

    DEST.mkdir(parents=True, exist_ok=True)
    zips = sorted(pypi_dir.rglob("*.zip"))
    if args.only_intent:
        zips = [z for z in zips if "malicious_intent" in z.parts]

    seen: set[str] = set()
    imported = skipped = 0
    for z in zips:
        if args.limit and imported >= args.limit:
            break
        digest = sha256_of(z)
        if digest in seen:
            continue
        seen.add(digest)
        out = DEST / z.stem  # <fecha>-<pkg>-v<ver>
        if out.exists():
            skipped += 1
            continue
        try:
            with zipfile.ZipFile(z) as zf:
                zf.extractall(out, pwd=PASSWORD)
            imported += 1
            if imported % 200 == 0:
                print(f"  ... {imported} importados")
        except (RuntimeError, zipfile.BadZipFile) as exc:
            print(f"  [AVISO] no se pudo descifrar {z.name}: {exc}", file=sys.stderr)
            skipped += 1

    print(f"Importados: {imported} | ya existentes/omitidos: {skipped}")
    print(f"Destino: {DEST}")
    print("Siguiente: python scripts/build_dataset.py --max-malicious 2000 --ratio 2.0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
