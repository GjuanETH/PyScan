#!/usr/bin/env python3
"""Importador genérico de datasets de paquetes maliciosos al pipeline de pyscan.

Sirve para integrar nuevas fuentes (Backstabber's Knife Collection, MalOSS, etc.)
sin escribir un script por cada una. Copia/extrae las muestras a
data/<label>/<source>/, deduplicando por sha256. Nunca ejecuta el código: solo
descomprime para el análisis estático posterior.

Admite tres formas de muestra:
  - Archivos comprimidos sin contraseña (.tar.gz/.whl/.zip/.egg/.tar) -> se copian.
  - ZIP cifrados (p. ej. Backstabber's/DataDog, contraseña 'infected')  -> se
    descifran con --password.
  - Carpetas de código ya extraído (con --include-dirs)                -> se copian.

Ejemplos:
  # Backstabber's Knife Collection (zips cifrados), solo la parte de PyPI
  python scripts/import_dataset.py --src ~/datasets/backstabbers \\
      --source backstabbers --password infected --path-filter pypi

  # MalOSS (archivos o carpetas), solo PyPI
  python scripts/import_dataset.py --src ~/datasets/maloss \\
      --source maloss --path-filter pypi --include-dirs

Después:
  python scripts/build_dataset.py --split 0.2 --seed 42
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_EXTS = (".tar.gz", ".tgz", ".whl", ".zip", ".egg", ".tar")


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_archive(p: Path) -> bool:
    return p.is_file() and p.name.lower().endswith(ARCHIVE_EXTS)


def _looks_like_package_dir(d: Path) -> bool:
    """Carpeta hoja que contiene código Python (setup.py o algún .py)."""
    if not d.is_dir():
        return False
    return any(f.name == "setup.py" or f.suffix == ".py"
              for f in d.iterdir() if f.is_file())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", required=True, type=Path,
                    help="carpeta descargada/clonada de la fuente")
    ap.add_argument("--source", required=True,
                    help="nombre de la fuente (ej. backstabbers, maloss)")
    ap.add_argument("--label", default="malicious", choices=["malicious", "benign"])
    ap.add_argument("--password", default="",
                    help="contraseña para ZIP cifrados (ej. infected)")
    ap.add_argument("--path-filter", default="",
                    help="solo muestras cuya ruta contenga este texto (ej. pypi)")
    ap.add_argument("--include-dirs", action="store_true",
                    help="también importar carpetas de paquete ya extraído")
    ap.add_argument("--limit", type=int, default=0, help="máximo a importar (0=todas)")
    args = ap.parse_args()

    if not args.src.is_dir():
        print(f"No existe la carpeta --src: {args.src}")
        return 1

    dest = ROOT / "data" / args.label / args.source
    dest.mkdir(parents=True, exist_ok=True)
    pwd = args.password.encode() if args.password else None

    def match(p: Path) -> bool:
        return (not args.path_filter) or (args.path_filter.lower() in str(p).lower())

    seen: set[str] = set()
    imported = skipped = errors = 0

    # 1) Archivos comprimidos
    for p in sorted(args.src.rglob("*")):
        if args.limit and imported >= args.limit:
            break
        if not _is_archive(p) or not match(p):
            continue
        digest = sha256_of(p)
        if digest in seen:
            continue
        seen.add(digest)
        try:
            if p.suffix.lower() == ".zip" and pwd:
                out = dest / p.stem
                if out.exists():
                    skipped += 1; continue
                with zipfile.ZipFile(p) as zf:
                    zf.extractall(out, pwd=pwd)
            else:
                target = dest / p.name
                if target.exists():
                    skipped += 1; continue
                shutil.copy2(p, target)
            imported += 1
            if imported % 100 == 0:
                print(f"  ... {imported} importados")
        except (RuntimeError, zipfile.BadZipFile, tarfile.TarError, OSError) as exc:
            print(f"  [AVISO] {p.name}: {exc}", file=sys.stderr); errors += 1

    # 2) Carpetas de paquete (opcional)
    if args.include_dirs:
        for d in sorted(args.src.rglob("*")):
            if args.limit and imported >= args.limit:
                break
            if not _looks_like_package_dir(d) or not match(d):
                continue
            digest = hashlib.sha256(str(sorted(
                f.name for f in d.iterdir() if f.is_file())).encode()).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            target = dest / d.name
            if target.exists():
                skipped += 1; continue
            try:
                shutil.copytree(d, target)
                imported += 1
            except OSError as exc:
                print(f"  [AVISO] {d.name}: {exc}", file=sys.stderr); errors += 1

    print(f"\nFuente '{args.source}' -> {dest}")
    print(f"Importados: {imported} | omitidos (ya existían): {skipped} | errores: {errors}")
    print("Siguiente: python scripts/build_dataset.py --split 0.2 --seed 42")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
