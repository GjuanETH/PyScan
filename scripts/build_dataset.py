#!/usr/bin/env python3
"""Unifica, deduplica y divide el dataset (benignos + maliciosos).

Acepta DOS formatos de muestra, para poder combinar varias fuentes:
  1. Artefactos comprimidos (.tar.gz/.whl/.zip/.egg)  -> típico de benignos
     recolectados de PyPI y de PyPI Malregistry.
  2. Carpetas de código ya extraído (una carpeta = una muestra)  -> típico de
     DataDog tras descifrar los ZIP (contraseña `infected`).

Recorre data/benign/ y data/malicious/ (o las rutas indicadas), calcula el
sha256 de cada muestra, deduplica, y separa en train/hold-out estratificado
por clase. Registra la fuente de cada muestra para auditar el balance.

Uso:
    python scripts/build_dataset.py --split 0.2 --seed 42
    python scripts/build_dataset.py --max-malicious 2000 --ratio 2.0
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
ARCHIVE_EXTS = (".tar.gz", ".tgz", ".whl", ".zip", ".egg", ".tar")


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_of_dir(path: Path) -> str:
    """Hash reproducible del contenido de una carpeta (rutas + bytes)."""
    h = hashlib.sha256()
    for p in sorted(path.rglob("*")):
        if p.is_file():
            h.update(p.relative_to(path).as_posix().encode("utf-8"))
            try:
                h.update(p.read_bytes())
            except OSError:
                continue
    return h.hexdigest()


def _is_archive(p: Path) -> bool:
    return p.is_file() and p.name.lower().endswith(ARCHIVE_EXTS)


def _leaf_package_dirs(base: Path):
    """Carpetas 'hoja' que contienen .py: cada una es una muestra de código."""
    for d in base.rglob("*"):
        if d.is_dir() and any(f.suffix == ".py" for f in d.iterdir() if f.is_file()):
            # Evita anidar: si un subdirectorio también tiene .py, se toma el
            # más externo que agrupe el paquete (raíz del paquete extraído).
            yield d


def collect(label_dir: Path, label: str) -> list[dict]:
    rows: list[dict] = []
    if not label_dir.exists():
        return rows
    seen_dirs: set[Path] = set()

    # (1) Artefactos comprimidos.
    for p in label_dir.rglob("*"):
        if _is_archive(p):
            rows.append({"path": str(p.relative_to(ROOT)), "kind": "archive",
                         "label": label, "source": _source_of(p, label_dir),
                         "sha256": sha256_of_file(p)})

    # (2) Carpetas de código extraído (solo si no hay artefactos que las cubran).
    for d in _leaf_package_dirs(label_dir):
        # Salta si ya se contó como parte de una carpeta padre.
        if any(parent in seen_dirs for parent in d.parents):
            continue
        seen_dirs.add(d)
        rows.append({"path": str(d.relative_to(ROOT)), "kind": "dir",
                     "label": label, "source": _source_of(d, label_dir),
                     "sha256": sha256_of_dir(d)})
    return rows


def _source_of(p: Path, label_dir: Path) -> str:
    """Primer segmento bajo data/<label>/ = nombre de la fuente (datadog, ...)."""
    try:
        rel = p.relative_to(label_dir)
        return rel.parts[0] if len(rel.parts) > 1 else "root"
    except ValueError:
        return "root"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--split", type=float, default=0.2, help="proporción de hold-out")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--max-malicious", type=int, default=0,
                    help="submuestrea maliciosos a este máximo (0 = sin límite)")
    ap.add_argument("--ratio", type=float, default=0.0,
                    help="benignos por cada malicioso (0 = usar todos)")
    args = ap.parse_args()

    rows = collect(DATA / "benign", "benign") + collect(DATA / "malicious", "malicious")
    if not rows:
        print("No se encontraron muestras en data/benign ni data/malicious.")
        print("Ejecuta collect_benign.py e importa maliciosos (ver docs/DATASET.md).")
        return 1

    # Deduplicar por sha256 (misma muestra en varias fuentes = una sola).
    seen, unique = set(), []
    for r in rows:
        if r["sha256"] not in seen:
            seen.add(r["sha256"])
            unique.append(r)

    rng = random.Random(args.seed)
    mal = [r for r in unique if r["label"] == "malicious"]
    ben = [r for r in unique if r["label"] == "benign"]
    rng.shuffle(mal); rng.shuffle(ben)

    if args.max_malicious and len(mal) > args.max_malicious:
        mal = mal[:args.max_malicious]
    if args.ratio and args.ratio > 0:
        ben = ben[:int(len(mal) * args.ratio)]

    kept = mal + ben
    print(f"Muestras crudas: {len(rows)} | únicas: {len(unique)} | "
          f"usadas: {len(kept)} (maliciosas={len(mal)} benignas={len(ben)})")

    # Conteo por fuente (auditoría de diversidad, va al paper).
    by_source: dict[str, int] = {}
    for r in kept:
        by_source[f"{r['label']}/{r['source']}"] = by_source.get(
            f"{r['label']}/{r['source']}", 0) + 1
    for k in sorted(by_source):
        print(f"  {k}: {by_source[k]}")

    # División estratificada por clase.
    train, holdout = [], []
    for subset in (mal, ben):
        cut = int(len(subset) * (1 - args.split))
        train += subset[:cut]
        holdout += subset[cut:]
    rng.shuffle(train); rng.shuffle(holdout)

    fields = ["path", "kind", "label", "source", "sha256"]
    for name, subset in (("train.csv", train), ("holdout.csv", holdout),
                         ("dataset.csv", kept)):
        with open(DATA / name, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields)
            w.writeheader()
            w.writerows(subset)
    print(f"Escritos: dataset.csv ({len(kept)}), train.csv ({len(train)}), "
          f"holdout.csv ({len(holdout)}) en {DATA}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
