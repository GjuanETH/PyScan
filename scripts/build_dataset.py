#!/usr/bin/env python3
"""Unifica, deduplica y divide el dataset (benignos + maliciosos).

Recorre data/benign/ y data/malicious/ buscando artefactos (.tar.gz/.whl/.zip),
calcula su sha256, construye un manifiesto unificado, elimina duplicados por hash
y separa en train/hold-out (por defecto 80/20, estratificado por clase).

Uso:
    python scripts/build_dataset.py --split 0.2 --seed 42
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
ARCHIVE_EXTS = (".tar.gz", ".tgz", ".whl", ".zip", ".egg")


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def collect(label_dir: Path, label: str) -> list[dict]:
    rows = []
    if not label_dir.exists():
        return rows
    for p in label_dir.rglob("*"):
        if p.is_file() and p.name.lower().endswith(ARCHIVE_EXTS):
            rows.append({"path": str(p.relative_to(ROOT)), "label": label,
                         "sha256": sha256_of(p)})
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", type=float, default=0.2, help="proporción de hold-out")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rows = collect(DATA / "benign", "benign") + collect(DATA / "malicious", "malicious")
    if not rows:
        print("No se encontraron artefactos en data/benign ni data/malicious.")
        print("Ejecuta primero collect_benign.py y descarga los maliciosos (ver docs/DATASET.md).")
        return 1

    # Deduplicar por sha256.
    seen, unique = set(), []
    for r in rows:
        if r["sha256"] not in seen:
            seen.add(r["sha256"])
            unique.append(r)

    n_mal = sum(r["label"] == "malicious" for r in unique)
    n_ben = sum(r["label"] == "benign" for r in unique)
    print(f"Artefactos: {len(rows)} | únicos: {len(unique)} | "
          f"maliciosos={n_mal} benignos={n_ben}")

    # División estratificada por clase.
    rng = random.Random(args.seed)
    train, holdout = [], []
    for label in ("benign", "malicious"):
        items = [r for r in unique if r["label"] == label]
        rng.shuffle(items)
        cut = int(len(items) * (1 - args.split))
        train += items[:cut]
        holdout += items[cut:]

    out_dir = DATA
    for name, subset in (("train.csv", train), ("holdout.csv", holdout),
                         ("dataset.csv", unique)):
        with open(out_dir / name, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["path", "label", "sha256"])
            w.writeheader()
            w.writerows(subset)
    print(f"Escritos: dataset.csv ({len(unique)}), train.csv ({len(train)}), "
          f"holdout.csv ({len(holdout)}) en {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
