#!/usr/bin/env python3
"""Auditoría de independencia entre entrenamiento y hold-out (corrección 1.1).

La deduplicación de build_dataset.py es por sha256 del ARCHIVO (tar.gz/zip o
carpeta). El mismo código puede llegar en otro empaquetado, en otra versión o en
otro paquete de la misma campaña. Este script mide ese riesgo y, si hace falta,
rehace la partición por grupos.

Pasos:
  1. Huella por archivo .py normalizado: sha256(ast.unparse(ast.parse(src))),
     que quita comentarios y formato. Se ignoran archivos triviales (< 64
     caracteres normalizados, p. ej. __init__.py vacíos).
  2. La huella del paquete es el CONJUNTO de huellas de sus archivos.
  3. Relaciones entre muestras: mismo nombre normalizado (PEP 503) con la misma
     u otra versión, conjunto de huellas idéntico y Jaccard >= 0,8.
  4. Componentes conexos (union-find) -> group_id.
  5. Informe de cruces entrenamiento <-> hold-out por tipo, clase y fuente.
  6. Siempre escribe data/train_grouped.csv y data/holdout_grouped.csv (con
     group_id). Con --resplit ningún grupo queda a ambos lados: "minimo" mueve
     al entrenamiento solo los grupos compartidos; "completo" rehace el 80/20 con
     StratifiedGroupKFold.

NUNCA ejecuta el código: solo lo descomprime de forma segura y lo parsea.

Uso:
    python scripts/audit_independence.py               # informe + group_id
    python scripts/audit_independence.py --resplit minimo     # saca del hold-out lo emparentado
    python scripts/audit_independence.py --resplit completo   # rehace el 80/20 por grupos
Luego, en config.yaml -> manifests: data/train_grouped.csv / data/holdout_grouped.csv
"""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import math
import sys
import tempfile
import warnings
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from pyscan.fetcher import safe_extract  # noqa: E402
import train_model as tm  # noqa: E402

FP_CACHE = ROOT / "data" / "fingerprints.jsonl"
OUT_JSON = ROOT / "data" / "analysis" / "independence_audit.json"
OUT_PAIRS = ROOT / "data" / "analysis" / "independence_pairs.csv"
MIN_CHARS = 64
JACCARD_T = 0.8


normalize_name = tm.normalize_name


def name_version(path: str) -> tuple[str, str]:
    """Identidad (nombre PEP 503, versión) de la muestra; misma regla que el entrenamiento."""
    return tm.sample_identity(path)


def huella_py(src: str) -> str | None:
    """Huella de un .py normalizado (sin comentarios ni formato); None si es trivial."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            norm = ast.unparse(ast.parse(src))
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        norm = " ".join(src.split())
    if len(norm) < MIN_CHARS:
        return None
    return hashlib.sha256(norm.encode("utf-8", "replace")).hexdigest()


def jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if a | b else 0.0


def _fingerprints_of_dir(root: Path) -> list[str]:
    out = set()
    for p in root.rglob("*.py"):
        try:
            h = huella_py(p.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        if h:
            out.add(h)
    return sorted(out)


def fingerprints(row: dict) -> list[str] | None:
    sample = ROOT / row["path"]
    if not sample.exists():
        return None
    try:
        if row.get("kind", "archive") == "dir":
            return _fingerprints_of_dir(sample)
        with tempfile.TemporaryDirectory(prefix="pyscan_fp_") as tmp:
            return _fingerprints_of_dir(safe_extract(sample, Path(tmp) / "x"))
    except Exception:  # noqa: BLE001 - muestras corruptas: sin huella
        return None


class UnionFind:
    def __init__(self, n: int):
        self.p = list(range(n))

    def find(self, i: int) -> int:
        while self.p[i] != i:
            self.p[i] = self.p[self.p[i]]
            i = self.p[i]
        return i

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)


def jaccard_pairs(sets: list[set], t: float = JACCARD_T):
    """Pares (i, j) con Jaccard >= t, con filtrado por prefijo (exacto)."""
    freq = Counter(h for s in sets for h in s)
    order = [sorted(s, key=lambda h: (freq[h], h)) for s in sets]
    index: dict[str, list[int]] = defaultdict(list)
    for i, toks in enumerate(order):
        if not toks:
            continue
        prefix = len(toks) - math.ceil(t * len(toks)) + 1
        cands = set()
        for h in toks[:prefix]:
            cands.update(index[h])
        for j in cands:
            a, b = sets[i], sets[j]
            if min(len(a), len(b)) < t * max(len(a), len(b)):
                continue
            if jaccard(a, b) >= t:
                yield j, i
        for h in toks[:prefix]:
            index[h].append(i)


def load_rows() -> list[dict]:
    rows = []
    for split in ("train", "holdout"):
        path = tm.manifest_path(split)
        # La auditoría parte siempre de la partición ORIGINAL (sin *_grouped).
        path = path.with_name(path.name.replace("_grouped", ""))
        with open(path, newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                r["split"] = split
                rows.append(r)
    return rows


def load_cache() -> dict[str, list[str]]:
    cache = {}
    if FP_CACHE.exists():
        for line in FP_CACHE.read_text(encoding="utf-8").splitlines():
            d = json.loads(line)
            cache[d["sha256"]] = d["fp"]
    return cache


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--resplit", choices=["minimo", "completo"],
                    help="minimo: mueve al entrenamiento los grupos que quedaron a ambos "
                         "lados (cambia lo mínimo); completo: rehace la partición 80/20 "
                         "con StratifiedGroupKFold")
    args = ap.parse_args()
    seed = tm.CFG.get("seed", 42)

    rows = load_rows()
    print(f"Muestras en los manifiestos: {len(rows)}")
    cache = load_cache()
    with open(FP_CACHE, "a", encoding="utf-8") as fh:
        for i, r in enumerate(rows, 1):
            if cache.get(r["sha256"]) is not None:
                continue  # las fallidas (None) se reintentan: el extractor pudo mejorar
            fp = fingerprints(r)
            cache[r["sha256"]] = fp
            fh.write(json.dumps({"sha256": r["sha256"], "fp": fp}) + "\n")
            if i % 200 == 0:
                print(f"  [{i}/{len(rows)}] huellas")

    sets = [set(cache.get(r["sha256"]) or []) for r in rows]
    nv = [name_version(r["path"]) for r in rows]
    uf = UnionFind(len(rows))
    pairs = []  # (i, j, tipo)

    by_name = defaultdict(list)
    for i, (name, _) in enumerate(nv):
        by_name[name].append(i)
    for idxs in by_name.values():
        for a in idxs[1:]:
            uf.union(idxs[0], a)
        for x in range(len(idxs)):
            for y in range(x + 1, len(idxs)):
                i, j = idxs[x], idxs[y]
                tipo = "mismo nombre y versión" if nv[i][1] == nv[j][1] else \
                    "mismo nombre, otra versión"
                pairs.append((i, j, tipo))

    by_set = defaultdict(list)
    for i, s in enumerate(sets):
        if s:
            by_set[frozenset(s)].append(i)
    identical = set()
    for idxs in by_set.values():
        for a in idxs[1:]:
            uf.union(idxs[0], a)
        for x in range(len(idxs)):
            for y in range(x + 1, len(idxs)):
                identical.add((idxs[x], idxs[y]))
                pairs.append((idxs[x], idxs[y], "huella idéntica"))

    for i, j in jaccard_pairs(sets):
        if (min(i, j), max(i, j)) in identical:
            continue
        uf.union(i, j)
        pairs.append((min(i, j), max(i, j), "Jaccard >= 0,8"))

    roots = [uf.find(i) for i in range(len(rows))]
    gid = {r: f"g{n:05d}" for n, r in enumerate(sorted(set(roots)))}
    for i, r in enumerate(rows):
        r["group_id"] = gid[roots[i]]

    # --- Cruces entrenamiento <-> hold-out ---------------------------------
    cross = [(i, j, t) for i, j, t in pairs if rows[i]["split"] != rows[j]["split"]]
    holdout_hit: dict[str, set] = defaultdict(set)
    for i, j, t in cross:
        h = i if rows[i]["split"] == "holdout" else j
        holdout_hit[t].add(h)
    any_hit = set().union(*holdout_hit.values()) if holdout_hit else set()

    def breakdown(idxs):
        c = Counter(f"{rows[i]['label']}/{rows[i].get('source', '')}" for i in idxs)
        return dict(sorted(c.items()))

    groups_both = Counter()
    for i, r in enumerate(rows):
        groups_both[(r["group_id"], r["split"])] += 1
    gsplits = defaultdict(set)
    for (g, s) in groups_both:
        gsplits[g].add(s)
    spanning = [g for g, s in gsplits.items() if len(s) == 2]
    n_hold = sum(1 for r in rows if r["split"] == "holdout")
    sizes = Counter(Counter(r["group_id"] for r in rows).values())

    report = {
        "n_train": len(rows) - n_hold, "n_holdout": n_hold,
        "sin_huella_util": sum(1 for s in sets if not s),
        "jaccard_umbral": JACCARD_T, "min_chars_archivo": MIN_CHARS,
        "grupos": len(gid), "distribucion_tamano_grupos": dict(sorted(sizes.items())),
        "grupos_a_ambos_lados": len(spanning),
        "holdout_con_pariente_en_train": {
            "total": len(any_hit),
            "porcentaje": round(100 * len(any_hit) / n_hold, 2) if n_hold else 0,
            "por_tipo": {t: len(v) for t, v in sorted(holdout_hit.items())},
            "por_clase_fuente": breakdown(any_hit),
        },
        "pares_cruzados_por_tipo": dict(Counter(t for _, _, t in cross)),
        "git_commit": tm.git_commit(),
    }

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_PAIRS, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["tipo", "sha256_train", "fuente_train", "label_train",
                    "sha256_holdout", "fuente_holdout", "label_holdout"])
        for i, j, t in cross:
            a, b = (i, j) if rows[i]["split"] == "train" else (j, i)
            w.writerow([t, rows[a]["sha256"], rows[a].get("source"), rows[a]["label"],
                        rows[b]["sha256"], rows[b].get("source"), rows[b]["label"]])

    # --- Manifiestos con group_id (y partición agrupada si se pide) ---------
    fields = ["path", "kind", "label", "source", "sha256", "group_id"]
    if args.resplit == "minimo":
        span = set(spanning)
        for r in rows:
            r["split_nuevo"] = "train" if r["group_id"] in span else r["split"]
        metodo = "mínimo: los grupos presentes en ambos lados pasan completos al entrenamiento"
    elif args.resplit == "completo":
        import numpy as np
        from sklearn.model_selection import StratifiedGroupKFold

        y = np.array([1 if r["label"] == "malicious" else 0 for r in rows])
        g = np.array([r["group_id"] for r in rows])
        sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
        _, hold_idx = next(sgkf.split(np.zeros(len(rows)), y, g))
        hold = set(hold_idx.tolist())
        for i, r in enumerate(rows):
            r["split_nuevo"] = "holdout" if i in hold else "train"
        metodo = "completo: StratifiedGroupKFold(n_splits=5), primer pliegue como hold-out"
    if args.resplit:
        moved = sum(1 for r in rows if r["split"] != r["split_nuevo"])
        report["reparticion"] = {
            "metodo": metodo,
            "semilla": seed, "muestras_que_cambian_de_lado": moved,
            "train": breakdown([i for i, r in enumerate(rows) if r["split_nuevo"] == "train"]),
            "holdout": breakdown([i for i, r in enumerate(rows) if r["split_nuevo"] == "holdout"]),
        }
        key = "split_nuevo"
    else:
        key = "split"
    for split in ("train", "holdout"):
        out = ROOT / "data" / f"{split}_grouped.csv"
        with open(out, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            w.writerows(r for r in rows if r[key] == split)

    OUT_JSON.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    h = report["holdout_con_pariente_en_train"]
    print(f"\nGrupos: {report['grupos']} | grupos a ambos lados: {report['grupos_a_ambos_lados']}")
    print(f"Hold-out con pariente en entrenamiento: {h['total']} ({h['porcentaje']} %)")
    for t, n in h["por_tipo"].items():
        print(f"  {t}: {n}")
    if args.resplit:
        print(f"Repartición agrupada: {report['reparticion']['muestras_que_cambian_de_lado']} "
              "muestras cambian de lado")
    print(f"\nInforme: {OUT_JSON.relative_to(ROOT)} | pares: {OUT_PAIRS.relative_to(ROOT)}")
    print("Manifiestos con group_id: data/train_grouped.csv, data/holdout_grouped.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
