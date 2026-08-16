#!/usr/bin/env python3
"""Análisis empírico de vectores de ataque en el corpus malicioso (Objetivo 1).

Recorre las muestras maliciosas (data/malicious/ o las etiquetadas como
"malicious" en data/dataset.csv), ejecuta los extractores estáticos del MVP
sobre cada paquete y cuantifica CON QUÉ FRECUENCIA aparece cada vector de
ataque. El resultado es la evidencia empírica que justifica los requerimientos
del sistema (RF/RNF) bajo ISO/IEC 25010:2023.

NUNCA ejecuta el código analizado: todo es análisis estático.

Vectores medidos (mapeados a la taxonomía de la literatura):
  V1  Typosquatting / combosquatting     (extractor de metadatos)
  V2  Ejecución en instalación           (AST: hook en setup.py)
  V3  Ofuscación / empaquetado           (entropía: ventanas sospechosas)
  V4  Ejecución de comandos/código       (AST: eval/exec/os.system/subprocess)
  V5  Deserialización insegura           (AST: pickle.loads/marshal.loads)
  V6  Codificación/decodificación        (AST: base64.*)
  V7  Red / exfiltración                 (AST: literales de red + socket/urllib/requests)

Uso:
    python scripts/analyze_attack_vectors.py               # usa data/malicious/
    python scripts/analyze_attack_vectors.py --from-csv data/dataset.csv
    python scripts/analyze_attack_vectors.py --limit 500
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pyscan import config  # noqa: E402
from pyscan.extractors import (ASTExtractor, EntropyExtractor,  # noqa: E402
                               MetadataExtractor)
from pyscan.fetcher import FetchError, safe_extract  # noqa: E402
from pyscan.models import ASTReport, EntropyReport, TyposquatReport  # noqa: E402

OUT_DIR = config.DATA_DIR / "analysis"
ARCHIVE_EXTS = (".tar.gz", ".tgz", ".whl", ".zip", ".egg", ".tar")

VECTORS = {
    "V1_typosquatting": "Typosquatting / combosquatting",
    "V2_install_execution": "Ejecución en instalación (setup.py)",
    "V3_obfuscation": "Ofuscación / empaquetado (entropía alta)",
    "V4_command_execution": "Ejecución de comandos/código",
    "V5_insecure_deserialization": "Deserialización insegura",
    "V6_encoding": "Codificación/decodificación (base64)",
    "V7_network_exfiltration": "Red / exfiltración de datos",
}

_NET_TOKENS = ("socket", "urllib", "requests", "http", "ftplib", "smtplib")


def _package_name(path: Path) -> str:
    stem = path.name
    for ext in ARCHIVE_EXTS:
        if stem.lower().endswith(ext):
            stem = stem[: -len(ext)]
            break
    m = re.match(r"^(?P<n>.+?)-\d", stem)
    return (m.group("n") if m else stem).lower().replace("_", "-")


def _classify(name: str, typo: TyposquatReport, entropy: EntropyReport,
              ast_rep: ASTReport) -> dict[str, bool]:
    calls = set(ast_rep.dangerous_calls)
    has_cmd = any(c in calls for c in (
        "eval", "exec", "compile", "__import__", "os.system", "os.popen",
        "subprocess.run", "subprocess.call", "subprocess.Popen"))
    has_deser = any(c in calls for c in ("pickle.loads", "marshal.loads"))
    has_b64 = any(c.startswith("base64.") for c in calls)
    net_imports = any(tok in imp for imp in ast_rep.imports for tok in _NET_TOKENS)
    has_net = bool(ast_rep.network_literals) or net_imports \
        or any("socket" in c or "urllib" in c or "requests" in c for c in calls)
    return {
        "V1_typosquatting": bool(typo.is_typosquat or typo.has_combo_affix),
        "V2_install_execution": bool(ast_rep.has_install_hook),
        "V3_obfuscation": entropy.suspicious_windows > 0,
        "V4_command_execution": has_cmd,
        "V5_insecure_deserialization": has_deser,
        "V6_encoding": has_b64,
        "V7_network_exfiltration": has_net,
    }


def _analyze_dir(name: str, root: Path, meta: MetadataExtractor):
    typo = meta.extract(name)
    entropy = EntropyExtractor().extract(root)
    ast_rep = ASTExtractor().extract(root)
    return _classify(name, typo, entropy, ast_rep), ast_rep.dangerous_calls


def _iter_samples(malicious_dir: Path):
    """Devuelve (nombre, ruta, kind) por muestra: archivo o carpeta con .py."""
    if not malicious_dir.exists():
        return
    for p in malicious_dir.rglob("*"):
        if p.is_file() and p.name.lower().endswith(ARCHIVE_EXTS):
            yield _package_name(p), p, "archive"
    seen: set[Path] = set()
    for d in malicious_dir.rglob("*"):
        if d.is_dir() and any(f.suffix == ".py" for f in d.iterdir() if f.is_file()):
            if any(par in seen for par in d.parents):
                continue
            seen.add(d)
            yield _package_name(d), d, "dir"


def _iter_from_csv(csv_path: Path):
    with open(csv_path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row.get("label") != "malicious":
                continue
            p = ROOT / row["path"]
            kind = row.get("kind", "archive")
            yield _package_name(p), p, kind


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from-csv", type=Path, default=None,
                    help="usa un manifiesto CSV (col. label=malicious) en vez de data/malicious/")
    ap.add_argument("--limit", type=int, default=0, help="máximo de muestras (0 = todas)")
    args = ap.parse_args()

    source = (_iter_from_csv(args.from_csv) if args.from_csv
              else _iter_samples(config.MALICIOUS_DIR))
    meta = MetadataExtractor()

    n = 0
    errors = 0
    vector_counts = Counter()
    cooccurrence = Counter()
    call_families = Counter()
    per_sample_rows = []

    for name, path, kind in source:
        if args.limit and n >= args.limit:
            break
        try:
            if kind == "dir":
                flags, calls = _analyze_dir(name, path, meta)
            else:
                with tempfile.TemporaryDirectory(prefix="pyscan_av_") as tmp:
                    extracted = safe_extract(path, Path(tmp) / "x")
                    flags, calls = _analyze_dir(name, extracted, meta)
        except Exception as exc:  # noqa: BLE001 - robustez ante muestras corruptas
            print(f"  [AVISO] {path.name}: {exc}", file=sys.stderr)
            errors += 1
            continue

        n += 1
        active = [k for k, v in flags.items() if v]
        for k in active:
            vector_counts[k] += 1
        cooccurrence[len(active)] += 1
        for c in calls:
            call_families[c] += 1
        per_sample_rows.append({"package": name, "kind": kind,
                                **{k: int(v) for k, v in flags.items()}})

    if n == 0:
        print("No se analizaron muestras. ¿Descargaste el dataset? Ver docs/INSTRUCTIVO_DATASETS.md")
        return 1

    summary = {
        "n_samples": n,
        "errors": errors,
        "vectors": {
            vid: {"label": VECTORS[vid], "count": vector_counts[vid],
                  "percentage": round(100 * vector_counts[vid] / n, 2)}
            for vid in VECTORS
        },
        "cooccurrence": {str(k): v for k, v in sorted(cooccurrence.items())},
        "multi_vector_percentage": round(
            100 * sum(v for k, v in cooccurrence.items() if k >= 2) / n, 2),
        "top_dangerous_calls": dict(call_families.most_common(15)),
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "attack_vectors.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    with open(OUT_DIR / "attack_vectors_per_sample.csv", "w", newline="",
              encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["package", "kind", *VECTORS.keys()])
        w.writeheader()
        w.writerows(per_sample_rows)

    print(f"\nMuestras maliciosas analizadas: {n} (errores: {errors})\n")
    print("| ID | Vector de ataque | Paquetes | % |")
    print("|----|------------------|---------:|---:|")
    for vid in sorted(VECTORS, key=lambda k: -vector_counts[k]):
        v = summary["vectors"][vid]
        print(f"| {vid.split('_')[0]} | {v['label']} | {v['count']} | {v['percentage']}% |")
    print(f"\nPaquetes con >=2 vectores simultaneos: {summary['multi_vector_percentage']}%")
    print(f"\nSalidas: {OUT_DIR/'attack_vectors.json'}")
    print(f"         {OUT_DIR/'attack_vectors_per_sample.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
