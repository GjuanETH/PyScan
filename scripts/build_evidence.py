#!/usr/bin/env python3
"""Arma el paquete de evidencia reproducible (corrección 1.7).

Crea evidencia/ (privada: está en .gitignore y NO contiene malware) con:
  manifiesto_train.csv / manifiesto_holdout.csv  (id, fuente, etiqueta, nombre,
      versión, sha256, group_id)
  config.yaml, requirements.lock, commit.txt, modelo.sha256
  metrics.json, pred_oof.csv, pred_holdout.csv y todos los resultados de data/analysis/
  pytest-junit.xml y coverage.xml (con --run-tests)
  ci.txt (enlace a la ejecución de CI) y capturas/ (con --capturas <carpeta>)
  SHA256SUMS  -> y su propio hash, que se cita en los anexos G y H.

Uso:
    python scripts/build_evidence.py --run-tests --capturas ~/Escritorio/capturas_anexo_D
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import train_model as tm  # noqa: E402
from audit_independence import name_version  # noqa: E402
from report_utils import norm_source  # noqa: E402

OUT = ROOT / "evidencia"
CI_URL = "https://github.com/GjuanETH/PyScan/actions"


def write_manifest(src: Path, dst: Path) -> int:
    with open(src, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    with open(dst, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "fuente", "etiqueta", "nombre", "version", "sha256", "group_id"])
        for i, r in enumerate(rows, 1):
            name, ver = name_version(r["path"])
            w.writerow([i, norm_source(r["label"], r.get("source", "")), r["label"], name, ver,
                        r["sha256"], r.get("group_id", "")])
    return len(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-tests", action="store_true", help="corre pytest con junit y cobertura")
    ap.add_argument("--capturas", type=Path, help="carpeta con las capturas del Anexo D")
    args = ap.parse_args()

    OUT.mkdir(exist_ok=True)
    for split in ("train", "holdout"):
        n = write_manifest(tm.manifest_path(split), OUT / f"manifiesto_{split}.csv")
        print(f"  manifiesto_{split}.csv: {n} filas")

    shutil.copy2(ROOT / "config.yaml", OUT / "config.yaml")
    lock = subprocess.run([sys.executable, "-m", "pip", "freeze"], capture_output=True, text=True)
    (OUT / "requirements.lock").write_text(lock.stdout, encoding="utf-8")
    shutil.copy2(OUT / "requirements.lock", ROOT / "requirements.lock")
    tag = subprocess.run(["git", "describe", "--tags", "--always"], cwd=ROOT,
                         capture_output=True, text=True).stdout.strip()
    (OUT / "commit.txt").write_text(f"commit: {tm.git_commit()}\netiqueta: {tag}\n",
                                    encoding="utf-8")
    sidecar = Path(str(tm.config.MODEL_FILE) + ".sha256")
    if sidecar.exists():
        shutil.copy2(sidecar, OUT / "modelo.sha256")
    shutil.copy2(tm.config.MODEL_DIR / "metrics.json", OUT / "metrics.json")

    analysis = OUT / "resultados"
    analysis.mkdir(exist_ok=True)
    for f in sorted((ROOT / "data" / "analysis").glob("*")):
        if f.is_file() and f.suffix in (".json", ".csv", ".png", ".log", ".txt"):
            shutil.copy2(f, analysis / f.name)

    if args.run_tests:
        r = subprocess.run([sys.executable, "-m", "pytest", "-q",
                            f"--junitxml={OUT / 'pytest-junit.xml'}", "--cov=pyscan",
                            f"--cov-report=xml:{OUT / 'coverage.xml'}", "--cov-report=term"],
                           cwd=ROOT, capture_output=True, text=True)
        (OUT / "pytest.log").write_text(r.stdout + r.stderr, encoding="utf-8")
        print("  pytest:", (r.stdout.strip().splitlines() or ["(sin salida)"])[-1])
    (OUT / "ci.txt").write_text(
        f"Ejecuciones de integración continua: {CI_URL}\n"
        "Pegar aquí el enlace de la ejecución del commit de commit.txt.\n", encoding="utf-8")
    if args.capturas and args.capturas.exists():
        dst = OUT / "capturas"
        shutil.copytree(args.capturas, dst, dirs_exist_ok=True)

    sums = []
    for f in sorted(p for p in OUT.rglob("*") if p.is_file() and p.name != "SHA256SUMS"):
        sums.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.relative_to(OUT)}")
    (OUT / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    digest = hashlib.sha256((OUT / "SHA256SUMS").read_bytes()).hexdigest()
    print(f"\nEvidencia en {OUT.relative_to(ROOT)}/ ({len(sums)} archivos)")
    print(f"Hash de la evidencia (sha256 de SHA256SUMS), para citar en los anexos: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
