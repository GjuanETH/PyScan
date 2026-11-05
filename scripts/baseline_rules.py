#!/usr/bin/env python3
"""Línea base determinista sobre las MISMAS 9 señales (corrección 1.9).

Pregunta: ¿el clasificador aporta algo frente a reglas fijas razonables? Se
evalúan reglas del tipo "hook de instalación y llamada de red o peligrosa",
"entropía máxima > T", "typosquat" y "llamadas peligrosas >= D". Los umbrales y
la combinación de reglas se eligen SOLO con el entrenamiento (mismo criterio del
modelo: Recall >= objetivo y luego F1) y se evalúan UNA vez en el hold-out.

Uso:  python scripts/baseline_rules.py
Salida: data/analysis/baseline_rules.json
"""

from __future__ import annotations

import itertools
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import numpy as np  # noqa: E402

import train_model as tm  # noqa: E402
from pyscan.classifier import feature_names  # noqa: E402

N = feature_names()
IDX = {n: i for i, n in enumerate(N)}


def rule_preds(X: np.ndarray, rules: tuple[str, ...], t_ent: float, t_dang: int) -> np.ndarray:
    hook = X[:, IDX["ast_has_install_hook"]] > 0
    net = X[:, IDX["ast_network_literals"]] > 0
    dang = X[:, IDX["ast_dangerous_calls"]]
    preds = np.zeros(len(X), dtype=bool)
    if "hook+red_o_peligrosa" in rules:
        preds |= hook & (net | (dang > 0))
    if "entropia_max" in rules:
        preds |= X[:, IDX["entropy_max"]] > t_ent
    if "typosquat" in rules:
        preds |= X[:, IDX["is_typosquat"]] > 0
    if "llamadas_peligrosas" in rules:
        preds |= dang >= t_dang
    return preds.astype(int)


def main() -> int:
    target = tm.CFG.get("target_recall", 0.90)
    Xtr, ytr, _ = tm.load_dataset(tm.manifest_path("train"))
    Xho, yho, _ = tm.load_dataset(tm.manifest_path("holdout"))
    Xtr, ytr = np.asarray(Xtr, float), np.asarray(ytr, int)
    Xho, yho = np.asarray(Xho, float), np.asarray(yho, int)

    names = ["hook+red_o_peligrosa", "entropia_max", "typosquat", "llamadas_peligrosas"]
    combos = [c for r in range(1, len(names) + 1) for c in itertools.combinations(names, r)]
    ents = np.round(np.arange(5.0, 8.01, 0.1), 1)
    dangs = range(1, 9)
    best = None
    for combo in combos:
        for t_ent in (ents if "entropia_max" in combo else [8.0]):
            for t_d in (dangs if "llamadas_peligrosas" in combo else [1]):
                m = tm.metrics_at(ytr, rule_preds(Xtr, combo, t_ent, t_d), 0.5)
                key = (m["recall"] >= target, m["f1"])
                if best is None or key > best[0]:
                    best = (key, combo, float(t_ent), int(t_d), m)
    _, combo, t_ent, t_d, m_train = best
    m_hold = tm.metrics_at(yho, rule_preds(Xho, combo, t_ent, t_d), 0.5)

    fixed = {}  # reglas simples sin ajuste, para contexto
    for label, c, te, td in [("solo hook + red o peligrosa", ("hook+red_o_peligrosa",), 8.0, 1),
                             ("solo typosquat", ("typosquat",), 8.0, 1),
                             ("cualquier llamada peligrosa", ("llamadas_peligrosas",), 8.0, 1),
                             ("entropía máxima > 7,0", ("entropia_max",), 7.0, 1)]:
        fixed[label] = tm.metrics_at(yho, rule_preds(Xho, c, te, td), 0.5)

    report = {"criterio": f"Recall >= {target} en entrenamiento y luego F1 máximo",
              "regla_elegida": {"reglas": list(combo), "umbral_entropia": t_ent,
                                "umbral_llamadas": t_d},
              "entrenamiento": m_train, "holdout": m_hold,
              "reglas_simples_en_holdout": fixed, "git_commit": tm.git_commit()}
    ml = json.loads((ROOT / "data" / "models" / "metrics.json").read_text(encoding="utf-8"))
    report["modelo_holdout"] = ml.get("holdout")
    out = ROOT / "data" / "analysis" / "baseline_rules.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Regla elegida en entrenamiento: {' O '.join(combo)} "
          f"(entropía > {t_ent}, llamadas >= {t_d})")
    print("| Detector (hold-out) | Recall | Precisión | F1 | FP |")
    print("|---|---|---|---|---|")
    rows = [("Línea base de reglas", m_hold)] + [(k, v) for k, v in fixed.items()]
    if ml.get("holdout"):
        rows.insert(0, ("pyscan (Random Forest)", ml["holdout"]))
    for name, m in rows:
        print(f"| {name} | {m['recall']} | {m['precision']} | {m['f1']} | "
              f"{m['false_positive_rate']} |")
    print(f"\nDatos: {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
