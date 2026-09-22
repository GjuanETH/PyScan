"""Gráficas de los anexos (datos reales de data/models y data/analysis).

Uso:  python scripts/build_anexo_charts.py
Salida: docs/diagrams/anexos/*.png
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
A = ROOT / "data" / "analysis"
OUT = ROOT / "docs" / "diagrams" / "anexos"
OUT.mkdir(parents=True, exist_ok=True)

BLUE, ORANGE, AQUA, YELLOW = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"
plt.rcParams.update({"font.family": "Liberation Sans", "font.size": 10,
                     "axes.edgecolor": INK2, "axes.labelcolor": INK2,
                     "xtick.color": INK2, "ytick.color": INK2})

def num(v, d=3):
    return f"{v:.{d}f}".replace(".", ",")

from matplotlib.ticker import FuncFormatter
COMMA = FuncFormatter(lambda v, _: f"{v:g}".replace(".", ","))

def style(ax, axis="y"):
    ax.xaxis.set_major_formatter(COMMA) if axis == "x" or ax.get_xlabel().startswith("Umbral") else None
    ax.yaxis.set_major_formatter(COMMA) if axis == "y" else None
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.grid(axis=axis, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)

def save(fig, name):
    fig.tight_layout()
    fig.savefig(OUT / name, dpi=200, facecolor="white")
    plt.close(fig)
    print("->", OUT / name)

m = json.loads((ROOT / "data/models/metrics.json").read_text(encoding="utf-8"))
abl = json.loads((A / "ablation.json").read_text(encoding="utf-8"))
imb = json.loads((A / "imbalance.json").read_text(encoding="utf-8"))
gd = json.loads((A / "compare_guarddog.json").read_text(encoding="utf-8"))
av = json.loads((A / "compare_antivirus.json").read_text(encoding="utf-8"))
vt = json.loads((A / "compare_virustotal.json").read_text(encoding="utf-8"))

# 1. Importancia de características
LBL = {"entropy_mean": "Entropía media", "name_min_distance": "Distancia del nombre",
       "entropy_max": "Entropía máxima", "ast_network_literals": "Literales de red (AST)",
       "ast_dangerous_calls": "Llamadas peligrosas (AST)", "ast_has_install_hook": "Hook de instalación",
       "is_typosquat": "¿Typosquat?", "has_combo_affix": "Afijo combo",
       "entropy_suspicious_windows": "Ventanas de entropía alta"}
fi = sorted(m["feature_importance"].items(), key=lambda kv: kv[1])
fig, ax = plt.subplots(figsize=(7, 3.6))
ax.barh([LBL[k] for k, _ in fi], [v for _, v in fi], color=BLUE, height=0.6)
for i, (_, v) in enumerate(fi):
    ax.text(v + 0.005, i, num(v, 2), va="center", color=INK, fontsize=9)
ax.set_xlabel("Importancia (Random Forest)")
ax.set_xlim(0, max(v for _, v in fi) * 1.15)
style(ax, "x")
save(fig, "importancia.png")

# 2. Ablación: F1 y tasa de FP por configuración
order = ["Todas (baseline)", "Sin nombre (solo código)", "Solo entropía", "Solo AST", "Solo nombre"]
names = ["Todas (9)", "Sin nombre (6)", "Solo entropía (3)", "Solo AST (3)", "Solo nombre (3)"]
f1 = [abl["configs"][k]["metrics"]["f1"] for k in order]
fp = [abl["configs"][k]["metrics"]["false_positive_rate"] for k in order]
fig, ax = plt.subplots(figsize=(7, 3.4))
x = range(len(order)); w = 0.36
b1 = ax.bar([i - w/2 - 0.01 for i in x], f1, w, color=BLUE, label="F1")
b2 = ax.bar([i + w/2 + 0.01 for i in x], fp, w, color=ORANGE, label="Tasa de falsos positivos")
for bars in (b1, b2):
    for b in bars:
        ax.text(b.get_x() + b.get_width()/2, b.get_height() + 0.015, num(b.get_height(), 2),
                ha="center", fontsize=8.5, color=INK)
ax.set_xticks(list(x)); ax.set_xticklabels(names, fontsize=9)
ax.set_ylim(0, 1.05); ax.legend(frameon=False, loc="upper right", fontsize=9)
style(ax)
save(fig, "ablacion.png")

# 3. Precisión según prevalencia
prev = imb["projection_by_prevalence"]
keys = list(prev.keys())
vals = [prev[k]["precision"] for k in keys]
fig, ax = plt.subplots(figsize=(7, 3.2))
bars = ax.bar(keys, vals, color=BLUE, width=0.55)
for b in bars:
    ax.text(b.get_x() + b.get_width()/2, b.get_height() + 0.015, num(b.get_height()),
            ha="center", fontsize=9, color=INK)
ax.set_xlabel("Prevalencia (maliciosos : benignos)")
ax.set_ylabel("Precisión proyectada")
ax.set_ylim(0, 1.05)
style(ax)
save(fig, "prevalencia.png")

# 4. Barrido de umbral a prevalencia 1:100
sw = imb["threshold_sweep"]
th = [r["threshold"] for r in sw]
fig, ax = plt.subplots(figsize=(7, 3.4))
ax.plot(th, [r["recall"] for r in sw], color=BLUE, lw=2, marker="o", ms=4, label="Recall")
ax.plot(th, [r["precision"] for r in sw], color=ORANGE, lw=2, marker="o", ms=4, label="Precisión (1:100)")
for t0, txt in ((0.45, "umbral de operación 0,45"), (0.65, "sensibilidad 0,65")):
    ax.axvline(t0, color=INK2, lw=1, ls="--")
    ax.text(t0 + 0.005, 0.03, txt, rotation=90, fontsize=8, color=INK2, va="bottom")
ax.axhline(0.90, color=GRID, lw=1)
ax.text(0.2, 0.855, "meta de Recall 0,90", fontsize=8, color=INK2)
ax.set_xlabel("Umbral de decisión"); ax.set_ylim(0, 1.05)
ax.legend(frameon=False, loc="center left", fontsize=9)
style(ax)
save(fig, "umbral.png")

# 5. pyscan vs GuardDog vs ClamAV (mismas 300 muestras)
mets = [("recall", "Recall"), ("precision", "Precisión"), ("false_positive_rate", "Tasa de FP")]
tools = [("pyscan (ML)", gd["pyscan"], BLUE), ("GuardDog (reglas)", gd["guarddog"], ORANGE),
         ("ClamAV (firmas)", av["clamav"], AQUA)]
fig, ax = plt.subplots(figsize=(7, 3.4))
w = 0.26
for j, (tn, d, c) in enumerate(tools):
    xs = [i + (j - 1) * (w + 0.02) for i in range(len(mets))]
    bs = ax.bar(xs, [d[k] for k, _ in mets], w, color=c, label=tn)
    for (k, _), b in zip(mets, bs):
        # ClamAV no emitió ninguna alerta: su precisión no está definida.
        lab = "n/d" if (tn.startswith("ClamAV") and k == "precision") else num(b.get_height(), 2)
        ax.text(b.get_x() + b.get_width()/2, b.get_height() + 0.015, lab,
                ha="center", fontsize=8.5, color=INK)
ax.set_xticks(range(len(mets))); ax.set_xticklabels([n for _, n in mets])
ax.set_ylim(0, 1.1); ax.legend(frameon=False, fontsize=9, loc="upper right")
style(ax)
save(fig, "comparativa_300.png")

# 6. pyscan vs VirusTotal (80 muestras)
fig, ax = plt.subplots(figsize=(7, 3.2))
w = 0.36
for j, (tn, d, c) in enumerate((("pyscan (ML)", vt["pyscan"], BLUE),
                                ("VirusTotal (≥ 2 motores)", vt["virustotal"], YELLOW))):
    xs = [i + (j - 0.5) * (w + 0.02) for i in range(len(mets))]
    bs = ax.bar(xs, [d[k] for k, _ in mets], w, color=c, label=tn)
    for b in bs:
        ax.text(b.get_x() + b.get_width()/2, b.get_height() + 0.015, num(b.get_height(), 3),
                ha="center", fontsize=8.5, color=INK)
ax.set_xticks(range(len(mets))); ax.set_xticklabels([n for _, n in mets])
ax.set_ylim(0, 1.12); ax.legend(frameon=False, fontsize=9, loc="upper right")
style(ax)
save(fig, "comparativa_vt.png")
