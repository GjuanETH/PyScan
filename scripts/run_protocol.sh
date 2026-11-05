#!/usr/bin/env bash
# Corre el protocolo experimental completo en la VM y empaqueta los resultados.
# Uso (desde la raíz del repo, con el venv activo):
#   export VT_API_KEY="su_clave"
#   bash scripts/run_protocol.sh
# Salida: resultados_<fecha>.tar.gz en la raíz (solo JSON/CSV de resultados, sin muestras).
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -z "${VT_API_KEY:-}" ]; then
  echo "Falta VT_API_KEY (export VT_API_KEY=...)." >&2; exit 1
fi
STAMP=$(date +%Y%m%d_%H%M)
LOG="data/analysis/run_${STAMP}.log"
mkdir -p data/analysis
paso() { echo; echo "=== $* ===" | tee -a "$LOG"; "$@" 2>&1 | tee -a "$LOG"; }

git status --short > "data/analysis/git_status_${STAMP}.txt"
paso python scripts/audit_independence.py --resplit completo
grep -q "grupos a ambos lados después: 0" "$LOG" || { echo "La repartición no quedó limpia; se detiene." >&2; exit 1; }
paso python scripts/train_model.py
paso python scripts/train_model.py --sampler smote --tag comparacion_smote
paso python scripts/report_holdout.py
paso python scripts/baseline_rules.py
paso python scripts/experiment_ablation.py
paso python scripts/experiment_imbalance.py
paso python scripts/benchmark_performance.py --from-csv data/holdout_grouped.csv --limit 100
paso python scripts/experiment_compare_guarddog.py
paso python scripts/experiment_compare_antivirus.py
paso python scripts/experiment_compare_virustotal.py
paso python scripts/report_comparisons.py

A=data/analysis
tar -czf "resultados_${STAMP}.tar.gz" \
  data/models/metrics.json "$A"/variante_comparacion_smote/metrics.json \
  "$A"/independence_audit.json "$A"/independence_pairs.csv "$A"/holdout_report.json \
  "$A"/baseline_rules.json "$A"/ablation.json "$A"/imbalance.json "$A"/benchmark.json \
  "$A"/compare_*.json "$A"/compare_*_per_sample.csv "$A"/comparisons_report.json \
  "$A"/exclusiones.csv "$A"/pred_holdout.csv "$A"/feature_refresh.json \
  "$A/git_status_${STAMP}.txt" "$LOG" 2>/dev/null || true
echo; echo "Listo: resultados_${STAMP}.tar.gz  (mándenlo completo)"
