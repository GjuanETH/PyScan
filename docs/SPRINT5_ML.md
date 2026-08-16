# Sprint 5 — Entrenamiento y uso del clasificador ML

## Flujo completo (en tu máquina, PowerShell)

```powershell
cd "...\Trabajo de Grado (1)\pyscan"
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev,ml]"        # instala scikit-learn, xgboost, imbalanced-learn

# 1. Poner los artefactos del dataset en:
#    data/benign/      (usa scripts/collect_benign.py)
#    data/malicious/   (DataDog + Malregistry + PackAttack, ver docs/DATASET.md)

# 2. Unificar, deduplicar por sha256 y dividir 80/20:
python scripts/build_dataset.py --split 0.2 --seed 42

# 3. Entrenar (k-fold estratificado, class_weight, SMOTE, ajuste de umbral):
python scripts/train_model.py --k 5 --target-recall 0.90 --holdout

# 4. Escanear con veredicto ML:
python -m pyscan.cli scan <paquete>              # exit code 2 si es MALICIOSO
python -m pyscan.cli scan <paquete> --sarif out.sarif
```

## Salidas

- `data/models/model.joblib` — bundle: modelo + orden de features + umbral.
- `data/models/metrics.json` — Recall, F1, PR-AUC, matriz de confusión,
  tasa de FP e importancia de características → **sección de Resultados del paper**.

## Decisiones de diseño (defendibles en la sustentación)

- **Predicciones out-of-fold** en la validación cruzada: el umbral se ajusta
  sobre muestras nunca vistas por el fold que las predijo (sin fuga de datos).
- **SMOTE solo dentro de cada fold de entrenamiento**, nunca sobre validación.
- El umbral maximiza F1 **sujeto a Recall >= 0.90** (KPI de la tesis); ante
  empate se prefiere el umbral más alto (menos falsos positivos).
- El hold-out (20 %) se evalúa **con el umbral ya fijado** en CV: es una
  estimación honesta del desempeño final.
- Códigos de salida del CLI (CI-ready): 0 benigno, 1 error, 2 malicioso.
