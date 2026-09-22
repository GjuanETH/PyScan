# pyscan

[![CI](https://github.com/GjuanETH/PyScan/actions/workflows/ci.yml/badge.svg)](https://github.com/GjuanETH/PyScan/actions/workflows/ci.yml)

MVP de **detección de paquetes maliciosos en PyPI** mediante análisis estático y
aprendizaje automático supervisado. Trabajo de grado — Universidad Católica de
Colombia, 2026.

Combina tres señales estáticas —**distancia de Levenshtein** sobre el nombre
(typosquatting), **entropía de Shannon** con ventana deslizante y recorrido de
**árboles de sintaxis abstracta (AST)**— que alimentan un clasificador
supervisado (Random Forest, seleccionado frente a XGBoost). El paquete **nunca se ejecuta**:
todo es análisis estático. Arquitectura de monolito modular con patrón
Pipes and Filters; interfaces con Pydantic; salida JSON/SARIF.

## Estado

MVP funcionalmente completo. **66 pruebas, cobertura 91 %.** KPI verificados
(modelo Random Forest, umbral 0,45; detalle en `data/models/metrics.json`):

| KPI (ISO/IEC 25010:2023) | Meta | Resultado |
|---|---|---|
| Recall (hold-out, 866 muestras) | ≥ 0,90 | **0,945** |
| F1-Score (hold-out) | ≥ 0,85 | **0,933** |
| Falsos positivos (validación cruzada k=5) | ≤ 10 % | **6,1 %** |
| Tiempo por paquete (100 paquetes) | ≤ 120 s | **0,91 s media; 25,1 s máx.** |
| Memoria (RSS del proceso) | ≤ 2 GB | **353 MB** |
| Cobertura de pruebas | ≥ 80 % | **91 %** |

Frente a GuardDog, sobre las mismas 300 muestras: Recall 0,880 vs 0,827 y
falsos positivos 4,0 % vs 23,7 %. A prevalencias realistas (1 malicioso por cada
100), la precisión esperada baja a ~0,13: pyscan sirve para **priorizar** paquetes
para revisión, no como veredicto definitivo (ver `data/analysis/imbalance.json`).

## Instalación

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
pip install -e ".[dev,ml]"
```

> En Windows, si Smart App Control bloquea el ejecutable, usa siempre
> `python -m pyscan.cli ...` en lugar de `pyscan ...`.

## Uso

**Analizar las dependencias de un proyecto** (el caso de uso principal):

```bash
python -m pyscan.cli scan -r requirements.txt
```

**Analizar uno o varios paquetes de PyPI:**

```bash
python -m pyscan.cli scan requests
python -m pyscan.cli scan requests flask numpy rich
```

**Analizar paquetes locales** (un `.tar.gz`/`.whl` o una carpeta, sin descargar):

```bash
python -m pyscan.cli scan --local ./algo.tar.gz --local ./carpeta-paquete
```

**Otros comandos y opciones:**

```bash
python -m pyscan.cli check-name reqursts     # analiza solo el nombre (offline)
python -m pyscan.cli info six                # metadatos del paquete
python -m pyscan.cli scan requests --json    # salida JSON
python -m pyscan.cli scan -r reqs.txt --sarif salida.sarif   # reporte SARIF 2.1.0
python -m pyscan.cli scan requests --model data/models/model.joblib  # modelo alterno
```

Al analizar más de un paquete se imprime un **resumen consolidado** (cuántos
analizados, cuántos maliciosos, y una sección "A revisar" con el motivo).

**Códigos de salida** (aptos para integración continua):
`0` = todo benigno · `1` = hubo errores · `2` = al menos un paquete MALICIOSO.

> El veredicto ML requiere un modelo entrenado (`data/models/model.joblib`).
> Sin él, `scan` muestra igualmente las señales del análisis pero sin veredicto.

## Entrenar el modelo

```bash
# 1) construir el dataset (ver docs/INSTRUCTIVO_DATASETS.md para descargar las fuentes)
python scripts/build_dataset.py --max-malicious 2000 --ratio 2.0 --split 0.2 --seed 42
# 2) entrenar (k-fold estratificado, SMOTE, ajuste de umbral, hold-out)
python scripts/train_model.py --k 5 --target-recall 0.90 --holdout
```

Genera `data/models/model.joblib` (modelo + orden de características + umbral) y
`data/models/metrics.json`.

## Pruebas y desempeño

```bash
python -m pytest --cov=pyscan --cov-report=term-missing
python scripts/benchmark_performance.py --packages requests flask numpy rich typer
```

## Scripts

| Script | Función |
|---|---|
| `build_dataset.py` | Unifica, deduplica (sha256) y divide el dataset. |
| `collect_benign.py` / `fetch_top_pypi.py` | Recolecta benignos del Top de PyPI. |
| `import_datadog.py` | Importa la parte PyPI del dataset de DataDog. |
| `train_model.py` | Entrena y evalúa el clasificador. |
| `analyze_attack_vectors.py` | Cuantifica los 7 vectores de ataque (Objetivo 1). |
| `experiment_ablation.py` | Estudio de ablación / fuga de datos. |
| `experiment_imbalance.py` | Evaluación a prevalencia realista. |
| `experiment_compare_guarddog.py` | Comparación empírica con GuardDog. |
| `experiment_compare_antivirus.py` / `experiment_compare_virustotal.py` | Comparación con ClamAV y VirusTotal. |
| `fetch_random_pypi.py` | Muestra aleatoria del índice de PyPI (benignos anti-sesgo). |
| `benchmark_performance.py` | Mide tiempo y memoria por paquete (KPI). |

## Estructura

```
src/pyscan/        motor del MVP (models, config, fetcher, extractors,
                   features, classifier, sarif, cli)
tests/             pruebas pytest (unitarias + integración)
scripts/           dataset, entrenamiento, experimentos y generadores de docs
docs/              guías técnicas (DATASET, INSTRUCTIVO_DATASETS, SPRINT5_ML,
                   experimentos) y diagramas
data/              listas de referencia, dataset y modelo (contenido pesado
                   y el malware NO se versionan; ver .gitignore)
```

## Seguridad

pyscan realiza únicamente **análisis estático**: descarga y descomprime los
paquetes (con protección anti Zip-Slip y zip-bomb; los enlaces simbólicos se omiten) pero **nunca ejecuta
su código**. Aun así, al manejar datasets de malware real, trabájalos en un
entorno aislado (máquina virtual). Ver `docs/INSTRUCTIVO_DATASETS.md`.

## Desarrollo

```bash
pip install -e ".[dev,ml]"
pre-commit install          # isort, black y flake8 en cada commit
```

El CI de GitHub Actions ejecuta estilo, pruebas y cobertura (mínimo 80 %) en
Python 3.10–3.12.

## Licencia

MIT — ver `LICENSE`.
