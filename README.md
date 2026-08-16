# pyscan

MVP de **detección de paquetes maliciosos en PyPI** mediante análisis estático y
aprendizaje automático supervisado. Trabajo de grado — Universidad Católica de
Colombia.

Combina tres señales estáticas — **distancia de Levenshtein** sobre metadatos,
**entropía de Shannon** con ventana deslizante y recorrido de **árboles de
sintaxis abstracta (AST)** — que alimentan un clasificador supervisado
(Random Forest / XGBoost). Arquitectura de monolito modular con patrón
Pipes and Filters; interfaces con Pydantic; salida JSON/SARIF.

## Estado (Sprints 1-4)

| Componente | Estado |
|---|---|
| Modelos de dominio (Pydantic) | ✅ |
| Fetcher seguro (anti Zip Slip / zip-bomb) | ✅ |
| Extractor de metadatos (typosquatting / combosquatting) | ✅ |
| Feature Builder | ✅ (parcial) |
| CLI (`scan`, `info`, `version`) | ✅ |
| Extractor de entropía (Shannon, ventana deslizante) | ✅ |
| Extractor AST (ast.NodeVisitor) | ✅ |
| Clasificador ML + dataset | ⏳ Sprint 5 |

Cobertura de pruebas actual: **90%** (objetivo KPI ≥ 80%).

## Instalación

```bash
pip install -e ".[dev,ml]"
```

## Uso

```bash
pyscan scan requests          # analiza un paquete de PyPI
pyscan scan reqursts --json   # salida JSON del reporte
pyscan check-name reqursts    # analiza solo el nombre (offline)
pyscan info six               # solo metadatos
```

(Sin instalar, desde la raíz: `PYTHONPATH=src python -m pyscan.cli scan requests`.)

## Pruebas

```bash
PYTHONPATH=src python -m pytest --cov=pyscan --cov-report=term-missing
```

## Dataset

Ver **`docs/DATASET.md`** para construir y **expandir** el dataset (cómo pasar de
~800 a ≥2.000 muestras maliciosas agregando datasets públicos). Scripts:

- `scripts/collect_benign.py` — descarga benignos del Top de PyPI (funciona en cualquier entorno con acceso a PyPI).
- `scripts/fetch_top_pypi.py` — refresca la lista del Top de PyPI.
- `scripts/build_dataset.py` — unifica, deduplica (sha256) y divide 80/20.

## Estructura

```
src/pyscan/        código del MVP (models, fetcher, extractors, features, cli)
tests/             pruebas pytest (unitarias + integración)
scripts/           recolección y construcción del dataset
data/              listas de referencia y dataset (no versionado el contenido pesado)
docs/              guía del dataset
```

## Licencia

MIT (código abierto).
