# Estado del backlog de Azure DevOps vs. lo construido

Revisión al cierre del **Sprint 4** (motor de análisis estático completo; falta ML).
Leyenda: ✅ hecho · 🟡 parcial · ⏳ pendiente (sprint posterior / requiere datos) · ❌ no hecho · ⚠️ contradice el alcance de la tesis.

## Fase 1 — Estado del arte y arquitectura
| Tarea | Estado | Nota |
|---|---|---|
| 1.1–1.3 Taxonomía, SLSA, diseño de arquitectura | ✅ (en la tesis) | La arquitectura (monolito modular + Pipes and Filters) ya está implementada en el código |
| 1.4 · Repo con ramas main y **develop** protegidas | 🟡 | Está en Azure DevOps con `main`; **falta crear/proteger `develop`**. (El backlog dice "GitHub"; usamos Azure) |
| 1.4 · Entorno con **Poetry/Pipenv** + pyproject.toml | 🟡 | Tenemos `pyproject.toml` ✅, pero usamos `venv`+`pip`, no Poetry/Pipenv |
| 1.4 · pre-commit hooks (black, flake8, isort) | ❌ | `black`/`flake8` están como dependencias, pero **no hay pre-commit configurado ni isort** |

## Fase 2 — Fetcher y datos
| Tarea | Estado | Nota |
|---|---|---|
| 2.1 · Cliente API **asíncrono** de metadatos PyPI | 🟡 | Hecho pero **síncrono** (requests), no async |
| 2.1 · Descarga de distribuciones (.tar.gz/.zip/.tgz) | ✅ | `fetcher.download_archive` + soporte tar/zip/whl |
| 2.1 · Extracción segura anti-path-traversal | ✅ | `safe_extract` (anti Zip Slip, symlinks, zip-bomb) |
| 2.1 · Limpieza automática con `tempfile` | ❌ | Hoy se cachea en `data/cache` (persistente), sin limpieza automática |
| 2.2 · Recolección dataset benigno | ✅ | `scripts/collect_benign.py` (probado con PyPI real) |
| 2.3 · Recolección dataset malicioso | ⏳ | Guía lista (`docs/DATASET.md`); la descarga se hace en tu máquina (GitHub bloqueado aquí) |
| 2.4 · Limpieza/curación del dataset | 🟡 | `scripts/build_dataset.py` (dedup por sha256 + split 80/20); falta correrlo con datos reales |

## Fase 3 — Extracción y ML
| Tarea | Estado | Nota |
|---|---|---|
| 3.1 · Entropía de Shannon (base) | ✅ | `shannon_entropy` |
| 3.1 · Ventana deslizante 256 bytes | ✅ | (bloques de 256 B; revisar si quieres solape real) |
| 3.1 · Filtro de binarios con **Magic Numbers** | ❌ | No implementado; hoy solo se analizan `*.py` |
| 3.1 · Flagging .py/.js/.json con entropía > **7.2** | 🟡 | Umbral en **7.0** (no 7.2) y solo `.py` (no .js/.json) |
| 3.2 · Top 5000 PyPI (descarga + caché) | 🟡 | `scripts/fetch_top_pypi.py` listo; corre en tu máquina. Hoy usa lista semilla |
| 3.2 · Typosquatting (Levenshtein/rapidfuzz) | ✅ | `MetadataExtractor` |
| 3.2 · Combosquatting (sufijos/prefijos) | ✅ | Detección de afijos |
| 3.2 · **Slopsquatting** y anomalías de publicación | ❌ | No implementado |
| 3.3 · NodeVisitor AST (setup.py / __init__.py) | ✅ | `ASTExtractor` sobre todos los `.py`, incl. hook de install en setup.py |
| 3.3 · **Parser JavaScript** (esprima/acorn) | ⚠️❌ | No hecho — **y contradice el alcance PyPI-only de la tesis** |
| 3.3 · Detector de sockets/IPs hardcodeadas | ✅ | `network_literals` (URLs + IPs) |
| 3.4 · Consolidación tabular de features | ✅ | `FeatureVector` + `build_features` |
| 3.5 · Entrenamiento del clasificador ML | ⏳ | **Sprint 5** (lo siguiente) |

## Fase 4 — Integración, validación, benchmarking
| Tarea | Estado | Nota |
|---|---|---|
| 4.1 · Ingesta dataset etiquetado | 🟡 | `build_dataset.py` (falta correr con datos) |
| 4.1 · Batch scanning de miles de muestras | ⏳ | Pendiente (requiere dataset) |
| 4.1 · Matriz de confusión y F1 | ⏳ | Pendiente (Sprint 5) |
| 4.1 · Threshold tuning | ⏳ | Pendiente |
| 4.1 · Tests pytest + **GitHub Actions** | 🟡 | **36 pruebas pytest ✅**; falta CI (en Azure sería **Azure Pipelines**, no GitHub Actions) |
| 4.2 · ROC/AUC | ⏳ | Pendiente |
| 4.3 · CLI typer con `--package` y `--ecosystem (npm/pypi)` | 🟡 | CLI typer ✅; **sin `--ecosystem`** (npm fuera de alcance) |
| 4.3 · **Agregador de scores ponderado** (M2·0.2+M3·0.4+M4·0.4) | ⚠️❌ | No hecho — **choca con la decisión por ML de la tesis** (ver abajo) |
| 4.3 · Salida JSON compatible **SARIF** | 🟡 | Hay JSON (pydantic); **falta el formato SARIF** |
| 4.3 · Concurrencia con `concurrent.futures` | ❌ | Hoy los extractores corren en secuencia |
| 4.4 · Benchmarking vs GuardDog/Semgrep | ⏳ | Pendiente |

## Fase 5 — Documentación y tesis
| Tarea | Estado | Nota |
|---|---|---|
| 5.1 Redacción de capítulos | 🟡 | Tesis avanzada; paper CONITTI en borrador |
| 5.2 Publicación open-source | 🟡 | Repo en Azure DevOps; el backlog dice GitHub |
| 5.3 Sustentación | ⏳ | Pendiente |

---

## ⚠️ Tres inconsistencias del backlog que conviene decidir

1. **npm / JavaScript vs PyPI-only.** El backlog incluye parser JS (esprima/acorn) y
   un flag `--ecosystem npm`. La **tesis dejó npm explícitamente fuera de alcance**
   (PyPI-only; npm es trabajo futuro). Hay que reconciliar: o se quitan esas tareas
   del backlog, o se cambia el alcance de la tesis (no recomendado a esta altura).

2. **Decisión por ML vs agregador ponderado.** El backlog tiene un "agregador de
   scores ponderado" (M2·0.2 + M3·0.4 + M4·0.4), que es una **regla fija**. La tesis
   justifica usar **ML en lugar de umbrales/pesos fijos**. Hay que definir: ¿el
   veredicto final lo da el clasificador ML (tesis) o la fórmula ponderada (backlog)?
   El paper se cae si decimos ambas cosas.

3. **GitHub vs Azure DevOps.** El backlog menciona GitHub, ramas `develop`,
   pre-commit y GitHub Actions; el proyecto vive en **Azure DevOps**. Conviene
   alinear el texto del backlog (Repos de Azure, Azure Pipelines) o mover a GitHub.

## Resumen
- **Núcleo del MVP (Fases 2.1 y 3.1–3.4): mayormente ✅** — fetcher seguro, los tres
  extractores y la consolidación de features funcionan y están probados (36 tests).
- **Pendiente de verdad:** Sprint 5 (ML + dataset + métricas) y varias tareas
  "de pulido" (pre-commit, SARIF, concurrencia, CI, slopsquatting, magic numbers).
- **Decisiones de alcance:** las tres inconsistencias de arriba.
