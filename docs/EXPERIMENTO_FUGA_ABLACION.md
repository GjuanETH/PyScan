# Experimento: fuga de datos y ablación de características

Este experimento responde la principal amenaza a la validez del modelo detectada
en el Objetivo 1: **la posible dependencia excesiva de las señales de nombre**
(`name_min_distance`, `is_typosquat`, `has_combo_affix`).

## Por qué existe la sospecha

Los paquetes benignos del dataset provienen del Top de PyPI, que es **la misma
lista** usada como referencia para medir la similitud de nombres. Por eso su
`name_min_distance` tiende a 0, mientras que los maliciosos tienen distancia > 0.
El modelo podría estar aprendiendo "¿el nombre está en el top?" en lugar de
"¿esto es malicioso?". En el modelo entrenado, esas señales concentraban ~77 %
de la importancia de características, lo que refuerza la sospecha.

## Qué hace el script

`scripts/experiment_ablation.py` reentrena el clasificador con distintos
subconjuntos de características —reutilizando la misma validación cruzada
estratificada y el mismo ajuste de umbral del entrenamiento principal— y compara
las métricas. Usa la caché `data/features_train.csv` ya calculada, así que **no
vuelve a extraer nada** y corre en segundos.

Configuraciones evaluadas: Todas (baseline), Solo nombre, Sin nombre (prueba de
fuga), Solo código (AST+entropía), Solo AST, Solo entropía, Solo metadatos.

## Cómo correrlo (en la VM)

```bash
cd ~/Tesis
source .venv/bin/activate
python scripts/experiment_ablation.py --k 5 --target-recall 0.90
# opcional, con XGBoost (el algoritmo que quedó seleccionado):
python scripts/experiment_ablation.py --k 5 --xgb
```

Requiere haber corrido antes `scripts/train_model.py` (para tener la caché de
características). Instala matplotlib si quieres el gráfico: `pip install matplotlib`.

## Salidas

- `data/analysis/ablation.json` y `ablation.csv` — métricas por configuración.
- `data/analysis/ablation.png` — gráfico de barras (Recall y F1) para la tesis.
- En consola: tabla comparativa + **interpretación automática**.

## Cómo interpretar (esto va en la tesis)

| Observación | Conclusión |
|---|---|
| "Solo nombre" ≈ "Todas" | **Hay fuga**: el nombre domina la decisión. Las métricas del baseline están infladas por el diseño del dataset. |
| "Sin nombre" mantiene Recall alto (≥0,85) | Las señales de **código (AST/entropía) discriminan por sí solas**: resultado deseable, el modelo es robusto ante evasión de nombre. |
| "Sin nombre" cae mucho | El modelo **depende del nombre**; se debe diversificar el conjunto benigno (paquetes fuera de la lista de referencia) y reentrenar. |
| "Solo AST" vs "Solo entropía" | Muestra **cuál extractor aporta más** (estudio de ablación). |

### Reporte honesto

Sea cual sea el resultado, se reporta tal cual. Si confirma la fuga, la
conclusión no es "el modelo es malo", sino que **el desempeño real depende de las
señales de código**, y el número del baseline debe leerse con esa salvedad. Esto
demuestra rigor y es exactamente lo que un jurado espera ver ante una amenaza a
la validez bien identificada.

## Siguiente paso (si se confirma la fuga)

Fuga fuerte → construir un conjunto benigno **diverso** (paquetes "long-tail",
fuera del Top de PyPI de referencia) con `collect_benign.py` apuntando a nombres
de rango bajo, reconstruir el dataset y reentrenar. El modelo resultante mide la
capacidad real de las señales de código, sin el atajo del nombre.
