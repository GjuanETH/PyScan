# Guía de construcción y expansión del dataset

El cuello de botella del proyecto **no son los paquetes benignos** (PyPI tiene
cientos de miles y se descargan a voluntad) sino las **muestras maliciosas**:
son escasas y PyPI las elimina rápido. Si hoy tienen ~500-800 muestras y
necesitan ≥2.000, la estrategia correcta **no es inventar ni aumentar
sintéticamente** código malicioso, sino **agregar y deduplicar varios datasets
públicos de investigación**.

> Nota de entorno: este sandbox **no** puede clonar GitHub (api/raw/`git clone`
> fallan). Los pasos de descarga de los datasets maliciosos hay que correrlos en
> **tu máquina local** (que sí tiene acceso). La recolección de benignos desde
> PyPI sí funciona aquí (`scripts/collect_benign.py`).

## 1. Fuentes de muestras maliciosas (para agregar)

| Fuente | Contenido | Notas |
|---|---|---|
| **PyPI Malregistry** (`lxyeternal/pypi_malregistry`) | Maliciosos PyPI etiquetados | Es el que probablemente ya usan |
| **DataDog/malicious-software-packages-dataset** | PyPI + npm, **actualizado constantemente** | Mayor volumen; ZIPs cifrados con contraseña `infected`. **La mayor palanca para escalar** |
| **Backstabber's Knife Collection (BKC)** (Ohm et al.) | Maliciosos PyPI + npm (académico) | Clásico de la literatura; ya lo citan [4] |
| **MalOSS** (`osssanitizer/maloss`) | Maliciosos multi-ecosistema | Académico |
| **OSV.dev** (avisos `MAL-…` de PyPI) | Nombres/versiones + metadatos | Inventario; los artefactos vienen de las fuentes de arriba |

> Verifiquen el conteo real de cada repo al clonarlo (no asuman cifras). Combinando
> DataDog + BKC + Malregistry suele superarse cómodamente el objetivo de 2.000
> muestras **únicas** de PyPI.

## 2. Regla de oro: deduplicar y contar lo ÚNICO

Las campañas de malware se repiten entre datasets (el mismo paquete aparece en
varios). **Cuenten muestras únicas por `sha256`**, no archivos crudos. El modelo
`Package` del MVP ya incluye `sha256` para esto.

```python
# pseudo: unir manifiestos y deduplicar
import pandas as pd
df = pd.concat([pd.read_csv(m) for m in manifests])
df = df.drop_duplicates(subset="sha256")
print("únicos:", len(df), "| maliciosos:", (df.label=="malicious").sum())
```

## 3. Balance de clases (decisión metodológica, va al paper)

- El mundo real es **muy desbalanceado** (malicioso ≪ benigno). No fuercen 1:1 a ciegas.
- Para entrenar: un ratio moderado (1:1 a 1:4 malicioso:benigno) funciona bien con
  `class_weight="balanced"` en Random Forest / XGBoost.
- **El hold-out (20%) debe reflejar un ratio realista** o, como mínimo, reportar las
  métricas con cuidado. La métrica prioritaria es **Recall** (no dejar pasar malware),
  coherente con la meta Recall ≥ 0,90.
- Documenten el ratio elegido y por qué: los revisores lo van a preguntar.

## 4. Riesgo de fuga (data leakage) — evitarlo

Si **todo** lo malicioso viene de una campaña y **todo** lo benigno del Top de
descargas, el clasificador puede aprender artefactos del dataset (p. ej. "tiene
README", antigüedad, número de releases) en vez de señales de malicia. Mitigación:

- Mezclen varias campañas/fuentes de maliciosos.
- Incluyan benignos "poco populares" además del Top (paquetes nuevos, pocos releases).
- Revisen la importancia de características (`feature_importance`) buscando señales
  sospechosamente "fáciles".

## 5. Flujo recomendado (reproducible)

```bash
# (A) En tu máquina local — descargar maliciosos
git clone https://github.com/lxyeternal/pypi_malregistry
git clone https://github.com/DataDog/malicious-software-packages-dataset
# (descifrar los ZIP de DataDog con contraseña "infected")
git clone https://github.com/cybertier/Backstabbers-Knife-Collection

# (B) Normalizar al layout de pyscan (un manifiesto por fuente)
python scripts/build_dataset.py --malicious-src <ruta_a_cada_repo> ...

# (C) Aquí o en local — recolectar benignos del Top de PyPI
python scripts/fetch_top_pypi.py --limit 5000          # refresca la lista
python scripts/collect_benign.py --limit 2000          # descarga benignos

# (D) Unir + deduplicar + dividir 80/20 (k-fold k=5 en validación interna)
python scripts/build_dataset.py --merge --split 0.2 --seed 42
```

## 6. Cómo se conecta con los Resultados (sección IV del paper)

Una vez tengan el dataset unificado y los tres extractores (metadatos ✓, entropía
y AST pendientes), se entrena el clasificador y se mide cada KPI de la Tabla I.
Esos números reales (Recall, F1, FP, tiempo, RAM, matrices de confusión) son los
que rellenan la sección IV, que hoy está como `[COMPLETAR]`.
