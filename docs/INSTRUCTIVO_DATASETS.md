# Instructivo: descarga y manejo de datasets para pyscan

Guía paso a paso para armar un dataset de entrenamiento **grande, diverso y sin
fuga de datos**, combinando varias fuentes públicas. Todo se corre **en tu
máquina** (el sandbox de Cowork no puede clonar GitHub). Verificado en agosto 2026.

> Regla de oro del proyecto: **no se inventa ni se genera sintéticamente** código
> malicioso. Se agregan datasets reales de investigación y se **deduplica por
> `sha256`**.

---

## 0. Resumen ejecutivo (el camino corto)

Con **DataDog + PyPI Malregistry** ya superas de sobra el objetivo de ≥2.000
muestras maliciosas únicas de PyPI. Las demás fuentes suman diversidad (clave
para evitar sobreajuste) o sirven para etiquetar.

```
DataDog (parte PyPI)  +  Malregistry  ->  deduplicar  ->  submuestrear  ->  entrenar
```

---

## 1. Fuentes recomendadas

### (A) Con código real — lo que necesitan los extractores de pyscan

| # | Fuente | Volumen (ago. 2026) | Licencia | Formato | Prioridad |
|---|--------|--------------------|----------|---------|-----------|
| 1 | **DataDog** `DataDog/malicious-software-packages-dataset` | **27.876** maliciosos (PyPI + npm + otros), en crecimiento | Apache-2.0 | ZIP cifrado, contraseña `infected` | **Alta** |
| 2 | **PyPI Malregistry** `lxyeternal/pypi_malregistry` | **>10.000** paquetes PyPI (act. 14 jun. 2026) | Investigación (ASE 2023) | `.tar.gz` originales en `<pkg>/<ver>/` | **Alta** |
| 3 | **Backstabber's Knife Collection** `cybertier/Backstabbers-Knife-Collection` | 174 paquetes (≈28 PyPI) | Acceso bajo solicitud justificada | archivos | Media (clásico académico, ya citado) |
| 4 | **MalOSS** `osssanitizer/maloss` | multi-ecosistema | Investigación | archivos/metadatos | Baja |

### (B) Inventarios / avisos (OSV) — solo nombres+versiones, **sin código**

Sirven para etiquetar o cruzar, no como fuente de artefactos (PyPI ya los borró).

| Fuente | Uso |
|--------|-----|
| **OpenSSF** `ossf/malicious-packages` | Base comunitaria en formato OSV (PyPI+npm), alimenta OSV.dev |
| **OSV.dev** (avisos `MAL-…`) | API + `osv-scanner` + deps.dev para verificar si un paquete es malicioso |
| **ecosyste.ms** `ecosyste-ms/typosquatting-dataset` | Mapa curado de typosquats → objetivo legítimo (útil para validar el extractor de metadatos) |

### (C) Benignos — abundantes, se descargan de PyPI

No son el cuello de botella. Usa el script del proyecto:

```powershell
python scripts/fetch_top_pypi.py --limit 5000     # refresca la lista Top-PyPI
python scripts/collect_benign.py --limit 2000     # descarga .tar.gz benignos
```

> Incluye también benignos **poco populares** (pocos releases, recién publicados),
> no solo el Top. Si todo lo benigno es "popular y maduro", el modelo puede
> aprender esa diferencia en vez de la malicia real (fuga de datos).

---

## 2. Descarga paso a paso (Windows PowerShell / Git Bash)

Coloca todo bajo una carpeta de trabajo, por ejemplo `datasets_raw/`.

```bash
# --- Fuente 1: DataDog (grande) ---
git clone https://github.com/DataDog/malicious-software-packages-dataset datasets_raw/datadog

# --- Fuente 2: Malregistry ---
git clone https://github.com/lxyeternal/pypi_malregistry datasets_raw/malregistry

# --- (opcional) Fuente 3: Backstabber's — requiere solicitar acceso ---
# https://dasfreak.github.io/Backstabbers-Knife-Collection/
```

Los ZIP de DataDog **están cifrados a propósito** (contraseña `infected`) para que
ningún antivirus los borre y para que no se ejecuten por accidente. **No los abras
haciendo doble clic.**

---

## 3. Importar al layout de pyscan

El proyecto espera las muestras bajo `data/benign/<fuente>/…` y
`data/malicious/<fuente>/…`. Cada muestra puede ser un **archivo** (`.tar.gz`) o
una **carpeta** de código extraído; `build_dataset.py` soporta ambos.

### 3.1 DataDog → automático (descifra solo la parte PyPI)

```powershell
python scripts/import_datadog.py --src datasets_raw/datadog --only-intent
# opciones: --limit 3000 (tope)   quita --only-intent para incluir 'compromised'
```

Esto descifra cada ZIP PyPI y lo deja en `data/malicious/datadog/<pkg>-<ver>/`,
deduplicando por `sha256` del ZIP. Nunca ejecuta el código.

### 3.2 Malregistry → copiar la parte PyPI

Malregistry ya trae los `.tar.gz` originales. Cópialos preservando estructura:

```powershell
# PowerShell
New-Item -ItemType Directory -Force data/malicious/malregistry | Out-Null
Copy-Item -Recurse datasets_raw/malregistry/* data/malicious/malregistry/
```

```bash
# Git Bash / Linux
mkdir -p data/malicious/malregistry
cp -r datasets_raw/malregistry/* data/malicious/malregistry/
```

`build_dataset.py` encontrará tanto los `.tar.gz` como las carpetas con `.py`.

### 3.3 Backstabber's Knife Collection y MalOSS → importador genérico

`import_dataset.py` integra cualquier fuente nueva (deduplica por `sha256`, nunca
ejecuta código). Sirve para estas dos y para futuras.

```bash
# Backstabber's: los artefactos suelen venir en ZIP cifrados (contraseña 'infected')
python scripts/import_dataset.py --src datasets_raw/backstabbers \
    --source backstabbers --password infected --path-filter pypi --include-dirs

# MalOSS: archivos o carpetas; se filtra solo la parte de PyPI
python scripts/import_dataset.py --src datasets_raw/maloss \
    --source maloss --path-filter pypi --include-dirs
```

Cada fuente queda en `data/malicious/<source>/` y `build_dataset.py` la detecta
sola (registra el `source` para auditar el balance por origen).

### 3.4 Segunda fuente benigna → muestra aleatoria de PyPI

Para no sesgar el modelo hacia paquetes "populares y maduros", se agrega una
muestra **aleatoria** del índice completo de PyPI (además del Top):

```bash
python scripts/fetch_random_pypi.py --limit 1000 --seed 42
python scripts/collect_benign.py --names-file data/random_pypi_names.txt \
    --out data/benign/pypi_random --limit 1000
```

Con esto el dataset queda con **6 fuentes**: 4 maliciosas (DataDog, Malregistry,
Backstabber's, MalOSS) y 2 benignas (Top-PyPI y muestra aleatoria).

---

## 4. Unificar, deduplicar y balancear

```powershell
python scripts/build_dataset.py --max-malicious 2000 --ratio 2.0 --split 0.2 --seed 42
```

Qué hace cada opción:

- `--max-malicious 2000` — **submuestrea** los maliciosos a 2.000 (no uses los 27k;
  desbalance extremo y tiempos enormes). Ajústalo según tu hardware.
- `--ratio 2.0` — 2 benignos por cada malicioso (1:1 a 1:4 es razonable). Un ratio
  moderado + `class_weight="balanced"`/SMOTE maneja bien el desbalance.
- `--split 0.2` — reserva 20 % como hold-out **estratificado por clase**.
- `--seed 42` — reproducibilidad (documenta la semilla en el paper).

Salida: `data/dataset.csv`, `data/train.csv`, `data/holdout.csv`, con columnas
`path, kind, label, source, sha256`. Imprime el **conteo por fuente** — pégalo en
la sección de metodología del paper como evidencia de diversidad.

---

## 5. Entrenar (Sprint 5)

```powershell
python scripts/train_model.py --k 5 --target-recall 0.90 --holdout
```

Detalles y justificación en `docs/SPRINT5_ML.md`. Produce
`data/models/model.joblib` y `data/models/metrics.json` (Recall, F1, PR-AUC,
matriz de confusión, tasa de FP, importancia de características → **Resultados**).

---

## 6. Evitar la fuga de datos (lo que preguntará el jurado)

1. **Deduplica por `sha256`** — las campañas se repiten entre datasets. Ya lo hace
   `build_dataset.py`; verifica que "únicas" < "crudas".
2. **Mezcla fuentes de maliciosos** (DataDog + Malregistry, no una sola campaña).
3. **Diversifica los benignos** (populares + poco populares).
4. **SMOTE solo dentro de cada fold de entrenamiento** — nunca sobre validación ni
   hold-out. Ya está implementado así.
5. **Revisa `feature_importance`**: si una sola característica "trivial" domina
   (p. ej. `has_long_description`), sospecha de un artefacto del dataset, no de
   una señal de malicia real.

---

## 7. Ética, seguridad y citación

- Estás manejando **malware real**. No lo ejecutes; pyscan solo hace análisis
  estático. Trabaja en una carpeta aislada y, si puedes, en una VM.
- **Cita cada fuente** en el paper. DataDog (Apache-2.0) exige atribución;
  Malregistry pide citar el paper ASE 2023 ("An Empirical Study of Malicious Code
  in PyPI Ecosystem"); Backstabber's, el paper de Ohm et al. (2020).
- Registra en el paper: fuentes usadas, conteos por fuente, ratio elegido,
  semilla y fecha de descarga (el dataset cambia con el tiempo).

---

## Fuentes verificadas (URLs)

- DataDog: https://github.com/DataDog/malicious-software-packages-dataset
- PyPI Malregistry: https://github.com/lxyeternal/pypi_malregistry
- Backstabber's Knife Collection: https://dasfreak.github.io/Backstabbers-Knife-Collection/
- OpenSSF malicious-packages: https://github.com/ossf/malicious-packages
- ecosyste.ms typosquatting-dataset: https://github.com/ecosyste-ms/typosquatting-dataset
- OSV.dev: https://osv.dev
