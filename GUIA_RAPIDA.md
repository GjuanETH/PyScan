# Guía rápida — ¿qué hago con pyscan? (Windows)

Esto es el **programa de tu tesis** (el MVP). Aquí está el paso a paso para
ponerlo a funcionar en tu computador. No necesitas saber programar: solo copiar
y pegar comandos.

---

## Paso 0 — Tener Python instalado (una sola vez)

1. Abre el menú Inicio y escribe **`python`**. Si abre algo o si al escribir
   `python --version` en una terminal te muestra un número (ej. `Python 3.11.x`),
   ya lo tienes. Salta al Paso 1.
2. Si no, descárgalo de https://www.python.org/downloads/ e instálalo.
   **IMPORTANTE:** en la primera pantalla del instalador, marca la casilla
   **"Add Python to PATH"** antes de darle a "Install".

---

## Paso 1 — Abrir una terminal en la carpeta del proyecto

1. Abre el Explorador de archivos y entra a la carpeta:
   `...\Trabajo de Grado (1)\pyscan`
2. Haz clic en la barra de dirección (arriba), escribe **`powershell`** y pulsa Enter.
   Se abrirá una ventana negra/azul ya ubicada en esa carpeta.

---

## Paso 2 — Instalar lo que el programa necesita (una sola vez)

Copia y pega esto en la terminal y pulsa Enter:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev,ml]"
```

> Si la segunda línea da un error de "permisos de scripts", ejecuta primero:
> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` y vuelve a intentar.

Sabrás que quedó bien si al inicio de la línea aparece **`(.venv)`**.

> **Atajo:** en vez de los Pasos 1 y 2 puedes hacer doble clic en el archivo
> **`setup.bat`** que está en esta carpeta. Hace lo mismo automáticamente.

---

## Paso 3 — Usar el programa

Con `(.venv)` activo, prueba estos comandos:

```powershell
python -m pyscan.cli scan requests          # analiza un paquete legítimo
python -m pyscan.cli scan reqursts --json   # nombre tipo "typosquat": lo marca sospechoso
python -m pyscan.cli info numpy             # solo muestra los metadatos del paquete
```

Eso ya descarga el paquete de PyPI de verdad y te muestra el análisis disponible
(por ahora, la parte de metadatos / typosquatting).

> **¿Por qué `python -m pyscan.cli` y no solo `pyscan`?**
> En Windows, el "Control de aplicaciones / Smart App Control" suele **bloquear**
> el `pyscan.exe` que crea pip (es un ejecutable nuevo sin firma). Llamarlo como
> módulo (`python -m pyscan.cli ...`) usa `python.exe`, que sí está permitido, y
> evita el problema por completo. Si ves un error "una directiva de Control de
> aplicaciones bloqueó este archivo", esa es la causa.

---

## Paso 4 — Verificar que todo está sano (las pruebas)

```powershell
python -m pytest --cov=pyscan
```

Debe decir que todas las pruebas pasan (`passed`) y mostrar la cobertura (~90%).
Esto es justamente lo que pide el KPI de tu tesis (cobertura ≥ 80%).

---

## ¿Y los resultados del paper?

Todavía no. Para llenar la sección "Resultados" del artículo faltan tres piezas
que construiremos en las próximas sesiones:

1. **Sprint 3** — extractor de entropía (Shannon).
2. **Sprint 4** — extractor de AST.
3. **Sprint 5** — el dataset completo + entrenar el modelo de Machine Learning.

Cuando eso esté, el programa dará los números reales (Recall, F1, etc.) que van
al paper. Para el dataset, mira **`docs/DATASET.md`**.

---

## Cada vez que vuelvas a trabajar

Solo necesitas abrir la terminal en la carpeta `pyscan` y activar el entorno:

```powershell
.\.venv\Scripts\Activate.ps1
```

Y ya puedes usar `pyscan ...` o `pytest`. (El Paso 2 solo se hace una vez.)
