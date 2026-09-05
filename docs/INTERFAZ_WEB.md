# Interfaz web de pyscan

Interfaz gráfica local que corre en el navegador y reutiliza el mismo motor de
análisis del CLI. Permite pegar nombres de paquetes o el contenido de un
`requirements.txt`, ver el veredicto de cada dependencia, y mantener actualizada
la lista de referencia del Top de PyPI.

> Es una capa de presentación sobre el MVP; no cambia la arquitectura. Se ejecuta
> solo en local (127.0.0.1) y nunca ejecuta el código de los paquetes.

## Requisitos

```bash
pip install flask          # o:  pip install -e ".[web,ml]"
```

Para ver el veredicto del modelo se necesita `data/models/model.joblib`
(entrenado con `scripts/train_model.py`). Sin él, la interfaz muestra igualmente
las señales del análisis, pero sin veredicto.

## Ejecutar

```bash
python scripts/webapp.py
```

Abre el navegador en **http://127.0.0.1:5000**.

## Uso

1. Pega los nombres de los paquetes (uno por línea) o el contenido de tu
   `requirements.txt` en la caja de texto.
2. Pulsa **Analizar**. Cada dependencia se descarga de PyPI y se analiza; la
   tabla muestra el veredicto (MALICIOSO / benigno) y los motivos.
3. **Actualizar lista de referencia** refresca la lista del Top de PyPI usada
   para detectar typosquatting (útil para mantener el detector vigente).

## Pestañas

La barra superior tiene tres vistas:

- **Escanear:** analizar paquetes o archivos (con detalle "por qué" al hacer clic
  en cada fila).
- **Análisis:** resume **lo que tú escaneaste** en la sesión (se actualiza con cada
  escaneo): tarjetas, gráfico de veredictos, señales más frecuentes en lo analizado
  e historial descargable.
- **General:** estadísticas **fijas del modelo y los experimentos** (no cambian con
  tus escaneos).

## Pestaña General (métricas del modelo)

Muestra los resultados del proyecto dentro de la propia herramienta, útil para la
sustentación:

- **KPI del modelo:** Recall (hold-out), F1, tasa de falsos positivos, PR-AUC,
  tiempo máximo por paquete y tamaño del dataset.
- **Vectores de ataque:** gráfico de barras con la frecuencia de cada vector
  (V1–V7), leído de `data/analysis/attack_vectors.json`.
- **Matriz de confusión** de la validación cruzada (VP/FN/FP/VN).
- **Composición del dataset:** anillo maliciosas vs benignas.
- **pyscan frente a otras herramientas:** barras comparando Recall/Precisión/F1/FP
  de pyscan con GuardDog, ClamAV (un antivirus) y VirusTotal (60+ motores), de
  `compare_guarddog.json`, `compare_antivirus.json` y `compare_virustotal.json`;
  si no existen, invita a correr los experimentos.
- **Importancia de características:** qué señales pesan más en la decisión del
  modelo (de `feature_importance` en `metrics.json`).
- **En esta sesión:** contador de lo analizado en la sesión actual.
- **Historial de la sesión:** tabla de todo lo analizado, con botones para
  **descargar en JSON o CSV** (evidencia o integración).

Cada dato del panel muestra una explicación al pasar el mouse (de dónde sale y
cómo se calcula). En la pestaña Escanear, al hacer **clic en una fila** se
despliega el detalle de las 9 características que llevaron al veredicto, con las
señales activas resaltadas.

Las cifras se leen de `data/models/metrics.json`, `data/analysis/attack_vectors.json`,
`data/analysis/benchmark.json`, `compare_guarddog.json` y `compare_antivirus.json`.
Si falta el modelo entrenado, el panel avisa y muestra lo que haya disponible. Usa
Chart.js desde CDN (requiere conexión para los gráficos; KPI y matriz funcionan sin
conexión).

## Endpoints (para integración)

- `GET /` — la página.
- `POST /api/scan` — recibe `{"text": "..."}` y devuelve los resultados en JSON.
- `POST /api/scan-local` — recibe un archivo (multipart) y lo analiza en local.
- `POST /api/update` — refresca la lista de referencia.
- `GET /api/status` — versión y si hay modelo entrenado.
- `GET /api/metrics` — métricas del modelo, vectores y dataset para el panel.

## Nota

El reentrenamiento del modelo (con dataset nuevo) sigue siendo una tarea de línea
de comandos (`train_model.py`), por su costo. El botón de actualización se ocupa
de la lista de referencia; poblar el modelo automáticamente desde la interfaz
queda como línea futura.
