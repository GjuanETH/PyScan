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

## Endpoints (para integración)

- `GET /` — la página.
- `POST /api/scan` — recibe `{"text": "..."}` y devuelve los resultados en JSON.
- `POST /api/update` — refresca la lista de referencia.
- `GET /api/status` — versión y si hay modelo entrenado.

## Nota

El reentrenamiento del modelo (con dataset nuevo) sigue siendo una tarea de línea
de comandos (`train_model.py`), por su costo. El botón de actualización se ocupa
de la lista de referencia; poblar el modelo automáticamente desde la interfaz
queda como línea futura.
