# pyscan como ejecutable (doble clic, sin montar entorno)

Empaqueta la interfaz web de pyscan en un único ejecutable con PyInstaller. El
usuario final hace doble clic y se abre la página en el navegador: no necesita
instalar Python ni activar entornos.

> Es una **capa de distribución**, no cambia la arquitectura ni el núcleo de la
> tesis. El motor sigue siendo el mismo CLI + análisis estático + modelo ML.

## Idea general

- El ejecutable se **construye una vez** en una máquina con Python (el resto de
  máquinas ya no lo necesitan).
- El ejecutable **es específico del sistema operativo**: en Windows se construye
  `pyscan.exe`; en Linux, un binario `pyscan`. No hay uno universal.
- La carpeta `data/` (modelo y resultados) **no va dentro** del ejecutable: se
  coloca a su lado, para poder actualizar el modelo o los experimentos sin
  reconstruir.

## Construir en Windows (recomendado para la sustentación)

Necesitas una vez: Python 3.10+ instalado en Windows y el proyecto descargado.

```bat
cd pyscan
build_exe.bat
```

El script crea el entorno si no existe, instala PyInstaller y construye. Al
terminar tendrás `dist\pyscan.exe`.

## Construir en Linux (p. ej. en la VM)

```bash
cd ~/Tesis
bash build_exe.sh          # genera dist/pyscan (binario Linux)
```

## Preparar la carpeta para usar/entregar

Junto al ejecutable debe quedar una carpeta `data/` con, al menos, el modelo:

```
pyscan.exe            (o  pyscan  en Linux)
data\
  models\
    model.joblib      <- imprescindible (el veredicto)
    metrics.json      <- opcional (KPI del panel)
  analysis\
    attack_vectors.json      <- opcional (gráfico de vectores)
    compare_guarddog.json    <- opcional (comparativa)
    compare_antivirus.json   <- opcional (comparativa)
    compare_virustotal.json  <- opcional (comparativa)
  dataset.csv         <- opcional (composición del dataset)
```

Solo `model.joblib` es obligatorio para escanear. Los demás archivos pueblan las
gráficas del panel; si faltan, el panel avisa y muestra lo que haya.

Copia el `model.joblib` (y los JSON que quieras) desde la VM a esa carpeta `data`.

## Usar

Doble clic en `pyscan.exe`. Se abre una ventana de consola (déjala abierta) y el
navegador en `http://127.0.0.1:5000`. Para cerrar pyscan, cierra esa ventana.

## Notas y limitaciones (honestas)

- **Tamaño:** el ejecutable pesa varios cientos de MB porque incluye
  scikit-learn/XGBoost. Es normal en apps de ML empaquetadas.
- **Antivirus de Windows:** SmartScreen puede advertir por ser un ejecutable sin
  firma digital. Es esperable en un binario propio; se abre con "Más información
  → Ejecutar de todas formas".
- **Modelo entre sistemas:** un `model.joblib` entrenado en Linux normalmente
  funciona en Windows si las versiones de scikit-learn/XGBoost coinciden. Si diera
  problemas, reentrena en el mismo sistema donde correrá el ejecutable.
- **El botón "Actualizar lista"** queda desactivado en el ejecutable (esa tarea
  se hace desde el código fuente); todo lo demás funciona igual.
- **Internet:** los gráficos usan Chart.js desde CDN, así que las gráficas del
  panel necesitan conexión. El escaneo de paquetes de PyPI también requiere red.
