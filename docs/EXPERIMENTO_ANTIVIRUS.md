# Experimento: pyscan frente a un antivirus tradicional (ClamAV)

Compara la efectividad de pyscan con un antivirus de firmas (ClamAV) sobre el
mismo subconjunto del hold-out, y produce las cifras para un gráfico comparativo.

## Por qué ClamAV

Es el antivirus de código abierto estándar, gratuito y scriptable, ideal para
un experimento reproducible. Se ejecuta en la VM donde ya está el dataset.

## Advertencia metodológica (importante para la sustentación)

Los antivirus tradicionales detectan malware por **firmas de amenazas conocidas**
(troyanos, virus de ejecutable), no los patrones de la **cadena de suministro**
en paquetes de PyPI (typosquatting, ejecución en instalación, exfiltración). Por
eso se espera que ClamAV tenga un **Recall bajo** sobre este dataset. Ese
resultado no es negativo: **evidencia que un antivirus general no basta y
justifica una herramienta especializada como pyscan.** Repórtalo así, con
honestidad.

## Pasos (en la VM)

1. Instalar ClamAV y actualizar la base de firmas:

```bash
sudo apt-get update
sudo apt-get install -y clamav
sudo freshclam        # descarga la base de firmas (puede tardar)
```

2. Traer el script (tras subirlo desde Windows con subir_a_azure.bat):

```bash
cd ~/Tesis && git pull
source .venv/bin/activate
```

3. Correr la comparación (empieza con pocas muestras para ver que funcione):

```bash
python scripts/experiment_compare_antivirus.py --limit-per-class 50
# corrida completa:
python scripts/experiment_compare_antivirus.py --limit-per-class 150
```

Si `clamscan` no estuviera en el PATH, pásalo con `--clamscan-bin /ruta/clamscan`.

## Salidas

`data/analysis/compare_antivirus.json` y `compare_antivirus_per_sample.csv`:
Recall, Precisión, F1 y FP de pyscan vs ClamAV, con desglose por fuente.

## Interpretación

- **pyscan** debería superar ampliamente a ClamAV en Recall (detecta el malware
  de PyPI), mientras que ClamAV detectará solo las muestras que además contengan
  una firma de malware tradicional conocida.
- La columna de **falsos positivos** de ClamAV suele ser muy baja (0), porque casi
  no marca nada; eso no es una ventaja: significa que **deja pasar el malware**.
- Envía el `compare_antivirus.json` al asistente para armar el gráfico y el
  documento de análisis, como se hizo con la comparación con GuardDog.
