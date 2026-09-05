# Experimento: pyscan frente a varios antivirus (VirusTotal)

Amplía la comparación con antivirus: en lugar de un solo motor (ClamAV), consulta
**VirusTotal**, que agrega ~60–70 motores antivirus comerciales a la vez. Responde
la observación del director de comparar contra *varios* antivirus, no uno.

## Cómo funciona

Para cada muestra del hold-out se calcula el **sha256** y se consulta por hash a
la API de VirusTotal. **No se suben archivos**: solo se consulta el hash, lo que
es más privado y rápido. Se reporta Recall, Precisión, F1 y falsos positivos de
pyscan frente al agregado de VirusTotal, más el Recall de los motores individuales
que más malware detectaron.

- Muestras **archivo** (benignos): un hash por muestra.
- Muestras **carpeta** (malware extraído de DataDog): se consulta el hash de cada
  archivo (hasta `--max-files`) y la muestra se marca si algún archivo es
  detectado, igual que hace ClamAV recursivamente.
- Una muestra se cuenta como maliciosa para VirusTotal si al menos
  `--min-detections` motores marcan el hash (por defecto 2, para no contar una
  falsa alarma aislada de un solo motor).

## Advertencia metodológica (para la sustentación)

Si un hash **no está** en la base de VirusTotal, se cuenta como "no detectado".
Es una medida conservadora y honesta: muchas muestras de la cadena de suministro
de PyPI no tienen firma en los antivirus tradicionales, por lo que se espera un
Recall agregado bajo. Ese resultado **no es negativo**: evidencia que ni la suma
de decenas de antivirus generales basta, y justifica una herramienta
especializada como pyscan.

## Requisitos

1. Una **API key gratuita** de VirusTotal: regístrate en
   https://www.virustotal.com/gui/join-us y copia tu clave.
2. La API gratuita permite ~4 consultas/minuto y 500/día. Por eso el muestreo por
   clase es pequeño y hay control de velocidad. No necesitas instalar nada extra
   (usa `requests`, que ya es dependencia).

## Uso (en la VM)

```bash
cd ~/Tesis && git pull
source .venv/bin/activate

# la clave va en una variable de entorno; nunca en el código ni en el repo
export VT_API_KEY=tu_clave_de_virustotal

# empieza pequeño para no gastar la cuota
python scripts/experiment_compare_virustotal.py --limit-per-class 20

# corrida más grande (tarda ~20-40 min por el límite de velocidad)
python scripts/experiment_compare_virustotal.py --limit-per-class 40
```

Opciones útiles: `--min-detections N` (umbral de motores), `--max-files N`
(archivos por carpeta a consultar), `--qpm N` (consultas por minuto; sube solo si
tienes una cuenta de pago).

## Salidas

`data/analysis/compare_virustotal.json` y `compare_virustotal_per_sample.csv`:
Recall/Precisión/F1/FP de pyscan vs VirusTotal, Recall por motor individual y
desglose por fuente del malware.

El panel web (pestaña **Panel** → *pyscan frente a otras herramientas*) toma ese
JSON automáticamente y grafica pyscan junto a ClamAV (un antivirus) y VirusTotal
(60+ motores). No hay que hacer nada extra: basta con que el archivo exista.

## Interpretación esperada

- **pyscan** debería tener el Recall más alto sobre el malware de PyPI.
- **VirusTotal (agregado)** superará a ClamAV solo (más motores = más cobertura),
  pero seguirá por debajo de pyscan en las muestras específicas de PyPI.
- Los **falsos positivos** de los antivirus suelen ser muy bajos (casi no marcan
  nada); eso no es una ventaja: significa que **dejan pasar** el malware de la
  cadena de suministro.
