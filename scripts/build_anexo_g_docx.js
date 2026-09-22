// Anexo G — Manejo y preparación de los datos. Cifras de data/models/metrics.json.
const C = require("./anexos_common");
const { t, p, h1, bullet, code, title, caption, source, table, n, miles, save, readJSON } = C;
const m = readJSON("data/models/metrics.json");

// Composición del manifiesto (train.csv / holdout.csv, 22-sep-2026)
const COMP = [
  ["Datadog Security Labs (parte PyPI)", "Maliciosa", 264, 70],
  ["PyPI Malregistry", "Maliciosa", 1336, 330],
  ["Top de PyPI", "Benigna", 1599, 401],
  ["Muestra aleatoria de PyPI", "Benigna", 384, 95],
];
const trM = COMP.reduce((a, r) => a + r[2], 0), hoM = COMP.reduce((a, r) => a + r[3], 0);
const HO_N = m.holdout.n_samples;
const TR_N = m.n_samples;

const c = [];
c.push(...title("ANEXO G", "MANEJO Y PREPARACIÓN DE LOS DATOS"));
c.push(p("Este anexo describe, de forma verificable, cómo se construyó el conjunto de datos con el que se entrena y evalúa el clasificador de pyscan: qué fuentes se usaron, cómo se ingirieron, limpiaron, deduplicaron y etiquetaron las muestras, y cómo se dividieron para evitar la fuga de datos. Todo el proceso es reproducible mediante los scripts del proyecto y semillas fijas."));

c.push(h1("G.1 Objetivo y alcance"));
c.push(p("El alcance del dato es deliberadamente acotado: únicamente paquetes del ecosistema PyPI y únicamente análisis estático. En ningún momento del flujo se ejecuta el código de las muestras; solo se descomprime para su lectura."));

c.push(h1("G.2 Fuentes de datos"));
c.push(p("El conjunto combina dos fuentes públicas de paquetes maliciosos reales y dos orígenes de paquetes benignos. La muestra aleatoria del índice de PyPI se incorporó para que el modelo no asociara la benignidad con la popularidad del paquete, sesgo que aparece cuando todos los benignos provienen de los paquetes más descargados. Una quinta fuente, MalOSS, aporta solo nombres y se usa como referencia (Tabla G.1)."));
c.push(caption("Tabla G.1. Fuentes de datos y su uso."));
c.push(table([0.25, 0.13, 0.30, 0.18, 0.14], ["Fuente", "Clase", "Contenido", "Uso", "Muestras"], [
  ["DataDog malicious-software-packages-dataset", "Maliciosa", "Parte PyPI de un dataset curado y verificado manualmente (ZIP cifrado).", "Entrenamiento y evaluación", "334"],
  ["PyPI Malregistry", "Maliciosa", "Registro de paquetes maliciosos de PyPI (Guo et al., ASE 2023), .tar.gz originales.", "Entrenamiento y evaluación", "1.666"],
  ["Top de PyPI", "Benigna", "Paquetes más descargados de PyPI.", "Entrenamiento y evaluación", "2.000"],
  ["Muestra aleatoria de PyPI", "Benigna", "Muestra del índice completo de PyPI (semilla 42).", "Entrenamiento y evaluación (anti-sesgo)", "479"],
  ["MalOSS", "Maliciosa (nombres)", "52 nombres de paquetes maliciosos de PyPI, sin código.", "Referencia de etiquetado", "—"],
]));
c.push(source());
c.push(p("Inventarios como OSV.dev, OpenSSF malicious-packages o MalOSS aportan nombres y avisos, pero no el artefacto con el código; por eso se emplean como referencia y no como muestras para los extractores. Backstabber's Knife Collection (Ohm et al.) no se incorporó porque su acceso requiere una solicitud con correo institucional; queda como ampliación futura."));

c.push(h1("G.3 Consideraciones éticas y de seguridad"));
c.push(p("El manejo de malware real exige cuidados. Se adoptaron cuatro medidas:"));
c.push(bullet("Las muestras maliciosas nunca se ejecutan: el pipeline solo las descomprime y lee su código."));
c.push(bullet("El trabajo con las muestras se realiza en una máquina virtual aislada (VirtualBox, Ubuntu 26.04 LTS, 2 vCPU, 4 GB de RAM), separada del entorno personal."));
c.push(bullet("Se respeta el cifrado de origen: los ZIP de DataDog vienen protegidos con la contraseña «infected» para que ningún antivirus los elimine y para que no se abran por accidente."));
c.push(bullet("El malware no se publica: las carpetas de muestras están excluidas del repositorio (.gitignore). Lo que se versiona son los manifiestos (ruta, fuente, etiqueta y sha256) y los scripts que permiten reconstruir el conjunto."));
c.push(p("No se genera ni se sintetiza código malicioso: todas las muestras provienen de datasets reales de investigación."));

c.push(h1("G.4 Ingesta por fuente"));
c.push(p("Cada fuente se descarga en una carpeta de trabajo y se importa al esquema del proyecto (data/malicious/<fuente>/ o data/benign/<fuente>/)."));
c.push(p([t("DataDog. ", { bold: true }), t("Descifra cada ZIP de la parte PyPI y lo deja como carpeta de código, deduplicando por el sha256 del ZIP:")]));
c.push(...code(["python scripts/import_datadog.py --src datasets_raw/datadog --only-intent"]));
c.push(p([t("PyPI Malregistry. ", { bold: true }), t("Se copian los .tar.gz originales preservando su estructura en data/malicious/malregistry/.")]));
c.push(p([t("Top de PyPI. ", { bold: true }), t("Se genera la lista de los paquetes más descargados y se descargan sus distribuciones de código:")]));
c.push(...code(["python scripts/fetch_top_pypi.py --limit 5000", "python scripts/collect_benign.py --limit 2000"]));
c.push(p([t("Muestra aleatoria de PyPI. ", { bold: true }), t("Se muestrea el índice completo de PyPI con semilla fija y se descargan los paquetes:")]));
c.push(...code(["python scripts/fetch_random_pypi.py --limit 1000 --seed 42",
  "python scripts/collect_benign.py --names-file data/random_pypi_names.txt \\",
  "    --out data/benign/pypi_random --limit 1000"]));
c.push(p("De los 1.000 nombres muestreados, 479 paquetes quedaron incorporados al manifiesto final."));

c.push(h1("G.5 Limpieza y normalización"));
c.push(p("Las fuentes se normalizan a dos formatos que el pipeline entiende: archivo comprimido (.tar.gz, .whl, .zip, .egg) o carpeta de código extraído. Sobre esa base se aplican los siguientes pasos:"));
c.push(bullet([t("Deduplicación por sha256: ", { bold: true }), t("una muestra presente en varias fuentes cuenta una sola vez, lo que impide que un mismo paquete quede a la vez en entrenamiento y en prueba.")]));
c.push(bullet([t("Exclusión de muestras ilegibles: ", { bold: true }), t("los archivos que no se pueden descomprimir se registran como error tolerable y se excluyen sin interrumpir el proceso.")]));
c.push(bullet([t("Extracción segura: ", { bold: true }), t("la descompresión rechaza rutas fuera del directorio (Zip Slip) y archivos de dispositivo, y limita el tamaño descomprimido (anti zip-bomb). Los enlaces simbólicos y duros se omiten sin escribirse en disco.")]));
c.push(p(`De las ${miles(trM + hoM)} muestras del manifiesto, ${miles(trM + hoM - TR_N - HO_N)} (${n((trM + hoM - TR_N - HO_N) / (trM + hoM) * 100, 1)} %) se descartaron durante la extracción de características. Al momento del entrenamiento, el extractor rechazaba el paquete completo si contenía un enlace; esa regla se corrigió después (hoy los enlaces se omiten), por lo que parte de las descartadas corresponde a paquetes con enlaces y no a archivos corruptos.`));

c.push(h1("G.6 Etiquetado y trazabilidad"));
c.push(p("La etiqueta (benigno o malicioso) se deriva de la carpeta de origen: lo que está bajo data/malicious/ es malicioso y lo que está bajo data/benign/ es benigno. Por tanto, la calidad de las etiquetas depende de la verificación hecha por cada fuente. El resultado de la unificación es un manifiesto CSV con una fila por muestra: ruta, tipo (archivo o carpeta), etiqueta, fuente y sha256, que permite auditar qué muestras entraron y en qué partición."));

c.push(h1("G.7 Composición final y balance de clases"));
c.push(p("El conjunto se construyó con build_dataset.py, con un tope de 2.000 muestras maliciosas y semilla 42. La Tabla G.2 presenta la composición por fuente y partición."));
c.push(caption("Tabla G.2. Composición del dataset por fuente y partición."));
c.push(table([0.36, 0.14, 0.17, 0.15, 0.18], ["Fuente", "Clase", "Entrenamiento", "Hold-out", "Total"], [
  ...COMP.map((r) => [r[0], r[1], miles(r[2]), miles(r[3]), miles(r[2] + r[3])]),
  ["Total del manifiesto", "", miles(trM), miles(hoM), miles(trM + hoM)],
  ["Muestras procesadas", "", miles(TR_N), miles(HO_N), miles(TR_N + HO_N)],
], { boldRows: [4, 5], highlightRows: [5] }));
c.push(source());
c.push(p(`El conjunto efectivo de entrenamiento quedó en ${miles(m.n_malicious)} paquetes maliciosos y ${miles(m.n_benign)} benignos (proporción cercana a 1:1,25). El balance casi uniforme favorece el aprendizaje, pero no representa la prevalencia real del malware en PyPI; el efecto de esa diferencia se analiza en el Anexo H.`));

c.push(h1("G.8 División de datos y prevención de fuga"));
c.push(p("El conjunto se divide de forma estratificada por clase en 80 % de entrenamiento y 20 % de hold-out (evaluación final), con semilla fija 42. La estratificación mantiene la proporción de clases en ambas particiones y la deduplicación previa garantiza que ninguna muestra del hold-out haya sido vista en el entrenamiento. La salida son dos archivos: train.csv y holdout.csv."));
c.push(p("Todos los experimentos de evaluación usan el hold-out, nunca los datos de entrenamiento: la evaluación final del modelo (866 muestras), la comparación con GuardDog y ClamAV (subconjunto de 300 muestras, 150 por clase) y la comparación con VirusTotal (subconjunto de 80 muestras, 40 por clase)."));

c.push(h1("G.9 Transformación a características"));
c.push(p("De cada muestra se obtiene un vector de nueve características. El paquete se descomprime y se ejecutan los tres extractores estáticos: nombre (typosquatting por distancia de Levenshtein), entropía de Shannon por ventanas de 256 bytes y recorrido del árbol de sintaxis abstracta (AST). Los vectores se guardan en un CSV de características, indexado por sha256, para no recalcularlos en cada entrenamiento (Tabla G.3)."));
c.push(caption("Tabla G.3. Características del vector de entrada al modelo."));
c.push(table([0.2, 0.8], ["Grupo", "Características (9 en total)"], [
  ["Nombre", "name_min_distance, is_typosquat, has_combo_affix"],
  ["Entropía", "entropy_max, entropy_mean, entropy_suspicious_windows"],
  ["AST", "ast_dangerous_calls, ast_network_literals, ast_has_install_hook"],
]));
c.push(source());
c.push(p("Se retiraron cinco características de metadatos de publicación (número de versiones, dependencias, descripción, autor y mantenedores) porque, al extraerse desde el artefacto descargado sin consultar la API de PyPI, quedaban constantes durante el entrenamiento y con importancia nula."));

c.push(h1("G.10 Preprocesamiento para el modelo"));
c.push(p("Se separan X (los nueve valores) y la etiqueta y (0 benigno, 1 malicioso). El desbalance residual se maneja dentro de cada partición de la validación cruzada con SMOTE y con pesos de clase; SMOTE se aplica solo a los datos de entrenamiento de cada pliegue, nunca a los de prueba, para no contaminar la evaluación. Los modelos de árboles no requieren escalar las variables. El umbral de decisión se ajusta hacia el Recall para reducir los falsos negativos; el modelo seleccionado (Random Forest) opera con umbral 0,45."));

c.push(h1("G.11 Reproducibilidad"));
c.push(p("Las descargas, el muestreo aleatorio, la deduplicación, la división y el entrenamiento usan semillas fijas y están encapsulados en scripts versionados:"));
c.push(...code([
  "python scripts/build_dataset.py --max-malicious 2000 --split 0.2 --seed 42",
  "python scripts/train_model.py --k 5 --target-recall 0.90 --holdout",
]));
c.push(p("Los resultados (data/models/metrics.json y data/analysis/*.json) y las gráficas de los anexos (scripts/build_anexo_charts.py) se regeneran a partir de esos archivos."));

c.push(h1("G.12 Limitaciones de los datos"));
c.push(bullet("El conjunto está casi balanceado, mientras que en PyPI el malware es una minoría pequeña; la precisión esperada en producción es menor (Anexo H)."));
c.push(bullet("La muestra aleatoria de benignos es pequeña (479 paquetes) y es donde se concentran los falsos positivos; ampliarla es la mejora de datos más directa."));
c.push(bullet("No se realizó una partición temporal (entrenar con paquetes anteriores a una fecha y evaluar con posteriores), por lo que no se mide la degradación frente a campañas nuevas."));
c.push(bullet("Las etiquetas se heredan de las fuentes; un error de etiquetado en origen se propaga al modelo."));

c.push(h1("G.13 Referencias"));
[
  "DataDog. malicious-software-packages-dataset. Disponible en: https://github.com/DataDog/malicious-software-packages-dataset",
  "Guo, W. et al. An Empirical Study of Malicious Code in PyPI Ecosystem (PyPI Malregistry). ASE 2023. Disponible en: https://github.com/lxyeternal/pypi_malregistry",
  "Duan, R. et al. Towards Measuring Supply Chain Attacks on Package Managers (MalOSS). Disponible en: https://github.com/osssanitizer/maloss",
  "Ohm, M. et al. Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks. 2020.",
  "van Kemenade, H. top-pypi-packages. Disponible en: https://hugovk.github.io/top-pypi-packages/",
  "Python Software Foundation. PyPI Simple Index. Disponible en: https://pypi.org/simple/",
].forEach((r) => c.push(p(r)));

save(c, "Anexo_G_Manejo_y_preparacion_de_datos.docx");
