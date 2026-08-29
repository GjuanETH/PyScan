// Documentación del proceso — Objetivo 1 (bitácora metodológica). NTC 1486.
const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType, PageNumber, Footer,
  ImageRun, LevelFormat,
} = require("docx");

const FONT = "Arial";
const CM = 567;
const CONTENT_W = Math.round(21 * CM) - (4 * CM) - (2 * CM);
const DIR = "/tmp/proc/diagrams";

const t = (text, opts = {}) => new TextRun({ text, font: FONT, size: 24, ...opts });
const p = (runs, opts = {}) => new Paragraph({
  spacing: { line: 360, after: 120 }, alignment: AlignmentType.JUSTIFIED,
  children: Array.isArray(runs) ? runs : [runs], ...opts,
});
const h1 = (text) => new Paragraph({
  heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 160 },
  children: [new TextRun({ text, font: FONT, size: 28, bold: true })],
});
const h2 = (text) => new Paragraph({
  heading: HeadingLevel.HEADING_2, spacing: { before: 200, after: 120 },
  children: [new TextRun({ text, font: FONT, size: 24, bold: true })],
});
// Lista numerada de pasos
const step = (text) => new Paragraph({
  numbering: { reference: "pasos", level: 0 },
  spacing: { line: 340, after: 80 }, alignment: AlignmentType.JUSTIFIED,
  children: [new TextRun({ text, font: FONT, size: 24 })],
});
function figure(file, wpx, hpx, targetW) {
  const scale = targetW / wpx;
  return new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 120, after: 60 },
    children: [new ImageRun({ type: "png", data: fs.readFileSync(`${DIR}/${file}`),
      transformation: { width: Math.round(wpx * scale), height: Math.round(hpx * scale) } })] });
}
const caption = (text) => new Paragraph({ spacing: { before: 20, after: 180 }, alignment: AlignmentType.CENTER,
  children: [new TextRun({ text, font: FONT, size: 20, italics: true })] });

function cell(text, { w, bold = false, align = AlignmentType.LEFT } = {}) {
  return new TableCell({ width: { size: w, type: WidthType.DXA },
    margins: { top: 60, bottom: 60, left: 90, right: 90 },
    children: [new Paragraph({ alignment: align, spacing: { line: 264, after: 0 },
      children: [new TextRun({ text, font: FONT, size: 19, bold })] })] });
}
function headerRow(cells, widths) {
  return new TableRow({ tableHeader: true, children: cells.map((c, i) => new TableCell({
    width: { size: widths[i], type: WidthType.DXA },
    shading: { type: ShadingType.CLEAR, fill: "1F3864", color: "auto" },
    margins: { top: 60, bottom: 60, left: 90, right: 90 },
    children: [new Paragraph({ alignment: AlignmentType.CENTER, spacing: { line: 264, after: 0 },
      children: [new TextRun({ text: c, font: FONT, size: 19, bold: true, color: "FFFFFF" })] })] })) });
}
function makeTable(widths, header, rows, rowOpts = []) {
  return new Table({ columnWidths: widths,
    width: { size: widths.reduce((a, b) => a + b, 0), type: WidthType.DXA },
    borders: {
      top: { style: BorderStyle.SINGLE, size: 4, color: "999999" },
      bottom: { style: BorderStyle.SINGLE, size: 4, color: "999999" },
      left: { style: BorderStyle.SINGLE, size: 4, color: "999999" },
      right: { style: BorderStyle.SINGLE, size: 4, color: "999999" },
      insideHorizontal: { style: BorderStyle.SINGLE, size: 2, color: "CCCCCC" },
      insideVertical: { style: BorderStyle.SINGLE, size: 2, color: "CCCCCC" },
    },
    rows: [headerRow(header, widths),
      ...rows.map((r) => new TableRow({ children: r.map((c, i) => cell(c, { w: widths[i], ...(rowOpts[i] || {}) })) }))] });
}

const children = [];

// Portada
children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 80 },
  children: [new TextRun({ text: "DOCUMENTACIÓN DEL PROCESO", font: FONT, size: 28, bold: true })] }));
children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 },
  children: [new TextRun({ text: "Objetivo Específico 1 — Identificación de vectores de ataque y definición de requerimientos",
    font: FONT, size: 24, bold: true })] }));
children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 240 },
  children: [new TextRun({ text: "Registro metodológico: procedimiento, requisitos, problemas y soluciones",
    font: FONT, size: 22, italics: true })] }));

// 1. Propósito
children.push(h1("1. Propósito de este documento"));
children.push(p(t("Este documento registra el procedimiento seguido para obtener los resultados del primer objetivo específico, más allá del resultado final. Describe el paso a paso de cada fase, los recursos y condiciones que se requirieron, y —de forma explícita— los problemas técnicos que surgieron y cómo se resolvieron. El propósito es dar trazabilidad y reproducibilidad al trabajo: cualquier lector debería poder repetir el proceso y llegar a resultados equivalentes, y comprender las decisiones tomadas ante cada obstáculo.")));

// 2. Visión general
children.push(h1("2. Visión general del proceso"));
children.push(p(t("El proceso se organizó en cinco fases secuenciales, desde el diseño del método de análisis hasta la obtención de las frecuencias de los vectores de ataque. La Figura 1 resume el flujo. Las secciones siguientes detallan cada fase con su procedimiento, sus requisitos y los problemas encontrados.")));
children.push(figure("proceso.png", 402, 942, 235));
children.push(caption("Figura 1. Fases del proceso para obtener los resultados del Objetivo 1."));

// 3. Fase 1
children.push(h1("3. Fase 1 — Diseño del método de análisis"));
children.push(p(t("Antes de tocar dato alguno, se definió cómo se medirían los vectores de ataque. Se decidió apoyarse en los tres extractores de análisis estático del MVP (metadatos, entropía y AST), que nunca ejecutan el código, y construir un script dedicado, analyze_attack_vectors.py, que recorre el corpus malicioso, aplica los extractores a cada paquete y clasifica los vectores presentes.")));
children.push(h2("Procedimiento"));
children.push(step("Se definió la taxonomía de siete vectores (V1 typosquatting, V2 ejecución en instalación, V3 ofuscación, V4 ejecución de comandos, V5 deserialización insegura, V6 codificación, V7 red/exfiltración)."));
children.push(step("Se estableció la correspondencia entre cada vector y la señal observable que lo evidencia (por ejemplo, V2 = hook de instalación en setup.py detectado por el extractor AST)."));
children.push(step("Se implementó el script para emitir frecuencias por vector, co-ocurrencia por paquete y conteo de llamadas peligrosas, en formatos JSON y CSV."));
children.push(step("Se validó el script con datos sintéticos antes de usarlo con malware real, confirmando que producía la tabla de frecuencias esperada."));
children.push(h2("Requisitos"));
children.push(p(t("Python 3.10+, los extractores del MVP y sus dependencias (Pydantic, RapidFuzz). No se requirió red ni datos reales en esta fase.")));

// 4. Fase 2
children.push(h1("4. Fase 2 — Preparación de un entorno seguro"));
children.push(p([
  t("Los datasets contienen "), t("malware real", { bold: true }),
  t(". Aunque el análisis es estático (no ejecuta el código), se decidió trabajar en una máquina virtual aislada para eliminar cualquier riesgo de contagio del equipo anfitrión, siguiendo la buena práctica estándar en investigación de malware."),
]));
children.push(h2("Procedimiento"));
children.push(step("Se instaló VirtualBox y se creó una máquina virtual con Ubuntu (40 GB de disco, 4 GB de RAM, 2 CPU)."));
children.push(step("Se reforzó el aislamiento: sin carpetas compartidas y con el portapapeles compartido deshabilitado durante el manejo de malware."));
children.push(step("Se instalaron las dependencias del entorno (git, python3-venv, pip) y se clonó el repositorio del proyecto desde Azure DevOps."));
children.push(step("Se creó un entorno virtual de Python y se instaló el MVP con sus dependencias de desarrollo y de Machine Learning."));
children.push(h2("Problemas encontrados y soluciones"));
children.push(p([t("Portapapeles bloqueado. ", { bold: true }),
  t("El aislamiento impedía pegar comandos y el token de acceso. Solución: se instalaron las Guest Additions de VirtualBox y se habilitó el portapapeles de forma temporal solo para la configuración inicial (antes de introducir malware), volviéndolo a deshabilitar después.")]));
children.push(p([t("Clonado del repositorio. ", { bold: true }),
  t("El clonado fallaba con «repository not found» al usar la URL del navegador. Solución: se empleó la URL de Git de Azure DevOps con el segmento /_git/ y autenticación mediante un Personal Access Token (PAT), configurando credential.helper para no reintroducirlo.")]));
children.push(p([t("Paquete de entorno faltante. ", { bold: true }),
  t("La creación del entorno virtual falló por ausencia de python3-venv y pip. Solución: se instalaron ambos con el gestor de paquetes del sistema y se recreó el entorno.")]));

// 5. Fase 3
children.push(h1("5. Fase 3 — Adquisición de los datasets"));
children.push(p(t("Se reunieron muestras maliciosas de dos fuentes públicas de investigación (Datadog Security Labs y PyPI Malregistry) y muestras benignas del Top de PyPI. El criterio rector fue no generar malware sintético, sino agregar datasets reales y deduplicar.")));
children.push(h2("Procedimiento"));
children.push(step("Se clonaron los repositorios de malware dentro de la máquina virtual."));
children.push(step("Se recolectaron paquetes benignos descargándolos directamente de PyPI con un script del proyecto."));
children.push(step("Se importaron las muestras al layout del proyecto (carpetas data/malicious y data/benign)."));
children.push(h2("Problemas encontrados y soluciones"));
children.push(p([t("Espacio en disco insuficiente. ", { bold: true }),
  t("El repositorio de Datadog incluye npm además de PyPI y llenó el disco («no space left on device»). Solución: se realizó una descarga parcial con git (sparse-checkout limitado a la carpeta samples/pypi y clonado superficial con --depth 1), trayendo únicamente la parte de PyPI necesaria y reduciendo el peso de decenas de GB a poco más de 1 GB.")]));
children.push(p([t("Scripts ausentes en el repositorio remoto. ", { bold: true }),
  t("Al clonar, faltaban los scripts nuevos (importación, análisis, entrenamiento) porque aún no se habían subido a Azure DevOps. Solución: se publicaron los cambios desde el equipo de desarrollo y se actualizó la copia de la máquina virtual con git pull.")]));
children.push(p([t("Lista de nombres benignos demasiado corta. ", { bold: true }),
  t("El recolector solo encontró ~48 nombres (la semilla embebida), insuficientes para 2.000 descargas. Solución: se generó primero la lista completa del Top de PyPI (5.000 nombres) con el script correspondiente y luego se recolectaron los benignos.")]));
children.push(p([t("Artefactos muy grandes. ", { bold: true }),
  t("Algunos paquetes benignos (por ejemplo, tensorflow, torch) superaban el límite de 100 MB de descarga. Comportamiento esperado: el Fetcher los omite por diseño (protección de capacidad), sin afectar el dataset.")]));

// 6. Fase 4
children.push(h1("6. Fase 4 — Construcción del dataset"));
children.push(p(t("Con las muestras crudas reunidas, se construyó un dataset unificado, deduplicado y balanceado, apto para el análisis y para el posterior entrenamiento del modelo.")));
children.push(h2("Procedimiento"));
children.push(step("Se importó la parte PyPI de Datadog descifrando sus ZIP protegidos (contraseña de resguardo del propio dataset), obteniendo 2.502 muestras."));
children.push(step("Se copió PyPI Malregistry al layout del proyecto."));
children.push(step("Se ejecutó la construcción del dataset: deduplicación por sha256, submuestreo a 2.000 maliciosos y balanceo frente a los benignos."));
children.push(step("Se dividió en entrenamiento y hold-out (80/20) de forma estratificada por clase, con semilla fija para reproducibilidad."));
children.push(h2("Resultado de la fase"));
children.push(p(t("Se obtuvo un dataset de 4.000 muestras únicas: 2.000 maliciosas (334 de Datadog y 1.666 de Malregistry) y 2.000 benignas del Top de PyPI, dividido en 3.200 de entrenamiento y 800 de hold-out. El conteo por fuente quedó registrado como evidencia de diversidad.")));

// 7. Fase 5
children.push(h1("7. Fase 5 — Ejecución del análisis y obtención de resultados"));
children.push(p(t("Finalmente se ejecutó el script de análisis sobre el conjunto de muestras maliciosas del dataset, obteniendo las frecuencias de cada vector de ataque.")));
children.push(h2("Problema encontrado y solución"));
children.push(p([t("Muestras corruptas abortaban la corrida. ", { bold: true }),
  t("Algunos archivos con extensión .tar.gz no eran archivos tar válidos y provocaban un error (tarfile.ReadError) que detenía todo el análisis. Solución: se modificó el módulo de extracción para convertir ese error en una excepción controlada y se ampliaron los manejadores de los scripts, de modo que una muestra corrupta se registra como aviso y se omite, permitiendo que la corrida continúe con las demás. Se verificó que la corrección no rompiera las pruebas existentes.")]));
children.push(h2("Resultados obtenidos"));
children.push(p(t("Se analizaron con éxito 1.926 paquetes maliciosos (74 descartados por corrupción). La distribución de vectores se resume en la Tabla 1; el detalle completo se presenta en el documento del Objetivo 1.")));
{
  const w = [Math.round(CONTENT_W*0.55), Math.round(CONTENT_W*0.22), Math.round(CONTENT_W*0.23)];
  const rows = [
    ["V4 Ejecución de comandos/código", "1.470", "76,32 %"],
    ["V7 Red / exfiltración de datos", "808", "41,95 %"],
    ["V1 Typosquatting / combosquatting", "500", "25,96 %"],
    ["V2 Ejecución en instalación", "388", "20,15 %"],
    ["V6 Codificación/decodificación (base64)", "302", "15,68 %"],
    ["V5 Deserialización insegura", "31", "1,61 %"],
    ["V3 Ofuscación / empaquetado (entropía)", "2", "0,10 %"],
  ];
  children.push(makeTable(w, ["Vector de ataque", "Paquetes", "%"], rows,
    [{}, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER, bold: true }]));
  children.push(caption("Tabla 1. Frecuencia de vectores obtenida (n = 1.926). El 48,23 % presentó ≥2 vectores."));
}

// 8. Tabla consolidada de problemas
children.push(h1("8. Resumen consolidado de problemas y soluciones"));
{
  const w = [Math.round(CONTENT_W*0.16), Math.round(CONTENT_W*0.42), Math.round(CONTENT_W*0.42)];
  const rows = [
    ["Fase 2", "Portapapeles bloqueado por el aislamiento", "Guest Additions + habilitación temporal antes del malware"],
    ["Fase 2", "Clonado «repository not found»", "URL con /_git/ + autenticación por PAT"],
    ["Fase 2", "Falta python3-venv / pip", "Instalación con el gestor del sistema"],
    ["Fase 3", "Disco lleno (Datadog incluye npm)", "Descarga parcial: sparse-checkout de samples/pypi + --depth 1"],
    ["Fase 3", "Scripts faltantes en el remoto", "Publicar en Azure DevOps + git pull"],
    ["Fase 3", "Lista de benignos muy corta (~48)", "Generar el Top de PyPI (5.000) antes de recolectar"],
    ["Fase 3", "Artefactos > 100 MB", "Omisión por diseño (protección de capacidad)"],
    ["Fase 5", "Muestras corruptas abortaban la corrida", "Extracción tolerante a fallos: se avisa y se omite"],
  ];
  children.push(makeTable(w, ["Fase", "Problema", "Solución aplicada"], rows,
    [{ align: AlignmentType.CENTER, bold: true }, {}, {}]));
  children.push(caption("Tabla 2. Consolidado de problemas técnicos y sus soluciones."));
}

// 9. Reproducibilidad
children.push(h1("9. Reproducibilidad y consideraciones éticas"));
children.push(p(t("El proceso es reproducible: las fuentes de datos son públicas, la deduplicación y el balanceo usan una semilla fija, y todos los scripts están versionados en el repositorio. Se documentaron las fuentes, los conteos por origen y la fecha de descarga, dado que estos datasets evolucionan en el tiempo. En cuanto a la ética, se manejó malware real bajo aislamiento estricto, sin ejecutarlo en ningún momento, y se citan todas las fuentes utilizadas.")));
children.push(p([
  t("Se identificó además una amenaza a la validez que quedó documentada: "),
  t("el clasificador entrenado con este dataset se apoya en gran medida en las señales de nombre", { bold: true }),
  t(", porque los benignos provienen del mismo Top de PyPI usado como referencia. Se registró como línea de mejora (diversificar los benignos y evaluar sin las características de nombre)."),
]));

// 10. Conclusión
children.push(h1("10. Conclusión"));
children.push(p(t("El proceso descrito permitió obtener, de forma reproducible y trazable, la evidencia empírica del primer objetivo específico. Los obstáculos encontrados —principalmente de entorno, capacidad de disco y calidad de los datos— se resolvieron con decisiones documentadas que fortalecieron la robustez de las herramientas (por ejemplo, la extracción tolerante a fallos). La documentación de este procedimiento complementa el documento de resultados del Objetivo 1 y respalda la validez del trabajo ante su revisión.")));

const doc = new Document({
  creator: "pyscan - Trabajo de Grado",
  numbering: { config: [{ reference: "pasos", levels: [{
    level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.START,
    style: { paragraph: { indent: { left: 460, hanging: 260 } } } }] }] },
  styles: { default: { document: { run: { font: FONT, size: 24 } } } },
  sections: [{
    properties: { page: {
      size: { width: Math.round(21 * CM), height: Math.round(29.7 * CM) },
      margin: { top: 3 * CM, bottom: 3 * CM, left: 4 * CM, right: 2 * CM },
    } },
    footers: { default: new Footer({ children: [new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 20 })] })] }) },
    children,
  }],
});

Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync("/tmp/Proceso_Objetivo1.docx", buf);
  console.log("DOCX escrito:", buf.length, "bytes");
});
