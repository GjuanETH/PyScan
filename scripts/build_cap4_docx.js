// Capítulo 4 — Implementación del MVP (OE3). NTC 1486.
const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType, PageNumber, Footer,
} = require("docx");

const FONT = "Arial";
const MONO = "Consolas";
const CM = 567;
const CONTENT_W = Math.round(21 * CM) - (4 * CM) - (2 * CM);

const t = (text, opts = {}) => new TextRun({ text, font: FONT, size: 24, ...opts });
const p = (runs, opts = {}) => new Paragraph({
  spacing: { line: 360, after: 120 }, alignment: AlignmentType.JUSTIFIED,
  children: Array.isArray(runs) ? runs : [runs], ...opts });
const h1 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 160 },
  children: [new TextRun({ text, font: FONT, size: 28, bold: true })] });
const h2 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 200, after: 120 },
  children: [new TextRun({ text, font: FONT, size: 24, bold: true })] });
const caption = (text) => new Paragraph({ spacing: { before: 20, after: 180 }, alignment: AlignmentType.CENTER,
  children: [new TextRun({ text, font: FONT, size: 20, italics: true })] });

// Bloque de código (monoespaciado, sombreado)
function code(lines, titulo) {
  const kids = lines.map((ln) => new Paragraph({
    spacing: { line: 240, after: 0 }, shading: { type: ShadingType.CLEAR, fill: "F2F2F2", color: "auto" },
    children: [new TextRun({ text: ln || " ", font: MONO, size: 17 })] }));
  return kids;
}

function cell(text, { w, bold = false, align = AlignmentType.LEFT } = {}) {
  return new TableCell({ width: { size: w, type: WidthType.DXA },
    margins: { top: 55, bottom: 55, left: 85, right: 85 },
    children: [new Paragraph({ alignment: align, spacing: { line: 256, after: 0 },
      children: [new TextRun({ text, font: FONT, size: 18, bold })] })] });
}
function headerRow(cells, widths) {
  return new TableRow({ tableHeader: true, children: cells.map((c, i) => new TableCell({
    width: { size: widths[i], type: WidthType.DXA },
    shading: { type: ShadingType.CLEAR, fill: "1F3864", color: "auto" },
    margins: { top: 55, bottom: 55, left: 85, right: 85 },
    children: [new Paragraph({ alignment: AlignmentType.CENTER, spacing: { line: 256, after: 0 },
      children: [new TextRun({ text: c, font: FONT, size: 18, bold: true, color: "FFFFFF" })] })] })) });
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

children.push(h1("4. IMPLEMENTACIÓN DEL MVP DE DETECCIÓN DE PAQUETES MALICIOSOS"));
children.push(p([t("Este capítulo desarrolla el tercer objetivo específico: "),
  t("implementar el MVP orientado a la detección de paquetes maliciosos en PyPI mediante algoritmos de análisis de metadatos, evaluación de entropía y recorrido de árboles de sintaxis abstracta, con el propósito de automatizar la identificación de amenazas.", { italics: true }),
  t(" Se describen los sprints ejecutados, los módulos construidos con fragmentos de código representativos, la construcción del dataset y el aseguramiento de calidad, y se miden los KPI definidos para el objetivo.")]));

// 4.1 Enfoque
children.push(h2("4.1 Enfoque de implementación"));
children.push(p(t("La implementación siguió un enfoque DevSecOps con elementos de Scrum, gestionado en Azure DevOps. El sistema se construyó de forma incremental en seis sprints, cada uno con un entregable funcional y sus pruebas automatizadas, respetando la arquitectura de monolito modular con patrón Pipes and Filters definida en el capítulo anterior. El lenguaje es Python 3.10+ y las interfaces entre módulos se definen con modelos tipados de Pydantic.")));

// 4.2 Sprints
children.push(h2("4.2 Sprints ejecutados"));
children.push(p(t("La Tabla 2 resume los seis sprints y su entregable principal.")));
{
  const w = [Math.round(CONTENT_W*0.12), Math.round(CONTENT_W*0.40), Math.round(CONTENT_W*0.48)];
  const rows = [
    ["Sprint 1", "Fetcher seguro", "Consulta a la API de PyPI, descarga del sdist, verificación de integridad (sha256) y extracción defensiva (anti Zip-Slip, symlink y zip-bomb)."],
    ["Sprint 2", "Extractor de metadatos", "Detección de typosquatting/combosquatting por distancia de Levenshtein contra el Top de PyPI."],
    ["Sprint 3", "Extractor de entropía", "Entropía de Shannon por ventana deslizante de 256 bytes para detectar ofuscación/empaquetado."],
    ["Sprint 4", "Extractor AST", "Recorrido del árbol de sintaxis abstracta: llamadas peligrosas, imports, literales de red y hooks de instalación; resistente a evasión por alias."],
    ["Sprint 5", "Entrenamiento del modelo", "Construcción del dataset y entrenamiento del clasificador supervisado (Random Forest / XGBoost) con manejo de desbalance."],
    ["Sprint 6", "Ensamble del CLI", "Integración del pipeline completo en la CLI (Typer), veredicto ML y salida JSON/SARIF con códigos de salida para CI."],
  ];
  children.push(makeTable(w, ["Sprint", "Entregable", "Descripción"], rows,
    [{ bold: true, align: AlignmentType.CENTER }, { bold: true }, {}]));
  children.push(caption("Tabla 2. Sprints ejecutados en Azure DevOps."));
}

// 4.3 Módulos
children.push(h2("4.3 Módulos implementados"));
children.push(p(t("El código fuente se organiza en el paquete src/pyscan/. A continuación se describen los módulos y se muestran tres fragmentos representativos de las técnicas centrales.")));

children.push(p([t("Fetcher seguro (fetcher.py). ", { bold: true }),
  t("Descarga el artefacto y lo extrae validando cada ruta antes de escribirla, rechazando rutas fuera del destino (Zip-Slip), enlaces y archivos de dispositivo. El Fragmento 1 muestra la validación en la extracción de archivos tar.")]));
children.push(...code([
  "for member in tar.getmembers():",
  "    if member.issym() or member.islnk():",
  "        raise FetchError(f\"Enlace no permitido: {member.name}\")",
  "    target = dest_dir / member.name",
  "    if not _is_within(dest_dir, target):",
  "        raise FetchError(f\"Ruta peligrosa (Zip Slip): {member.name}\")",
]));
children.push(caption("Fragmento 1. Extracción segura contra path traversal y enlaces (fetcher.py)."));

children.push(p([t("Extractor AST (ast_extractor.py). ", { bold: true }),
  t("Detecta llamadas peligrosas resistiendo la evasión por alias de import (por ejemplo, import subprocess as sp; sp.run(...)), resolviendo el nombre real antes de compararlo. El Fragmento 2 muestra la resolución de alias.")]));
children.push(...code([
  "def _resolve(self, name):",
  "    root, _, rest = name.partition('.')",
  "    real = self._aliases.get(root)",
  "    if real is None:",
  "        return name",
  "    return f'{real}.{rest}' if rest else real",
]));
children.push(caption("Fragmento 2. Resolución de alias de import en el recorrido AST."));

children.push(p([t("Ensamble del CLI (cli.py). ", { bold: true }),
  t("Orquesta el pipeline: descarga, aplica los tres extractores, consolida el vector de características y solicita el veredicto al clasificador. El Fragmento 3 muestra el motor de análisis reutilizable.")]));
children.push(...code([
  "report.typosquat = MetadataExtractor().extract(name, metadata)",
  "report.entropy   = EntropyExtractor().extract(extracted_path)",
  "report.ast       = ASTExtractor().extract(extracted_path)",
  "report.features  = build_features(typosquat=report.typosquat,",
  "                                  entropy=report.entropy, ast=report.ast)",
  "report.prediction = predict(report.features, model_path=model_path)",
]));
children.push(caption("Fragmento 3. Motor de análisis: de las señales al veredicto (cli.py)."));

children.push(p(t("La CLI expone el análisis para el caso de uso real: escaneo de un requirements.txt completo, de varios paquetes a la vez o de artefactos locales, con un resumen consolidado y códigos de salida aptos para integración continua (0 benigno, 1 error, 2 malicioso).")));

// 4.4 Dataset
children.push(h2("4.4 Construcción del dataset"));
children.push(p(t("El dataset combina muestras maliciosas de fuentes públicas de investigación con muestras benignas del Top de PyPI. Todas las muestras se identifican y deduplican por su hash sha256, registrado en los manifiestos (dataset.csv, train.csv, holdout.csv) como verificación de integridad y reproducibilidad. La Tabla 3 resume su composición.")));
{
  const w = [Math.round(CONTENT_W*0.40), Math.round(CONTENT_W*0.24), Math.round(CONTENT_W*0.36)];
  const rows = [
    ["Datadog (parte PyPI)", "334 maliciosas", "Dataset de Datadog Security Labs (importado y descifrado)."],
    ["PyPI Malregistry", "1.666 maliciosas", "Registro de malware PyPI (ASE 2023)."],
    ["Top de PyPI", "2.000 benignas", "Paquetes populares descargados de PyPI."],
    ["Total", "4.000 únicas", "Deduplicadas por sha256; división 3.200 train / 800 hold-out (80/20, estratificada, semilla 42)."],
  ];
  children.push(makeTable(w, ["Fuente", "Muestras", "Descripción"], rows,
    [{ bold: true }, { align: AlignmentType.CENTER }, {}]));
  children.push(caption("Tabla 3. Composición del dataset de entrenamiento y evaluación."));
}
children.push(p([t("Nota de consistencia: ", { bold: true, italics: true }),
  t("verificar con el director la alineación de esta descripción con la sección de metodología, dado que el conjunto efectivamente empleado fue Datadog + PyPI Malregistry.", { italics: true })]));

// 4.5 Calidad
children.push(h2("4.5 Aseguramiento de calidad"));
children.push(p(t("Cada módulo cuenta con pruebas automatizadas con pytest. La suite consta de 58 pruebas (unitarias y de integración) que se ejecutan en cada cambio antes de publicar en Azure DevOps, actuando como control de calidad. La Tabla 4 muestra la cobertura por módulo; el total es del 91 %, superando el umbral del 80 % exigido.")));
{
  const w = [Math.round(CONTENT_W*0.5), Math.round(CONTENT_W*0.25), Math.round(CONTENT_W*0.25)];
  const rows = [
    ["models.py", "68", "100 %"],
    ["config.py", "23", "100 %"],
    ["features.py", "18", "100 %"],
    ["sarif.py", "30", "100 %"],
    ["classifier.py", "39", "95 %"],
    ["entropy.py", "58", "91 %"],
    ["ast_extractor.py", "111", "89 %"],
    ["metadata.py", "74", "89 %"],
    ["cli.py", "193", "88 %"],
    ["fetcher.py", "161", "87 %"],
    ["TOTAL", "780", "91 %"],
  ];
  children.push(makeTable(w, ["Módulo", "Sentencias", "Cobertura"], rows,
    [{}, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER, bold: true }]));
  children.push(caption("Tabla 4. Cobertura de código por módulo (pytest --cov)."));
}
children.push(p(t("La robustez se verificó en las corridas de análisis sobre miles de paquetes reales: las muestras corruptas o ilegibles se registran como aviso y se omiten sin abortar la ejecución, de modo que no se observaron excepciones no controladas. El pipeline formal de integración continua en Azure Pipelines queda planteado como paso de cierre.")));

// 4.6 KPI OE3
children.push(h2("4.6 Medición de los KPI del objetivo (OE3)"));
{
  const w = [Math.round(CONTENT_W*0.28), Math.round(CONTENT_W*0.34), Math.round(CONTENT_W*0.14), Math.round(CONTENT_W*0.24)];
  const rows = [
    ["Completitud funcional", "Implementación de funciones (pruebas OK)", "≥ 95 %", "100 % (58/58 pruebas); 12/12 módulos"],
    ["Testeabilidad", "Cobertura de código", "≥ 80 %", "91 %"],
    ["Madurez", "Tasa de fallos no manejados", "≤ 1 %", "≈ 0 % (sin excepciones no controladas)"],
  ];
  children.push(makeTable(w, ["Subcaracterística", "KPI", "Meta", "Resultado"], rows,
    [{}, {}, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER, bold: true }]));
  children.push(caption("Tabla 5. Cumplimiento de los KPI del tercer objetivo específico."));
}

// 4.7 Conclusión
children.push(h2("4.7 Conclusión parcial"));
children.push(p(t("El MVP quedó implementado en seis sprints conforme a la arquitectura diseñada, integrando los tres extractores estáticos y el clasificador supervisado en una herramienta de línea de comandos apta para el caso de uso real (análisis de las dependencias de un proyecto). El aseguramiento de calidad —58 pruebas automatizadas, 91 % de cobertura y ausencia de fallos no manejados— evidencia el cumplimiento de los tres KPI del tercer objetivo específico. Con ello se dispone de un sistema funcional y estable, base para la validación de su eficacia y calidad abordada en el capítulo siguiente.")));

const doc = new Document({
  creator: "pyscan - Trabajo de Grado",
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
  fs.writeFileSync("/tmp/Capitulo4_Implementacion.docx", buf);
  console.log("DOCX escrito:", buf.length, "bytes");
});
