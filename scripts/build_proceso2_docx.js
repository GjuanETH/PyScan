// Bitácora de proceso — Objetivo 2 (diseño de la arquitectura). NTC 1486.
const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType, PageNumber, Footer, ImageRun, LevelFormat,
} = require("docx");

const FONT = "Arial";
const CM = 567;
const CONTENT_W = Math.round(21 * CM) - (4 * CM) - (2 * CM);
const DIR = "/tmp/proc2";

const t = (text, opts = {}) => new TextRun({ text, font: FONT, size: 24, ...opts });
const p = (runs, opts = {}) => new Paragraph({
  spacing: { line: 360, after: 120 }, alignment: AlignmentType.JUSTIFIED,
  children: Array.isArray(runs) ? runs : [runs], ...opts });
const h1 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 160 },
  children: [new TextRun({ text, font: FONT, size: 28, bold: true })] });
const h2 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 200, after: 120 },
  children: [new TextRun({ text, font: FONT, size: 24, bold: true })] });
const step = (text) => new Paragraph({ numbering: { reference: "pasos2", level: 0 },
  spacing: { line: 340, after: 80 }, alignment: AlignmentType.JUSTIFIED,
  children: [new TextRun({ text, font: FONT, size: 24 })] });
function figure(file, wpx, hpx, targetW) {
  const scale = targetW / wpx;
  return new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 120, after: 60 },
    children: [new ImageRun({ type: "png", data: fs.readFileSync(`${DIR}/${file}`),
      transformation: { width: Math.round(wpx*scale), height: Math.round(hpx*scale) } })] });
}
const caption = (text) => new Paragraph({ spacing: { before: 20, after: 180 }, alignment: AlignmentType.CENTER,
  children: [new TextRun({ text, font: FONT, size: 20, italics: true })] });
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

// Portada
children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 80 },
  children: [new TextRun({ text: "DOCUMENTACIÓN DEL PROCESO", font: FONT, size: 28, bold: true })] }));
children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 },
  children: [new TextRun({ text: "Objetivo Específico 2 — Diseño de la arquitectura del MVP y del modelo de ML",
    font: FONT, size: 24, bold: true })] }));
children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 240 },
  children: [new TextRun({ text: "Registro metodológico: fases, decisiones de diseño y tensiones resueltas",
    font: FONT, size: 22, italics: true })] }));

// 1. Propósito
children.push(h1("1. Propósito de este documento"));
children.push(p(t("Este documento registra el procedimiento seguido para diseñar la arquitectura del sistema, más allá del resultado presentado en el documento de arquitectura. Describe cómo se derivó el diseño a partir de los requerimientos, qué alternativas se evaluaron en cada decisión y qué tensiones surgieron —principalmente entre ideas iniciales del backlog y el alcance definitivo de la tesis— y cómo se resolvieron. El propósito es dar trazabilidad y justificar que cada elección arquitectónica responde a un criterio, no al azar.")));

// 2. Visión general
children.push(h1("2. Visión general del proceso"));
children.push(p(t("El diseño se abordó en cinco fases secuenciales, partiendo de los requerimientos del Objetivo 1 y culminando en una arquitectura verificada contra ellos. La Figura 1 resume el flujo.")));
children.push(figure("proceso2.png", 437, 892, 235));
children.push(caption("Figura 1. Fases del proceso de diseño arquitectónico."));

// 3. Fase 1
children.push(h1("3. Fase 1 — Análisis de los requerimientos"));
children.push(p(t("El punto de partida fueron los productos del Objetivo 1: la taxonomía de siete vectores de ataque y el conjunto de once requerimientos funcionales y doce no funcionales, estos últimos organizados según las características de ISO/IEC 25010:2023. El diseño se planteó como la traducción de ese conjunto en una estructura de software.")));
children.push(h2("Procedimiento"));
children.push(step("Se agruparon los requerimientos por naturaleza: capacidades de detección (RF02–RF08), decisión y entrega (RF09–RF11), y calidad (RNF)."));
children.push(step("Se identificó que cada familia de vectores exigía una técnica de análisis distinta (similitud de nombre, entropía, AST), lo que anticipaba una separación en componentes especializados."));
children.push(step("Se fijaron los atributos de calidad rectores: mantenibilidad (para poder crecer el sistema) y fiabilidad (por manejar paquetes potencialmente maliciosos)."));

// 4. Fase 2
children.push(h1("4. Fase 2 — Selección del estilo arquitectónico"));
children.push(p(t("La decisión central fue el estilo. Se evaluaron tres opciones y se eligió un monolito modular estructurado con el patrón Pipes and Filters.")));
children.push(h2("Alternativas evaluadas y decisión"));
children.push(p([
  t("Microservicios", { bold: true }),
  t(" se descartó por complejidad operativa desproporcionada para un MVP de línea de comandos. Un "),
  t("monolito no estructurado", { bold: true }),
  t(" se descartó por comprometer la mantenibilidad (RNF10–RNF12). Se eligió el "),
  t("monolito modular con Pipes and Filters", { bold: true }),
  t(" porque modela naturalmente un flujo de análisis por etapas y permite tratar cada extractor como un filtro independiente e intercambiable, satisfaciendo la modularidad y la capacidad de prueba exigidas."),
]));

// 5. Fase 3
children.push(h1("5. Fase 3 — Definición de componentes y contratos"));
children.push(p(t("Con el estilo fijado, se descompuso el sistema en componentes y se definieron los contratos entre ellos.")));
children.push(h2("Procedimiento"));
children.push(step("Se asignó un componente por responsabilidad: Fetcher seguro, tres extractores, Feature Builder, clasificador y serializador de reportes, con config y models como módulos transversales."));
children.push(step("Se decidió definir las interfaces entre filtros con modelos tipados de Pydantic, en lugar de diccionarios sueltos, para validar los datos en tránsito y permitir probar cada módulo en aislamiento."));
children.push(step("Se verificó que cada componente quedara asociado a requerimientos concretos (por ejemplo, el Fetcher a RF01 y a los RNF de fiabilidad y capacidad)."));

// 6. Fase 4
children.push(h1("6. Fase 4 — Diseño del modelo de Machine Learning"));
children.push(p(t("El componente de decisión se diseñó considerando dos hechos del dominio: el fuerte desbalance de clases y la prioridad de no dejar pasar malware (Recall).")));
children.push(h2("Decisiones de diseño"));
children.push(step("Representación: un vector de características numéricas consolidado por el Feature Builder, para lograr inferencia rápida y de bajo consumo (RNF de eficiencia)."));
children.push(step("Algoritmos: ensambles basados en árboles (Random Forest y XGBoost), robustos ante características heterogéneas y de rápida inferencia, evaluando ambos y seleccionando el mejor."));
children.push(step("Desbalance: incorporación del costo de clase (class_weight / scale_pos_weight) y SMOTE aplicado solo dentro de cada partición de entrenamiento, para evitar la fuga de información."));
children.push(step("Evaluación: validación cruzada estratificada con predicciones out-of-fold, ajuste del umbral hacia el Recall y verificación final en un hold-out."));

// 7. Fase 5
children.push(h1("7. Fase 5 — Verificación del diseño contra los requerimientos"));
children.push(p(t("Finalmente se comprobó, mediante una matriz de trazabilidad, que cada decisión de diseño respondiera a requerimientos concretos y que ningún requerimiento quedara sin un componente responsable. Esta verificación cierra el ciclo requerimiento → diseño y es la base para la implementación de los objetivos siguientes.")));

// 8. Decisiones de diseño (ADR)
children.push(h1("8. Registro de decisiones de diseño"));
children.push(p(t("La Tabla 1 consolida las decisiones arquitectónicas principales, la alternativa descartada y el criterio de decisión.")));
{
  const w = [Math.round(CONTENT_W*0.26), Math.round(CONTENT_W*0.26), Math.round(CONTENT_W*0.28), Math.round(CONTENT_W*0.20)];
  const rows = [
    ["Estilo arquitectónico", "Monolito modular + Pipes and Filters", "Microservicios; monolito no estructurado", "Mantenibilidad para un MVP"],
    ["Contratos entre módulos", "Modelos tipados (Pydantic)", "Diccionarios sin tipar", "Validación y pruebas en aislamiento"],
    ["Decisión final", "Clasificador de ML", "Agregador de puntajes ponderado (reglas)", "Alcance de la tesis (decisión por ML)"],
    ["Algoritmo de ML", "Random Forest / XGBoost", "Redes neuronales; SVM", "Robustez, rapidez, interpretabilidad"],
    ["Tratamiento del desbalance", "class_weight + SMOTE en fold", "Submuestreo agresivo; ignorarlo", "Preservar Recall sin fuga de datos"],
    ["Fetcher", "Síncrono y seguro", "Asíncrono desde el inicio", "Simplicidad del MVP (async = futuro)"],
    ["Salida", "JSON + SARIF 2.1.0", "Solo JSON", "Integración en CI/CD"],
  ];
  children.push(makeTable(w, ["Decisión", "Elección", "Alternativa descartada", "Criterio"], rows,
    [{ bold: true }, {}, {}, {}]));
  children.push(caption("Tabla 1. Registro de decisiones de diseño (ADR)."));
}

// 9. Tensiones resueltas
children.push(h1("9. Tensiones e inconsistencias resueltas"));
children.push(p(t("Durante el diseño se detectaron tensiones entre ideas registradas en el backlog inicial y el alcance definitivo de la tesis. Documentarlas y resolverlas fue parte del proceso.")));
children.push(p([t("Alcance npm/JS. ", { bold: true }),
  t("El backlog contemplaba analizar también paquetes de npm; esto contradecía el alcance PyPI-only de la tesis. Resolución: se acotó el diseño a PyPI y npm quedó como trabajo futuro.")]));
children.push(p([t("Mecanismo de decisión. ", { bold: true }),
  t("El backlog proponía un agregador de puntajes ponderado (una regla fija) que chocaba con la decisión por aprendizaje automático de la tesis. Resolución: el veredicto final lo emite el clasificador de ML; las señales alimentan el vector de características, no una fórmula fija.")]));
children.push(p([t("Plataforma de gestión. ", { bold: true }),
  t("Referencias mezcladas a GitHub y a Azure DevOps. Resolución: se unificó en Azure DevOps, donde reside el repositorio y se ejecuta la integración continua.")]));

// 10. Conclusión
children.push(h1("10. Conclusión"));
children.push(p(t("El proceso descrito muestra que la arquitectura no se adoptó por defecto, sino que resultó de un análisis de alternativas guiado por los requerimientos y los atributos de calidad. Cada decisión quedó justificada y trazada, y las tensiones entre el backlog inicial y el alcance de la tesis se resolvieron de forma explícita y coherente con la decisión por Machine Learning. Esta documentación complementa el documento de arquitectura del Objetivo 2 y respalda la solidez del diseño ante su revisión.")));

const doc = new Document({
  creator: "pyscan - Trabajo de Grado",
  numbering: { config: [{ reference: "pasos2", levels: [{
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
  fs.writeFileSync("/tmp/Proceso_Objetivo2.docx", buf);
  console.log("DOCX escrito:", buf.length, "bytes");
});
