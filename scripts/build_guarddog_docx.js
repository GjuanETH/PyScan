// Comparación empírica pyscan vs GuardDog. NTC 1486.
const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType, PageNumber, Footer, ImageRun,
} = require("docx");

const FONT = "Arial";
const CM = 567;
const CONTENT_W = Math.round(21 * CM) - (4 * CM) - (2 * CM);
const DIR = "/tmp/gd";

const t = (text, opts = {}) => new TextRun({ text, font: FONT, size: 24, ...opts });
const p = (runs, opts = {}) => new Paragraph({
  spacing: { line: 360, after: 120 }, alignment: AlignmentType.JUSTIFIED,
  children: Array.isArray(runs) ? runs : [runs], ...opts });
const h1 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 160 },
  children: [new TextRun({ text, font: FONT, size: 28, bold: true })] });
const h2 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 200, after: 120 },
  children: [new TextRun({ text, font: FONT, size: 24, bold: true })] });
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
    children: [new Paragraph({ alignment: align, spacing: { line: 258, after: 0 },
      children: [new TextRun({ text, font: FONT, size: 19, bold })] })] });
}
function headerRow(cells, widths) {
  return new TableRow({ tableHeader: true, children: cells.map((c, i) => new TableCell({
    width: { size: widths[i], type: WidthType.DXA },
    shading: { type: ShadingType.CLEAR, fill: "1F3864", color: "auto" },
    margins: { top: 55, bottom: 55, left: 85, right: 85 },
    children: [new Paragraph({ alignment: AlignmentType.CENTER, spacing: { line: 258, after: 0 },
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

children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 80 },
  children: [new TextRun({ text: "COMPARACIÓN CON EL ESTADO DEL ARTE", font: FONT, size: 28, bold: true })] }));
children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 240 },
  children: [new TextRun({ text: "Evaluación empírica de pyscan frente a GuardDog (Datadog)", font: FONT, size: 24, bold: true })] }));
children.push(p(t("Este documento compara empíricamente el detector propuesto (pyscan) con GuardDog, la herramienta de código abierto de Datadog para identificar paquetes maliciosos en PyPI, ejecutando ambos sobre el mismo conjunto de muestras. El objetivo es posicionar el trabajo frente al estado del arte, no declarar un ganador: se trata de comprender en qué coinciden y en qué difieren un enfoque basado en reglas y uno basado en aprendizaje automático.")));

// 1. Diseño experimental
children.push(h1("1. Diseño experimental"));
children.push(p(t("Ambos detectores se evaluaron sobre un subconjunto de 300 muestras del conjunto de hold-out (150 maliciosas y 150 benignas), es decir, muestras que el modelo de pyscan no utilizó en su entrenamiento. pyscan emite su veredicto mediante el clasificador supervisado. GuardDog no produce una etiqueta binaria calibrada, sino un conjunto de hallazgos; para poder compararlo, se consideró que marca un paquete como malicioso cuando activa al menos una regla de amenaza (threat-*), excluyendo las reglas de capacidad (capability-*), que señalan comportamientos también presentes en software legítimo.")));

// 2. Resultados
children.push(h1("2. Resultados"));
{
  const w = [Math.round(CONTENT_W*0.32), Math.round(CONTENT_W*0.17), Math.round(CONTENT_W*0.17), Math.round(CONTENT_W*0.17), Math.round(CONTENT_W*0.17)];
  const rows = [
    ["pyscan (ML)", "0,907", "0,965", "0,935", "0,033"],
    ["GuardDog (reglas)", "0,893", "0,728", "0,802", "0,336"],
  ];
  children.push(makeTable(w, ["Detector", "Recall", "Precisión", "F1", "FP"], rows,
    [{ bold: true }, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER }]));
  children.push(caption("Tabla 1. Desempeño global sobre 300 muestras (GuardDog no pudo analizar 1, excluida de su cómputo)."));
}
children.push(figure("gd_global.png", 1350, 750, 520));
children.push(caption("Figura 1. Comparación de métricas globales."));
children.push(p([
  t("La capacidad de detección (Recall) es "), t("comparable", { bold: true }),
  t(" entre ambos (0,907 vs 0,893). La diferencia principal está en la precisión: pyscan alcanza 0,965 frente a 0,728 de GuardDog, con una tasa de falsos positivos diez veces menor (0,033 vs 0,336)."),
]));

children.push(h2("2.1 Desglose por fuente del malware"));
children.push(p(t("Como las heurísticas de GuardDog se desarrollaron en parte a partir del conjunto de datos de Datadog, se desglosó el Recall por fuente para una comparación más justa. La fuente Malregistry es independiente de GuardDog.")));
{
  const w = [Math.round(CONTENT_W*0.4), Math.round(CONTENT_W*0.3), Math.round(CONTENT_W*0.3)];
  const rows = [
    ["DataDog", "0,966", "0,897"],
    ["Malregistry (independiente)", "0,893", "0,893"],
  ];
  children.push(makeTable(w, ["Fuente", "Recall pyscan", "Recall GuardDog"], rows,
    [{}, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER }]));
  children.push(caption("Tabla 2. Recall sobre malware, por fuente."));
}
children.push(figure("gd_fuente.png", 1125, 690, 400));
children.push(caption("Figura 2. Recall por fuente. En Malregistry, ambos detectores empatan."));
children.push(p([
  t("Sobre Malregistry, la fuente más independiente de GuardDog, "),
  t("ambos detectores empatan en Recall (0,893)", { bold: true }),
  t("; sobre DataDog, pyscan detecta algo más (0,966 vs 0,897). No se observó la ventaja “de casa” que cabría esperar de GuardDog en las muestras de Datadog."),
]));

// 3. Interpretación honesta
children.push(h1("3. Interpretación y limitaciones"));
children.push(p(t("Los resultados posicionan a pyscan como competitivo frente a una herramienta madura del estado del arte, con una ventaja clara en precisión. No obstante, una lectura rigurosa exige explicitar tres limitaciones de la comparación:")));
children.push(p([
  t("Propósitos distintos. ", { bold: true }),
  t("GuardDog es una herramienta de propósito general diseñada para presentar hallazgos a un analista, no para emitir un veredicto binario. Al forzarlo a una decisión binaria (≥ 1 regla de amenaza = malicioso), se penaliza su precisión, pues sus reglas se activan también en paquetes legítimos que usan subprocess, red o codificación. Su alta tasa de falsos positivos debe leerse bajo esta luz."),
]));
children.push(p([
  t("Ventaja de distribución para pyscan. ", { bold: true }),
  t("Aunque el hold-out no se usó en el entrenamiento, proviene de las mismas fuentes (DataDog y Malregistry) con las que se entrenó pyscan, lo que le confiere una ventaja de dominio. GuardDog, en cambio, no se entrena sobre datos."),
]));
children.push(p([
  t("Limitaciones ya documentadas. ", { bold: true }),
  t("El desempeño de pyscan está condicionado por la dependencia parcial de las señales de nombre (analizada en el estudio de ablación) y por el balance del conjunto (analizado en la evaluación de prevalencia realista)."),
]));

// 4. Conclusión
children.push(h1("4. Conclusión"));
children.push(p(t("En igualdad de condiciones de evaluación, pyscan iguala a GuardDog en capacidad de detección —con empate en Recall sobre la fuente independiente— y lo supera en precisión, generando muchas menos alarmas falsas. Interpretado con sus limitaciones (propósitos distintos de las herramientas, ventaja de distribución del modelo y las salvedades ya documentadas), el experimento cumple su objetivo: sitúa al detector propuesto dentro de la línea de herramientas del estado del arte y evidencia el valor de un enfoque basado en aprendizaje automático sobre señales de análisis estático, particularmente para reducir los falsos positivos. Los casos que GuardDog detecta y pyscan no constituyen, además, material valioso para el trabajo futuro.")));

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
  fs.writeFileSync("/tmp/Comparacion_pyscan_GuardDog.docx", buf);
  console.log("DOCX escrito:", buf.length, "bytes");
});
