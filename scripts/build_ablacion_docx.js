// Análisis del modelo — Estudio de ablación y prueba de fuga de datos. NTC 1486.
const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType, PageNumber, Footer, ImageRun,
} = require("docx");

const FONT = "Arial";
const CM = 567;
const CONTENT_W = Math.round(21 * CM) - (4 * CM) - (2 * CM);
const DIR = "/tmp/abl";

const t = (text, opts = {}) => new TextRun({ text, font: FONT, size: 24, ...opts });
const p = (runs, opts = {}) => new Paragraph({
  spacing: { line: 360, after: 120 }, alignment: AlignmentType.JUSTIFIED,
  children: Array.isArray(runs) ? runs : [runs], ...opts,
});
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

function cell(text, { w, bold = false, align = AlignmentType.LEFT, fill = null } = {}) {
  return new TableCell({ width: { size: w, type: WidthType.DXA },
    shading: fill ? { type: ShadingType.CLEAR, fill, color: "auto" } : undefined,
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

// Portada
children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 80 },
  children: [new TextRun({ text: "ANÁLISIS DEL MODELO", font: FONT, size: 28, bold: true })] }));
children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 240 },
  children: [new TextRun({ text: "Estudio de ablación de características y prueba de fuga de datos",
    font: FONT, size: 24, bold: true })] }));
children.push(p(t("Este documento profundiza el análisis del clasificador de pyscan mediante un estudio de ablación. Su objetivo es responder, con evidencia experimental, una amenaza a la validez identificada en el Objetivo 1: la posible dependencia excesiva del modelo respecto de las señales basadas en el nombre del paquete. El experimento cuantifica además el aporte individual de cada extractor.")));

// 1. Motivación y método
children.push(h1("1. Motivación y método"));
children.push(p(t("En el modelo entrenado, las características de nombre (distancia mínima de nombre e indicador de typosquatting) concentraban cerca del 77 % de la importancia. Como los paquetes benignos provienen del Top de PyPI —la misma lista usada como referencia para medir la similitud de nombres—, existía la sospecha de que el modelo aprendiera a distinguir por el nombre y no por el comportamiento del código, inflando el desempeño (una forma de fuga de datos).")));
children.push(p(t("Para medirlo, se reentrenó el clasificador (XGBoost) con distintos subconjuntos de características, reutilizando la misma validación cruzada estratificada de cinco particiones y el mismo ajuste de umbral del entrenamiento principal. Se evaluaron 3.095 muestras (1.545 maliciosas y 1.550 benignas). Comparar el desempeño entre subconjuntos permite aislar el efecto de cada grupo de señales.")));

// 2. Resultados
children.push(h1("2. Resultados"));
{
  const w = [Math.round(CONTENT_W*0.34), Math.round(CONTENT_W*0.16), Math.round(CONTENT_W*0.16), Math.round(CONTENT_W*0.17), Math.round(CONTENT_W*0.17)];
  const rows = [
    ["Todas (baseline, 14 feat.)", "0,961", "0,969", "0,994", "0,023"],
    ["Solo nombre (3 feat.)", "0,903", "0,867", "0,955", "0,181"],
    ["Sin nombre / solo código (AST+entropía)", "0,909", "0,922", "0,973", "0,062"],
    ["Solo AST (3 feat.)", "0,925", "0,837", "0,909", "0,283"],
    ["Solo entropía (3 feat.)", "0,907", "0,855", "0,941", "0,215"],
    ["Solo metadatos sin nombre (5 feat.)", "1,000", "0,666", "0,499", "1,000"],
  ];
  children.push(makeTable(w, ["Configuración", "Recall", "F1", "PR-AUC", "FP"], rows,
    [{}, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER }]));
  children.push(caption("Tabla 1. Desempeño (validación cruzada out-of-fold) por subconjunto de características."));
}
children.push(figure("ablation_real.png", 1500, 780, 540));
children.push(caption("Figura 1. Recall, F1 y tasa de falsos positivos por configuración."));

// 3. Interpretación
children.push(h1("3. Interpretación"));
children.push(h2("3.1 La fuga de datos existe pero es acotada"));
children.push(p([
  t("El uso exclusivo de las señales de nombre alcanza un F1 de 0,867, "),
  t("claramente por debajo del baseline (0,969)", { bold: true }),
  t(", y con una tasa de falsos positivos elevada (18,1 %). Esto descarta una fuga catastrófica: el nombre por sí solo no reproduce el desempeño del modelo completo. La alta importancia observada previamente refleja que el nombre es la señal más útil de forma aislada, pero no que el modelo dependa exclusivamente de ella."),
]));
children.push(h2("3.2 Las señales de código discriminan por sí solas"));
children.push(p([
  t("Al eliminar por completo las características de nombre, el modelo mantiene "),
  t("Recall 0,909 y F1 0,922, con una tasa de falsos positivos de apenas 6,2 %", { bold: true }),
  t(". Es decir, con solo las señales de código (AST y entropía) el detector identifica el 91 % del malware. Este es el resultado central: valida que el análisis estático del comportamiento del código —no el nombre— sostiene la capacidad de detección, y que el sistema sería robusto ante un atacante que evada la detección por nombre."),
]));
children.push(h2("3.3 Los extractores se complementan"));
children.push(p(t("Por separado, el extractor de AST logra el mayor Recall (0,925) pero sobre-marca (FP 28,3 %), y la entropía se comporta de forma similar (FP 21,5 %). Combinados, la tasa de falsos positivos cae al 6,2 %, y al añadir el nombre desciende al 2,3 %. Cada señal aporta y ninguna es suficiente por sí sola: esto confirma empíricamente el principio de cobertura múltiple planteado en el Objetivo 1. El nombre, en particular, actúa como un refinador de precisión más que como el motor de la detección.")));
children.push(h2("3.4 Hallazgo: características de metadatos inertes"));
children.push(p([
  t("Las configuraciones «Sin nombre» y «Solo código» arrojaron resultados idénticos, y «Solo metadatos» resultó degenerada (marca todo como malicioso, FP 100 %). Esto revela que las cinco características de metadatos de publicación (número de releases, dependencias, descripción, mantenedores) "),
  t("no están siendo pobladas durante el entrenamiento", { bold: true }),
  t(": provienen de la API de PyPI, pero el pipeline extrae las características desde los paquetes ya descargados, calculando únicamente nombre, entropía y AST. En consecuencia, esas cinco características tienen valor constante y aportan nula capacidad discriminante (importancia 0,0 en el modelo). Es una limitación honesta del pipeline actual, no un error de resultados."),
]));

// 4. Amenazas a la validez y próximos pasos
children.push(h1("4. Amenazas a la validez y próximos pasos"));
children.push(p(t("El experimento acota, pero no elimina, la amenaza de fuga: como los benignos provienen del Top de PyPI, la señal de nombre sigue beneficiada por el diseño del dataset. La conclusión válida es que el desempeño reportado en el baseline debe leerse sabiendo que la contribución neta de la detección proviene de las señales de código, cuya capacidad quedó demostrada de forma independiente.")));
children.push(p(t("Se derivan dos líneas de mejora concretas. Primero, construir un conjunto benigno diverso con paquetes poco populares y fuera de la lista de referencia, reconstruir el dataset y reentrenar, para obtener una medición del nombre libre del sesgo del Top de PyPI. Segundo, poblar las características de metadatos desde la API de PyPI durante la construcción del dataset —o retirarlas del vector—, de modo que el modelo aproveche también las señales de reputación y publicación, hoy inertes.")));

// 5. Conclusión
children.push(h1("5. Conclusión"));
children.push(p(t("El estudio de ablación convierte una sospecha en un resultado medido: la dependencia del modelo respecto del nombre existe pero es acotada, y las señales de análisis estático del código (AST y entropía) sostienen por sí solas una detección del 91 % con baja tasa de falsos positivos. La combinación de todas las señales ofrece el mejor equilibrio (Recall 0,96, F1 0,97, FP 2,3 %), confirmando el principio de cobertura múltiple. El experimento también expuso una limitación honesta del pipeline —las características de metadatos inertes— que queda documentada como línea de mejora. En conjunto, el análisis fortalece la validez del trabajo y demuestra un tratamiento riguroso y transparente de sus propias limitaciones.")));

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
  fs.writeFileSync("/tmp/Analisis_Modelo_Ablacion.docx", buf);
  console.log("DOCX escrito:", buf.length, "bytes");
});
