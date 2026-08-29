// Análisis del modelo — Evaluación bajo prevalencia realista. NTC 1486.
const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType, PageNumber, Footer, ImageRun,
} = require("docx");

const FONT = "Arial";
const CM = 567;
const CONTENT_W = Math.round(21 * CM) - (4 * CM) - (2 * CM);
const DIR = "/tmp/imb";

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

children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 80 },
  children: [new TextRun({ text: "ANÁLISIS DEL MODELO", font: FONT, size: 28, bold: true })] }));
children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 240 },
  children: [new TextRun({ text: "Evaluación bajo prevalencia realista de clases", font: FONT, size: 24, bold: true })] }));
children.push(p(t("Este documento evalúa el comportamiento del clasificador de pyscan cuando la proporción de paquetes maliciosos es la del mundo real —muy inferior a la del conjunto de datos de entrenamiento—. Es una pregunta esperable en la evaluación de cualquier detector de eventos raros y su respuesta matiza la interpretación de las métricas obtenidas con un conjunto balanceado.")));

// 1. Motivación y método
children.push(h1("1. Motivación y método"));
children.push(p(t("El conjunto de datos se construyó con un balance cercano a 1:1 entre paquetes maliciosos y benignos. En producción, sin embargo, el malware es minoritario: se estima una prevalencia del orden de 1:100 a 1:1000. Bajo ese desbalance, dos métricas se comportan de manera distinta. El Recall (proporción de malware detectado) y la tasa de falsos positivos (FPR) son propiedades del clasificador y no dependen de la prevalencia. La precisión (proporción de alarmas que son realmente maliciosas), en cambio, sí depende: cuando los benignos son mayoría abrumadora, incluso una FPR baja genera muchas alarmas falsas por cada acierto.")));
children.push(p([
  t("Aprovechando esa independencia, no fue necesario recolectar más paquetes benignos. Se midieron el Recall (0,971) y la FPR (0,021) sobre el conjunto de hold-out (769 muestras, umbral de operación 0,54) y se proyectó la precisión esperada a distintas prevalencias π mediante la identidad "),
  t("precisión(π) = TPR·π / (TPR·π + FPR·(1−π))", { bold: true }),
  t("."),
]));

// 2. Resultados
children.push(h1("2. Resultados"));
children.push(h2("2.1 Precisión proyectada según la prevalencia"));
{
  const w = [Math.round(CONTENT_W*0.20), Math.round(CONTENT_W*0.17), Math.round(CONTENT_W*0.15), Math.round(CONTENT_W*0.16), Math.round(CONTENT_W*0.16), Math.round(CONTENT_W*0.16)];
  const rows = [
    ["1:1 (dataset)", "0,979", "0,971", "0,975", "≈4.959", "0,02"],
    ["1:9", "0,840", "0,971", "0,901", "1.157", "0,19"],
    ["1:19", "0,713", "0,971", "0,822", "681", "0,40"],
    ["1:99 (realista)", "0,322", "0,971", "0,484", "301", "2,10"],
    ["1:199", "0,191", "0,971", "0,320", "254", "4,23"],
    ["1:999 (muy realista)", "0,045", "0,971", "0,086", "216", "21,21"],
  ];
  children.push(makeTable(w, ["Prevalencia", "Precisión", "Recall", "F1", "Alarmas/10k", "Falsas/acierto"], rows,
    [{}, { align: AlignmentType.CENTER, bold: true }, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER }]));
  children.push(caption("Tabla 1. Desempeño proyectado a distintas prevalencias, con el umbral de operación (0,54)."));
}
children.push(figure("imb_prevalencia.png", 1350, 750, 520));
children.push(caption("Figura 1. La precisión decae al reducirse la prevalencia, mientras el Recall permanece constante."));

children.push(h2("2.2 Ajuste del umbral a prevalencia realista"));
children.push(p(t("Para atenuar el efecto anterior se realizó un barrido del umbral de decisión a una prevalencia de 1:100. Subir el umbral reduce la tasa de falsos positivos y, por tanto, eleva la precisión, a costa de algo de Recall. La Tabla 2 muestra puntos representativos.")));
{
  const w = [Math.round(CONTENT_W*0.22), Math.round(CONTENT_W*0.20), Math.round(CONTENT_W*0.20), Math.round(CONTENT_W*0.19), Math.round(CONTENT_W*0.19)];
  const rows = [
    ["0,54 (operación)", "0,971", "0,322", "0,484", "0,0206"],
    ["0,70", "0,963", "0,386", "0,551", "0,0155"],
    ["0,85", "0,950", "0,427", "0,589", "0,0129"],
    ["0,95 (sugerido)", "0,937", "0,550", "0,693", "0,0077"],
  ];
  children.push(makeTable(w, ["Umbral", "Recall", "Precisión (proy.)", "F1 (proy.)", "FPR"], rows,
    [{ bold: true }, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER }]));
  children.push(caption("Tabla 2. Barrido de umbral a prevalencia 1:100 (extracto)."));
}
children.push(figure("imb_umbral.png", 1350, 750, 520));
children.push(caption("Figura 2. Equilibrio precisión–recall al variar el umbral a prevalencia 1:100."));

// 3. Interpretación
children.push(h1("3. Interpretación"));
children.push(p([
  t("A la prevalencia realista de 1:100, la precisión proyectada desciende al 32 %: aproximadamente "),
  t("dos alarmas falsas por cada detección verdadera", { bold: true }),
  t(". A 1:1000 el efecto se agrava (una detección real por cada veintiún avisos falsos). Es fundamental subrayar que esto "),
  t("no constituye un defecto del modelo", { bold: true }),
  t(": es una consecuencia matemática inevitable de detectar eventos raros, que afecta por igual a cualquier detector —incluidas las herramientas comerciales— y se conoce como la paradoja del falso positivo. El Recall se mantiene en 0,971 en todos los escenarios, es decir, la capacidad de no dejar pasar malware no se degrada."),
]));
children.push(p([
  t("El barrido de umbral ofrece la vía práctica de mitigación. Elevando el umbral a 0,95, a prevalencia 1:100 la precisión sube al 55 % conservando un Recall de 0,937. "),
  t("En un despliegue real, pyscan se operaría con un umbral orientado a la precisión, o como primer filtro de alto Recall seguido de una etapa de verificación", { bold: true }),
  t(" (revisión humana o un segundo analizador). Esta decisión de operación es coherente con la prioridad del proyecto de minimizar los falsos negativos sin saturar de alarmas al usuario."),
]));

// 4. Conclusión
children.push(h1("4. Conclusión"));
children.push(p(t("La evaluación bajo prevalencia realista demuestra un tratamiento riguroso de las condiciones de despliegue. El modelo mantiene un Recall alto e independiente de la prevalencia, pero su precisión —como la de cualquier detector de eventos raros— depende de la proporción real de malware y decae al 32 % a 1:100 con el umbral de operación. El ajuste del umbral recupera precisión de forma controlada (55 % a 1:100 con Recall 0,94), y motiva un esquema de operación en dos etapas. Documentar este comportamiento, en lugar de reportar únicamente las métricas balanceadas, fortalece la validez externa del trabajo y anticipa una de las preguntas centrales sobre su aplicabilidad práctica.")));

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
  fs.writeFileSync("/tmp/Analisis_Modelo_Desbalance.docx", buf);
  console.log("DOCX escrito:", buf.length, "bytes");
});
