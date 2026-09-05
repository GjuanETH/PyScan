// Capítulo 5 — Validación de la eficacia y la calidad del MVP (OE4). NTC 1486.
const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType, PageNumber, Footer,
} = require("docx");

const FONT = "Arial";
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

function cellC(text, { w, bold = false, align = AlignmentType.LEFT, fill = null, color = null } = {}) {
  return new TableCell({ width: { size: w, type: WidthType.DXA },
    shading: fill ? { type: ShadingType.CLEAR, fill, color: "auto" } : undefined,
    margins: { top: 55, bottom: 55, left: 85, right: 85 },
    children: [new Paragraph({ alignment: align, spacing: { line: 254, after: 0 },
      children: [new TextRun({ text, font: FONT, size: 18, bold, color: color || undefined })] })] });
}
function headerRow(cells, widths) {
  return new TableRow({ tableHeader: true, children: cells.map((c, i) => new TableCell({
    width: { size: widths[i], type: WidthType.DXA },
    shading: { type: ShadingType.CLEAR, fill: "1F3864", color: "auto" },
    margins: { top: 55, bottom: 55, left: 85, right: 85 },
    children: [new Paragraph({ alignment: AlignmentType.CENTER, spacing: { line: 254, after: 0 },
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
      ...rows.map((r) => new TableRow({ children: r.map((c, i) => cellC(c, { w: widths[i], ...(rowOpts[i] || {}) })) }))] });
}

const children = [];

children.push(h1("5. VALIDACIÓN DE LA EFICACIA Y LA CALIDAD DEL MVP"));
children.push(p([t("Este capítulo desarrolla el cuarto objetivo específico: "),
  t("validar la eficacia y la calidad del MVP mediante un plan de pruebas, con el fin de verificar que el software cumple con los requerimientos definidos.", { italics: true }),
  t(" Se presentan el plan de pruebas, los resultados del clasificador (validación cruzada y hold-out), la matriz de confusión, la evaluación de desempeño y una síntesis del cumplimiento de todos los KPI del proyecto.")]));

// 5.1 Plan de pruebas
children.push(h2("5.1 Plan de pruebas"));
children.push(p(t("La validación se estructuró bajo la guía de medición ISO/IEC 25023, abarcando cuatro tipos de prueba. Las pruebas unitarias verifican cada función de los módulos en aislamiento; las de integración comprueban el pipeline completo contra PyPI real; las de regresión se ejecutan en cada cambio para preservar el comportamiento; y las de carga/rendimiento miden el tiempo y la memoria por paquete. La Tabla 2 resume el plan.")));
{
  const w = [Math.round(CONTENT_W*0.24), Math.round(CONTENT_W*0.52), Math.round(CONTENT_W*0.24)];
  const rows = [
    ["Unitarias", "Verificación de funciones por módulo con pytest.", "58 pruebas OK"],
    ["Integración", "Pipeline completo sobre paquetes reales de PyPI.", "OK"],
    ["Regresión", "Ejecución de la suite ante cada cambio antes de publicar.", "Suite estable"],
    ["Carga / rendimiento", "Tiempo y memoria por paquete (benchmark_performance.py).", "Ver 5.4"],
  ];
  children.push(makeTable(w, ["Tipo de prueba", "Descripción", "Resultado"], rows,
    [{ bold: true }, {}, { align: AlignmentType.CENTER }]));
  children.push(caption("Tabla 2. Plan de pruebas del MVP."));
}
children.push(p(t("La suite consta de 58 pruebas automatizadas que pasan en su totalidad, con una cobertura de código del 91 % (detallada por módulo en el capítulo 4). En las corridas sobre miles de paquetes reales no se registraron excepciones no controladas: las muestras corruptas se omiten con un aviso, evidenciando la tolerancia a fallos.")));

// 5.2 Validación del clasificador
children.push(h2("5.2 Validación del clasificador (k-fold y hold-out)"));
children.push(p(t("El clasificador se evaluó sobre un dataset de 4.000 muestras balanceadas, dividido en 3.200 para entrenamiento y 800 como hold-out (80/20, estratificado). Sobre el conjunto de entrenamiento se aplicó validación cruzada estratificada de cinco particiones (k=5), evaluando Random Forest y XGBoost; se seleccionó XGBoost por su mejor equilibrio. La Tabla 3 muestra los resultados de la validación cruzada.")));
{
  const w = [Math.round(CONTENT_W*0.26), Math.round(CONTENT_W*0.15), Math.round(CONTENT_W*0.15), Math.round(CONTENT_W*0.15), Math.round(CONTENT_W*0.15), Math.round(CONTENT_W*0.14)];
  const rows = [
    ["Random Forest", "0,964", "0,971", "0,968", "0,994", "0,028"],
    ["XGBoost (seleccionado)", "0,961", "0,977", "0,969", "0,994", "0,023"],
  ];
  children.push(makeTable(w, ["Modelo", "Recall", "Precisión", "F1", "PR-AUC", "FP"], rows,
    [{ bold: true }, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER }]));
  children.push(caption("Tabla 3. Resultados de la validación cruzada estratificada (k=5)."));
}
children.push(p([t("En el conjunto de hold-out (769 muestras no vistas en el entrenamiento), el modelo alcanzó "),
  t("Recall 0,971, Precisión 0,979 y F1 0,975", { bold: true }),
  t(", confirmando su capacidad de generalización.")]));

// 5.3 Matriz de confusión
children.push(h2("5.3 Matriz de confusión"));
children.push(p(t("La Tabla 4 presenta la matriz de confusión del modelo seleccionado (predicciones out-of-fold de la validación cruzada, 3.095 muestras).")));
{
  const w = [Math.round(CONTENT_W*0.34), Math.round(CONTENT_W*0.33), Math.round(CONTENT_W*0.33)];
  const rows = [
    ["Real: Malicioso", "VP = 1.484", "FN = 61"],
    ["Real: Benigno", "FP = 35", "VN = 1.515"],
  ];
  children.push(makeTable(w, ["", "Predicho: Malicioso", "Predicho: Benigno"], rows,
    [{ bold: true }, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER }]));
  children.push(caption("Tabla 4. Matriz de confusión (validación cruzada, XGBoost)."));
}
children.push(p(t("De 1.545 paquetes maliciosos, el modelo detectó 1.484 (61 falsos negativos), y de 1.550 benignos solo marcó 35 como maliciosos. Esto se traduce en un Recall de 0,96 y una tasa de falsos positivos de 2,3 %, ambos dentro de las metas.")));

// 5.4 Desempeño
children.push(h2("5.4 Pruebas de desempeño"));
children.push(p([
  t("Con el script benchmark_performance.py se midió el análisis completo por paquete sobre paquetes reales de PyPI. El "),
  t("tiempo máximo fue de ≈ 1,5 s por paquete", { bold: true }),
  t(" (muy por debajo del límite de 120 s) y el "),
  t("consumo de memoria (RSS) ≈ 63 MB", { bold: true }),
  t(" (límite 2 GB). El sistema es, por tanto, rápido y liviano.")]));

// 5.5 Evaluación complementaria
children.push(h2("5.5 Evaluación complementaria de robustez"));
children.push(p(t("Más allá del plan mínimo, se realizaron tres análisis adicionales que refuerzan la validez del sistema. El estudio de ablación mostró que, aun eliminando las señales de nombre, el modelo mantiene un Recall de 0,91 con solo las señales de código, descartando una dependencia excesiva del nombre. La evaluación a prevalencia realista (1:100) evidenció que —como todo detector de eventos raros— la precisión desciende al aumentar el desbalance, y que puede recuperarse ajustando el umbral de decisión. Finalmente, la comparación empírica con GuardDog (Datadog) sobre el mismo conjunto arrojó un Recall comparable (empate de 0,89 en la fuente independiente) y una precisión superior de pyscan (0,97 frente a 0,73). El detalle de estos análisis se documenta en los anexos correspondientes.")));

// 5.6 Cumplimiento de KPI
children.push(h2("5.6 Cumplimiento de los indicadores clave (KPI)"));
children.push(p(t("La Tabla 5 sintetiza el cumplimiento de todos los KPI definidos en la sección 1.4.3, para los cuatro objetivos específicos.")));
{
  const w = [Math.round(CONTENT_W*0.09), Math.round(CONTENT_W*0.45), Math.round(CONTENT_W*0.16), Math.round(CONTENT_W*0.16), Math.round(CONTENT_W*0.14)];
  const OK = { align: AlignmentType.CENTER, bold: true, fill: "E2EFDA" };
  const C = { align: AlignmentType.CENTER };
  const rows = [
    ["OE1", "Cobertura de vectores de ataque (en alcance)", "≥ 90 %", "> 90 %", "Cumple"],
    ["OE1", "Trazabilidad de requerimientos", "100 %", "100 %", "Cumple"],
    ["OE2", "Cobertura arquitectónica", "100 %", "100 %", "Cumple"],
    ["OE2", "Independencia de módulos", "4/4", "4/4", "Cumple"],
    ["OE3", "Implementación de funciones (pruebas OK)", "≥ 95 %", "100 %", "Cumple"],
    ["OE3", "Cobertura de código", "≥ 80 %", "91 %", "Cumple"],
    ["OE3", "Tasa de fallos no manejados", "≤ 1 %", "≈ 0 %", "Cumple"],
    ["OE4", "Recall del clasificador", "≥ 0,90", "0,97", "Cumple"],
    ["OE4", "F1-Score del clasificador", "≥ 0,85", "0,975", "Cumple"],
    ["OE4", "Tasa de falsos positivos", "≤ 10 %", "2,3 %", "Cumple"],
    ["OE4", "Tiempo de análisis por paquete", "≤ 120 s", "≈ 1,5 s", "Cumple"],
    ["OE4", "Memoria RAM pico", "≤ 2 GB", "≈ 63 MB", "Cumple"],
  ];
  children.push(makeTable(w, ["OE", "KPI", "Meta", "Resultado", "Estado"], rows,
    [{ align: AlignmentType.CENTER, bold: true }, {}, C, { align: AlignmentType.CENTER, bold: true }, OK]));
  children.push(caption("Tabla 5. Cumplimiento consolidado de los KPI (sección 1.4.3)."));
}

// 5.7 Conclusión
children.push(h2("5.7 Conclusión parcial"));
children.push(p(t("El plan de pruebas y la validación del clasificador demuestran que el MVP cumple la totalidad de los indicadores clave definidos al inicio del proyecto: alcanza un Recall de 0,97 y un F1 de 0,975 con una tasa de falsos positivos del 2,3 %, se ejecuta en ≈1,5 s por paquete con ≈63 MB de memoria, y respalda su estabilidad con 58 pruebas automatizadas y una cobertura del 91 %. Los análisis complementarios de ablación, prevalencia realista y comparación con el estado del arte confirman la solidez y la honestidad de los resultados. Con ello se cumple el cuarto objetivo específico y se valida la eficacia y la calidad del sistema propuesto.")));

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
  fs.writeFileSync("/tmp/Capitulo5_Validacion.docx", buf);
  console.log("DOCX escrito:", buf.length, "bytes");
});
