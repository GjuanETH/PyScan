// Cuadro comparativo de arquitecturas + justificación. NTC 1486.
const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType, PageNumber, Footer,
} = require("docx");
const FONT = "Arial", CM = 567;
const CONTENT_W = Math.round(21 * CM) - (4 * CM) - (2 * CM);
const t = (x, o = {}) => new TextRun({ text: x, font: FONT, size: 24, ...o });
const p = (r, o = {}) => new Paragraph({ spacing: { line: 360, after: 120 }, alignment: AlignmentType.JUSTIFIED, children: Array.isArray(r) ? r : [r], ...o });
const h1 = (x) => new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 160 }, children: [new TextRun({ text: x, font: FONT, size: 28, bold: true })] });
const h2 = (x) => new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 200, after: 120 }, children: [new TextRun({ text: x, font: FONT, size: 24, bold: true })] });
const capn = (x) => new Paragraph({ spacing: { before: 20, after: 180 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: x, font: FONT, size: 20, italics: true })] });
function cl(x, { w, b = false, a = AlignmentType.LEFT, fill = null } = {}) {
  return new TableCell({ width: { size: w, type: WidthType.DXA }, shading: fill ? { type: ShadingType.CLEAR, fill, color: "auto" } : undefined,
    margins: { top: 55, bottom: 55, left: 80, right: 80 },
    children: [new Paragraph({ alignment: a, spacing: { line: 250, after: 0 }, children: [new TextRun({ text: x, font: FONT, size: 17, bold: b })] })] });
}
function hrow(cs, ws) { return new TableRow({ tableHeader: true, children: cs.map((c, i) => new TableCell({ width: { size: ws[i], type: WidthType.DXA }, shading: { type: ShadingType.CLEAR, fill: "1F3864", color: "auto" }, margins: { top: 55, bottom: 55, left: 80, right: 80 }, children: [new Paragraph({ alignment: AlignmentType.CENTER, spacing: { line: 250, after: 0 }, children: [new TextRun({ text: c, font: FONT, size: 17, bold: true, color: "FFFFFF" })] })] })) }); }
function tbl(ws, head, rows, opts = []) { return new Table({ columnWidths: ws, width: { size: ws.reduce((a, b) => a + b, 0), type: WidthType.DXA },
  borders: { top: { style: BorderStyle.SINGLE, size: 4, color: "999999" }, bottom: { style: BorderStyle.SINGLE, size: 4, color: "999999" }, left: { style: BorderStyle.SINGLE, size: 4, color: "999999" }, right: { style: BorderStyle.SINGLE, size: 4, color: "999999" }, insideHorizontal: { style: BorderStyle.SINGLE, size: 2, color: "CCCCCC" }, insideVertical: { style: BorderStyle.SINGLE, size: 2, color: "CCCCCC" } },
  rows: [hrow(head, ws), ...rows.map((r) => new TableRow({ children: r.map((c, i) => cl(c, { w: ws[i], ...(opts[i] || {}) })) }))] }); }
const C = { a: AlignmentType.CENTER };

const ch = [];
ch.push(h1("Cuadro comparativo de arquitecturas y justificación de la elección"));
ch.push(p(t("Como parte del diseño del MVP se evaluaron cuatro estilos arquitectónicos frente a los requerimientos no funcionales del sistema, en especial la mantenibilidad y la eficiencia. Este documento presenta la comparación y justifica la elección del monolito modular con patrón Pipes and Filters.")));

ch.push(h2("1. Estilos evaluados"));
ch.push(p([
  t("Monolito modular (Pipes and Filters): ", { bold: true }),
  t("una sola aplicación desplegable, organizada como una tubería de filtros independientes que se comunican por estructuras de datos tipadas."),
]));
ch.push(p([t("Microservicios: ", { bold: true }), t("cada extractor y el clasificador como servicios independientes que se comunican por red (API).")]));
ch.push(p([t("Monolito no estructurado: ", { bold: true }), t("una sola aplicación sin separación clara de módulos ni contratos entre ellos.")]));
ch.push(p([t("Arquitectura por capas: ", { bold: true }), t("separación en capas horizontales (presentación, lógica, datos) sin el flujo por filtros.")]));

ch.push(h2("2. Cuadro comparativo"));
ch.push(tbl(
  [Math.round(CONTENT_W*0.30), Math.round(CONTENT_W*0.19), Math.round(CONTENT_W*0.17), Math.round(CONTENT_W*0.17), Math.round(CONTENT_W*0.17)],
  ["Criterio", "Monolito modular + Pipes and Filters", "Micro-servicios", "Monolito no estructurado", "Por capas"],
  [
    ["Complejidad operativa / despliegue", "Baja (un binario/CLI)", "Alta (orquestación, red)", "Baja", "Media"],
    ["Mantenibilidad y separación", "Alta", "Alta", "Baja", "Media"],
    ["Independencia y prueba de módulos", "Alta (cada filtro se prueba solo)", "Alta", "Baja", "Media"],
    ["Facilidad de extender (nuevos extractores)", "Alta (agregar un filtro)", "Media-alta", "Baja", "Media"],
    ["Rendimiento / latencia", "Alta (en proceso)", "Menor (saltos de red)", "Alta", "Alta"],
    ["Costo de infraestructura", "Nulo", "Alto (servicios)", "Nulo", "Bajo"],
    ["Adecuación a un MVP de línea de comandos", "Muy alta", "Baja", "Media", "Media"],
  ],
  [{ b: true }, { a: AlignmentType.CENTER, fill: "E2EFDA", b: true }, C, C, C]
));
ch.push(capn("Tabla 1. Comparación de estilos arquitectónicos frente a los criterios del proyecto."));

ch.push(h2("3. Justificación de la elección"));
ch.push(p([
  t("Se eligió el "),
  t("monolito modular con patrón Pipes and Filters", { bold: true }),
  t(" porque ofrece el mejor equilibrio para un MVP de línea de comandos. Frente a los "),
  t("microservicios", { bold: true }),
  t(", evita una complejidad operativa y un costo de infraestructura desproporcionados (orquestación, comunicación por red, despliegue de varios servicios) que no aportan valor a una herramienta que se ejecuta localmente o en un agente de CI. Frente al "),
  t("monolito no estructurado", { bold: true }),
  t(", preserva la mantenibilidad, la testeabilidad y la modularidad exigidas por los requerimientos no funcionales (RNF10–RNF12). Frente a la "),
  t("arquitectura por capas", { bold: true }),
  t(", el patrón Pipes and Filters modela con naturalidad un flujo de análisis por etapas (descarga → extracción → características → veredicto), en el que cada extractor es un filtro independiente e intercambiable.")]));
ch.push(p(t("En concreto, el estilo elegido permite agregar, reemplazar o probar cada extractor en aislamiento; comunica las etapas mediante modelos tipados de Pydantic que validan los datos en tránsito; y mantiene un despliegue simple, rápido y sin dependencias de infraestructura. Estas propiedades sostienen directamente las metas de mantenibilidad y eficiencia del sistema, por lo que constituyó la decisión más adecuada al alcance del trabajo.")));

const doc = new Document({ creator: "pyscan", styles: { default: { document: { run: { font: FONT, size: 24 } } } },
  sections: [{ properties: { page: { size: { width: Math.round(21 * CM), height: Math.round(29.7 * CM) }, margin: { top: 3 * CM, bottom: 3 * CM, left: 4 * CM, right: 2 * CM } } },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 20 })] })] }) },
    children: ch }] });
Packer.toBuffer(doc).then((b) => { fs.writeFileSync("/tmp/Comparativo_Arquitecturas.docx", b); console.log("OK", b.length); });
