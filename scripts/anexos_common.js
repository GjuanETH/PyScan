// Ayudantes comunes para los anexos (NTC 1486: Arial 12, márgenes 3-3-4-2 cm, interlineado 1,5).
const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType, PageNumber, Footer, ImageRun,
} = require("docx");

const FONT = "Arial";
const CM = 567;
const CONTENT_W = Math.round(21 * CM) - (4 * CM) - (2 * CM);
const ROOT = path.resolve(__dirname, "..");
const IMG = path.join(ROOT, "docs", "diagrams", "anexos");
const OUT_DIR = path.resolve(ROOT, "..", "Anexos");

const t = (text, opts = {}) => new TextRun({ text, font: FONT, size: 24, ...opts });
const p = (runs, opts = {}) => new Paragraph({
  spacing: { line: 360, after: 120 }, alignment: AlignmentType.JUSTIFIED,
  children: Array.isArray(runs) ? runs : [typeof runs === "string" ? t(runs) : runs], ...opts });
const h1 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 160 },
  children: [new TextRun({ text, font: FONT, size: 24, bold: true, color: "000000" })] });
const h2 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 200, after: 120 },
  children: [new TextRun({ text, font: FONT, size: 24, bold: true, italics: true, color: "000000" })] });
const bullet = (runs) => new Paragraph({ spacing: { line: 360, after: 80 }, alignment: AlignmentType.JUSTIFIED,
  indent: { left: 567, hanging: 283 },
  children: [t("•\t"), ...(Array.isArray(runs) ? runs : [typeof runs === "string" ? t(runs) : runs])] });
const code = (lines) => lines.map((l, i) => new Paragraph({ spacing: { line: 240, after: i === lines.length - 1 ? 160 : 0 },
  indent: { left: 567 }, shading: { type: ShadingType.CLEAR, fill: "F2F2F2", color: "auto" },
  children: [new TextRun({ text: l, font: "Courier New", size: 18 })] }));
const title = (anexo, sub) => [
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 80 },
    children: [new TextRun({ text: anexo, font: FONT, size: 24, bold: true })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 240 },
    children: [new TextRun({ text: sub, font: FONT, size: 24, bold: true })] }),
];
const caption = (text) => new Paragraph({ spacing: { before: 60, after: 60 }, alignment: AlignmentType.LEFT,
  keepNext: true, children: [new TextRun({ text, font: FONT, size: 22, bold: true })] });
const source = (text = "Fuente: elaboración propia.") => new Paragraph({ spacing: { before: 40, after: 200 },
  children: [new TextRun({ text, font: FONT, size: 20, italics: true })] });
function figure(file, targetW = 540) {
  const buf = fs.readFileSync(path.join(IMG, file));
  const w = buf.readUInt32BE(16), h = buf.readUInt32BE(20);
  return new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 60, after: 40 }, keepNext: true,
    children: [new ImageRun({ type: "png", data: buf,
      transformation: { width: targetW, height: Math.round(h * targetW / w) } })] });
}
function cell(text, { w, bold = false, align = AlignmentType.CENTER, fill = null } = {}) {
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
// fracs: proporciones del ancho; firstLeft: primera columna alineada a la izquierda; boldRows: índices en negrita
function table(fracs, header, rows, { firstLeft = true, boldRows = [], highlightRows = [] } = {}) {
  const widths = fracs.map((f) => Math.round(CONTENT_W * f));
  const b = { style: BorderStyle.SINGLE, size: 4, color: "999999" };
  const bi = { style: BorderStyle.SINGLE, size: 2, color: "CCCCCC" };
  return new Table({ columnWidths: widths, width: { size: widths.reduce((a, c) => a + c, 0), type: WidthType.DXA },
    borders: { top: b, bottom: b, left: b, right: b, insideHorizontal: bi, insideVertical: bi },
    rows: [headerRow(header, widths), ...rows.map((r, ri) => new TableRow({ children: r.map((c, i) => cell(c, {
      w: widths[i], bold: boldRows.includes(ri),
      fill: highlightRows.includes(ri) ? "E8EEF7" : null,
      align: (i === 0 && firstLeft) ? AlignmentType.LEFT : AlignmentType.CENTER })) }))] });
}
const n = (v, d = 3) => { const [i, f] = Math.abs(v).toFixed(d).split(".");
  return (v < 0 ? "-" : "") + i.replace(/\B(?=(\d{3})+(?!\d))/g, ".") + (f ? "," + f : ""); };
const pct = (v, d = 1) => (v * 100).toFixed(d).replace(".", ",") + " %";
const miles = (v) => v.toLocaleString("es-CO").replace(/,/g, ".");

function save(children, file) {
  const doc = new Document({
    creator: "pyscan - Trabajo de Grado",
    styles: { default: { document: { run: { font: FONT, size: 24 } } } },
    sections: [{
      properties: { page: { size: { width: Math.round(21 * CM), height: Math.round(29.7 * CM) },
        margin: { top: 3 * CM, bottom: 3 * CM, left: 4 * CM, right: 2 * CM } } },
      footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER,
        children: [new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 20 })] })] }) },
      children,
    }],
  });
  fs.mkdirSync(OUT_DIR, { recursive: true });
  return Packer.toBuffer(doc).then((buf) => {
    fs.writeFileSync(path.join(OUT_DIR, file), buf);
    console.log("DOCX:", file, buf.length, "bytes");
  });
}
const readJSON = (rel) => JSON.parse(fs.readFileSync(path.join(ROOT, rel), "utf-8"));

module.exports = { t, p, h1, h2, bullet, code, title, caption, source, figure, table, n, pct, miles, save, readJSON, CONTENT_W };
