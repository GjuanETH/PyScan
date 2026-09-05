// Manual de usuario de pyscan. NTC 1486.
const fs = require("fs");
const { Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType, PageNumber, Footer } = require("docx");
const FONT = "Arial", MONO = "Consolas", CM = 567;
const CONTENT_W = Math.round(21 * CM) - (4 * CM) - (2 * CM);
const t = (x, o = {}) => new TextRun({ text: x, font: FONT, size: 24, ...o });
const p = (r, o = {}) => new Paragraph({ spacing: { line: 340, after: 110 }, alignment: AlignmentType.JUSTIFIED, children: Array.isArray(r) ? r : [r], ...o });
const h1 = (x) => new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 140 }, children: [new TextRun({ text: x, font: FONT, size: 28, bold: true })] });
const h2 = (x) => new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 200, after: 110 }, children: [new TextRun({ text: x, font: FONT, size: 23, bold: true })] });
function code(lines) { return lines.map((ln) => new Paragraph({ spacing: { line: 240, after: 0 }, shading: { type: ShadingType.CLEAR, fill: "F2F2F2", color: "auto" }, children: [new TextRun({ text: ln || " ", font: MONO, size: 18 })] })); }
const capn = (x) => new Paragraph({ spacing: { before: 20, after: 160 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: x, font: FONT, size: 20, italics: true })] });
function cl(x, { w, b = false } = {}) { return new TableCell({ width: { size: w, type: WidthType.DXA }, margins: { top: 50, bottom: 50, left: 80, right: 80 }, children: [new Paragraph({ spacing: { line: 250, after: 0 }, children: [new TextRun({ text: x, font: FONT, size: 18, bold: b })] })] }); }
function hrow(cs, ws) { return new TableRow({ tableHeader: true, children: cs.map((c, i) => new TableCell({ width: { size: ws[i], type: WidthType.DXA }, shading: { type: ShadingType.CLEAR, fill: "1F3864", color: "auto" }, margins: { top: 50, bottom: 50, left: 80, right: 80 }, children: [new Paragraph({ children: [new TextRun({ text: c, font: FONT, size: 18, bold: true, color: "FFFFFF" })] })] })) }); }
function tbl(ws, head, rows) { return new Table({ columnWidths: ws, width: { size: ws.reduce((a, b) => a + b, 0), type: WidthType.DXA }, borders: { top: { style: BorderStyle.SINGLE, size: 4, color: "999999" }, bottom: { style: BorderStyle.SINGLE, size: 4, color: "999999" }, left: { style: BorderStyle.SINGLE, size: 4, color: "999999" }, right: { style: BorderStyle.SINGLE, size: 4, color: "999999" }, insideHorizontal: { style: BorderStyle.SINGLE, size: 2, color: "CCCCCC" }, insideVertical: { style: BorderStyle.SINGLE, size: 2, color: "CCCCCC" } }, rows: [hrow(head, ws), ...rows.map((r) => new TableRow({ children: r.map((c, i) => cl(c, { w: ws[i] })) }))] }); }

const ch = [];
ch.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 }, children: [new TextRun({ text: "MANUAL DE USUARIO", font: FONT, size: 30, bold: true })] }));
ch.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 240 }, children: [new TextRun({ text: "pyscan — detección de paquetes maliciosos en PyPI", font: FONT, size: 24, bold: true })] }));

ch.push(h1("1. ¿Qué es pyscan?"));
ch.push(p(t("pyscan es una herramienta de línea de comandos que analiza paquetes de PyPI para determinar si son maliciosos. Combina tres análisis estáticos (similitud del nombre, entropía y recorrido del código) con un modelo de aprendizaje automático que emite el veredicto. No ejecuta el código del paquete en ningún momento. Su uso principal es revisar las dependencias de un proyecto antes de integrarlas.")));

ch.push(h1("2. Requisitos"));
ch.push(p(t("Python 3.10 o superior y acceso a internet para descargar los paquetes de PyPI. Para obtener el veredicto del modelo se requiere un modelo entrenado (archivo data/models/model.joblib); sin él, pyscan muestra igualmente las señales del análisis, pero sin veredicto.")));

ch.push(h1("3. Instalación"));
ch.push(...code([
  "python -m venv .venv",
  "# Windows:  .\\.venv\\Scripts\\Activate.ps1",
  "# Linux/Mac: source .venv/bin/activate",
  "pip install -e \".[dev,ml]\"",
]));
ch.push(p([t("En Windows, si el sistema bloquea el ejecutable, use siempre "), t("python -m pyscan.cli", { font: MONO }), t(" en lugar de "), t("pyscan", { font: MONO }), t(".")]));

ch.push(h1("4. Uso"));
ch.push(h2("4.1 Analizar las dependencias de un proyecto (uso principal)"));
ch.push(...code(["python -m pyscan.cli scan -r requirements.txt"]));
ch.push(p(t("Lee todas las dependencias del archivo y las analiza, con un resumen consolidado al final.")));
ch.push(h2("4.2 Analizar uno o varios paquetes"));
ch.push(...code(["python -m pyscan.cli scan requests", "python -m pyscan.cli scan requests flask numpy rich"]));
ch.push(h2("4.3 Analizar paquetes locales (sin descargar)"));
ch.push(...code(["python -m pyscan.cli scan --local ./paquete.tar.gz --local ./carpeta"]));
ch.push(h2("4.4 Otros comandos y opciones"));
ch.push(...code([
  "python -m pyscan.cli check-name reqursts     # solo el nombre (offline)",
  "python -m pyscan.cli info six                # metadatos del paquete",
  "python -m pyscan.cli scan requests --json    # salida en formato JSON",
  "python -m pyscan.cli scan -r reqs.txt --sarif salida.sarif   # reporte SARIF",
]));

ch.push(h1("5. Cómo interpretar los resultados"));
ch.push(p(t("Para cada paquete, pyscan muestra las señales detectadas y, si hay modelo, un veredicto. La Tabla 1 explica cada elemento.")));
ch.push(tbl([Math.round(CONTENT_W*0.28), Math.round(CONTENT_W*0.72)], ["Elemento", "Significado"], [
  ["typosquat", "Si el nombre se parece a un paquete popular (posible suplantación) y a cuál."],
  ["entropía", "Nivel de aleatoriedad del código; valores altos sugieren ofuscación/empaquetado."],
  ["AST", "Llamadas peligrosas detectadas en el código (eval, subprocess, base64, sockets…)."],
  ["ML", "Veredicto del modelo: MALICIOSO o benigno, con un puntaje de probabilidad."],
  ["RESUMEN", "Al analizar varios paquetes: cuántos y cuáles resultaron sospechosos."],
]));
ch.push(capn("Tabla 1. Elementos del reporte de pyscan."));
ch.push(p([t("Códigos de salida (útiles en integración continua): ", { bold: true }),
  t("0 = todo benigno · 1 = hubo errores · 2 = al menos un paquete MALICIOSO.")]));

ch.push(h1("6. Ejemplo de salida"));
ch.push(...code([
  "Paquete: reqursts 0.0.1",
  "  typosquat: SOSPECHOSO | distancia mínima=1 | parecido a 'requests'",
  "  entropía: max=7.8 | 12 ventanas altas",
  "  AST: 4 llamadas peligrosas -> exec, base64.b64decode, os.system",
  "       hook de instalación en setup.py",
  "  ML: MALICIOSO | score=0.96",
]));

ch.push(h1("7. Solución de problemas"));
ch.push(p([t("«Sin veredicto — no hay modelo entrenado»: ", { bold: true }), t("falta el archivo del modelo. Solicítelo al equipo o entrénelo (ver manual técnico). Aun así se muestran las señales.")]));
ch.push(p([t("Un paquete no se pudo analizar: ", { bold: true }), t("puede estar corrupto; pyscan lo omite con un aviso y continúa con los demás.")]));
ch.push(p([t("Error de red: ", { bold: true }), t("verifique la conexión; pyscan necesita descargar el paquete de PyPI (salvo el modo --local y check-name).")]));

const doc = new Document({ creator: "pyscan", styles: { default: { document: { run: { font: FONT, size: 24 } } } },
  sections: [{ properties: { page: { size: { width: Math.round(21 * CM), height: Math.round(29.7 * CM) }, margin: { top: 3 * CM, bottom: 3 * CM, left: 4 * CM, right: 2 * CM } } },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 20 })] })] }) },
    children: ch }] });
Packer.toBuffer(doc).then((b) => { fs.writeFileSync("/tmp/Manual_Usuario.docx", b); console.log("OK", b.length); });
