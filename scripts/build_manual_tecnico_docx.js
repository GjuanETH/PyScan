// Manual técnico de pyscan. NTC 1486.
const fs = require("fs");
const { Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType, PageNumber, Footer, ImageRun } = require("docx");
const FONT = "Arial", MONO = "Consolas", CM = 567;
const CONTENT_W = Math.round(21 * CM) - (4 * CM) - (2 * CM);
const IMG = "/tmp/cuerpo/img";
const t = (x, o = {}) => new TextRun({ text: x, font: FONT, size: 24, ...o });
const p = (r, o = {}) => new Paragraph({ spacing: { line: 340, after: 110 }, alignment: AlignmentType.JUSTIFIED, children: Array.isArray(r) ? r : [r], ...o });
const h1 = (x) => new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 140 }, children: [new TextRun({ text: x, font: FONT, size: 28, bold: true })] });
const h2 = (x) => new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 200, after: 110 }, children: [new TextRun({ text: x, font: FONT, size: 23, bold: true })] });
function code(lines) { return lines.map((ln) => new Paragraph({ spacing: { line: 240, after: 0 }, shading: { type: ShadingType.CLEAR, fill: "F2F2F2", color: "auto" }, children: [new TextRun({ text: ln || " ", font: MONO, size: 17 })] })); }
const capn = (x) => new Paragraph({ spacing: { before: 20, after: 160 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: x, font: FONT, size: 20, italics: true })] });
function figu(file, w, h, tw) { const s = tw / w; return new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 100, after: 60 }, children: [new ImageRun({ type: "png", data: fs.readFileSync(`${IMG}/${file}`), transformation: { width: Math.round(w * s), height: Math.round(h * s) } })] }); }
function cl(x, { w, b = false } = {}) { return new TableCell({ width: { size: w, type: WidthType.DXA }, margins: { top: 50, bottom: 50, left: 80, right: 80 }, children: [new Paragraph({ spacing: { line: 248, after: 0 }, children: [new TextRun({ text: x, font: FONT, size: 17, bold: b })] })] }); }
function hrow(cs, ws) { return new TableRow({ tableHeader: true, children: cs.map((c, i) => new TableCell({ width: { size: ws[i], type: WidthType.DXA }, shading: { type: ShadingType.CLEAR, fill: "1F3864", color: "auto" }, margins: { top: 50, bottom: 50, left: 80, right: 80 }, children: [new Paragraph({ children: [new TextRun({ text: c, font: FONT, size: 17, bold: true, color: "FFFFFF" })] })] })) }); }
function tbl(ws, head, rows) { return new Table({ columnWidths: ws, width: { size: ws.reduce((a, b) => a + b, 0), type: WidthType.DXA }, borders: { top: { style: BorderStyle.SINGLE, size: 4, color: "999999" }, bottom: { style: BorderStyle.SINGLE, size: 4, color: "999999" }, left: { style: BorderStyle.SINGLE, size: 4, color: "999999" }, right: { style: BorderStyle.SINGLE, size: 4, color: "999999" }, insideHorizontal: { style: BorderStyle.SINGLE, size: 2, color: "CCCCCC" }, insideVertical: { style: BorderStyle.SINGLE, size: 2, color: "CCCCCC" } }, rows: [hrow(head, ws), ...rows.map((r) => new TableRow({ children: r.map((c, i) => cl(c, { w: ws[i] })) }))] }); }

const ch = [];
ch.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 }, children: [new TextRun({ text: "MANUAL TÉCNICO", font: FONT, size: 30, bold: true })] }));
ch.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 220 }, children: [new TextRun({ text: "pyscan — arquitectura, operación y mantenimiento", font: FONT, size: 24, bold: true })] }));

ch.push(h1("1. Arquitectura"));
ch.push(p(t("pyscan es un monolito modular estructurado con el patrón Pipes and Filters: la salida de cada etapa alimenta a la siguiente mediante modelos tipados de Pydantic. Los tres extractores son filtros independientes. La Figura 1 muestra la estructura de componentes.")));
ch.push(figu("componentes.png", 1164, 858, 470));
ch.push(capn("Figura 1. Vista de componentes."));

ch.push(h1("2. Estructura del proyecto"));
ch.push(...code([
  "src/pyscan/",
  "  models.py        entidades Pydantic",
  "  config.py        umbrales, rutas y constantes",
  "  fetcher.py       descarga PyPI + extracción segura",
  "  extractors/      metadata.py, entropy.py, ast_extractor.py",
  "  features.py      construcción del vector de características",
  "  classifier.py    carga del modelo y veredicto",
  "  sarif.py         salida SARIF 2.1.0",
  "  cli.py           interfaz de línea de comandos",
  "tests/             pruebas pytest",
  "scripts/           dataset, entrenamiento, experimentos",
  "data/              dataset y modelo (no versionado el contenido pesado)",
]));

ch.push(h1("3. Módulos"));
ch.push(tbl([Math.round(CONTENT_W*0.28), Math.round(CONTENT_W*0.72)], ["Módulo", "Responsabilidad"], [
  ["fetcher.py", "Consulta la API de PyPI, descarga el sdist, verifica sha256 y extrae de forma segura (anti Zip-Slip, symlink y zip-bomb)."],
  ["extractors/metadata.py", "Typosquatting/combosquatting por distancia de Levenshtein."],
  ["extractors/entropy.py", "Entropía de Shannon por ventana de 256 bytes."],
  ["extractors/ast_extractor.py", "Recorrido AST: llamadas peligrosas, imports, literales de red y hooks; resistente a alias de import."],
  ["features.py", "Consolida los reportes en un vector de 9 características numéricas."],
  ["classifier.py", "Carga el modelo (joblib) y emite el veredicto con su puntaje."],
  ["sarif.py", "Genera el reporte en formato SARIF 2.1.0."],
  ["cli.py", "Orquesta el pipeline y expone los comandos."],
]));

ch.push(h1("4. Flujo de datos"));
ch.push(p(t("El flujo de un análisis es unidireccional (Figura 2): del nombre del paquete a la descarga y extracción segura, luego a los tres extractores, al vector de características y al veredicto del modelo, que se serializa como JSON o SARIF.")));
ch.push(figu("flujo.png", 1569, 317, 520));
ch.push(capn("Figura 2. Flujo de datos de un análisis."));

ch.push(h1("5. Modelo de Machine Learning"));
ch.push(p(t("El clasificador es supervisado y binario (benigno/malicioso). Opera sobre un vector de 9 características (nombre, entropía y AST). Se evalúan Random Forest y XGBoost, con manejo del desbalance mediante class_weight/scale_pos_weight y SMOTE aplicado solo dentro de cada partición de entrenamiento. El umbral de decisión se ajusta hacia el Recall y se valida en un hold-out. El artefacto model.joblib empaqueta el modelo, el orden de las características y el umbral.")));

ch.push(h1("6. Construcción del dataset y entrenamiento"));
ch.push(...code([
  "# 1) recolectar benignos y armar el dataset (ver docs/INSTRUCTIVO_DATASETS.md)",
  "python scripts/fetch_top_pypi.py --limit 5000",
  "python scripts/collect_benign.py --limit 2000",
  "python scripts/import_datadog.py --src <repo_datadog> --only-intent",
  "python scripts/build_dataset.py --max-malicious 2000 --ratio 2.0 --split 0.2 --seed 42",
  "# 2) entrenar",
  "python scripts/train_model.py --k 5 --target-recall 0.90 --holdout",
]));

ch.push(h1("7. Pruebas y calidad"));
ch.push(...code([
  "python -m pytest --cov=pyscan --cov-report=term-missing",
  "python scripts/benchmark_performance.py --packages requests flask numpy",
]));
ch.push(p(t("La suite consta de 58 pruebas con una cobertura del 91 %. El benchmark mide el tiempo y la memoria por paquete.")));

ch.push(h1("8. Mantenimiento y actualización"));
ch.push(p(t("Para mantener el detector vigente frente a nuevas campañas de malware se recomienda: (1) refrescar periódicamente la lista de referencia del Top de PyPI con fetch_top_pypi.py; (2) ampliar el dataset con nuevas muestras maliciosas (ver instructivo) y reentrenar el modelo con train_model.py; y (3) versionar el nuevo model.joblib y metrics.json. Como línea futura se plantea un comando pyscan update que automatice el refresco de la lista de referencia y el reentrenamiento.")));

ch.push(h1("9. Cómo extender el sistema"));
ch.push(p(t("Para añadir un nuevo extractor (por ejemplo, una nueva familia de señales): (1) crear el módulo en extractors/ que reciba la ruta extraída y devuelva un reporte tipado; (2) exponer su salida en features.py agregando las nuevas características al FeatureVector; (3) invocarlo en el motor de análisis del cli.py; y (4) agregar sus pruebas en tests/ y reentrenar el modelo para que incorpore las nuevas características. La independencia de los filtros permite hacerlo sin afectar a los demás módulos.")));

ch.push(h1("10. Dependencias"));
ch.push(p(t("Python 3.10+, Pydantic, Typer, RapidFuzz, scikit-learn, XGBoost, imbalanced-learn, joblib; pytest y pytest-cov para pruebas. Licencia MIT.")));

const doc = new Document({ creator: "pyscan", styles: { default: { document: { run: { font: FONT, size: 24 } } } },
  sections: [{ properties: { page: { size: { width: Math.round(21 * CM), height: Math.round(29.7 * CM) }, margin: { top: 3 * CM, bottom: 3 * CM, left: 4 * CM, right: 2 * CM } } },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 20 })] })] }) },
    children: ch }] });
Packer.toBuffer(doc).then((b) => { fs.writeFileSync("/tmp/Manual_Tecnico.docx", b); console.log("OK", b.length); });
