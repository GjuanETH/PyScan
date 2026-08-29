// Objetivo 2 — Diseño de la arquitectura del MVP y del modelo de ML. NTC 1486.
const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType, PageNumber, Footer,
  ImageRun,
} = require("docx");

const FONT = "Arial";
const CM = 567;
const CONTENT_W = Math.round(21 * CM) - (4 * CM) - (2 * CM);
const DIR = "/tmp/obj2/diagrams";

const t = (text, opts = {}) => new TextRun({ text, font: FONT, size: 24, ...opts });
const p = (runs, opts = {}) =>
  new Paragraph({
    spacing: { line: 360, after: 120 }, alignment: AlignmentType.JUSTIFIED,
    children: Array.isArray(runs) ? runs : [runs], ...opts,
  });
const h1 = (text) => new Paragraph({
  heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 160 },
  children: [new TextRun({ text, font: FONT, size: 28, bold: true })],
});
const h2 = (text) => new Paragraph({
  heading: HeadingLevel.HEADING_2, spacing: { before: 200, after: 120 },
  children: [new TextRun({ text, font: FONT, size: 24, bold: true })],
});

// Imagen centrada, escalada a un ancho objetivo en px (96 dpi).
function figure(file, wpx, hpx, targetW) {
  const scale = targetW / wpx;
  return new Paragraph({
    alignment: AlignmentType.CENTER, spacing: { before: 120, after: 60 },
    children: [new ImageRun({
      type: "png",
      data: fs.readFileSync(`${DIR}/${file}`),
      transformation: { width: Math.round(wpx * scale), height: Math.round(hpx * scale) },
    })],
  });
}
const caption = (text) => new Paragraph({
  spacing: { before: 20, after: 180 }, alignment: AlignmentType.CENTER,
  children: [new TextRun({ text, font: FONT, size: 20, italics: true })],
});

function cell(text, { w, bold = false, align = AlignmentType.LEFT } = {}) {
  return new TableCell({
    width: { size: w, type: WidthType.DXA },
    margins: { top: 60, bottom: 60, left: 90, right: 90 },
    children: [new Paragraph({ alignment: align, spacing: { line: 276, after: 0 },
      children: [new TextRun({ text, font: FONT, size: 20, bold })] })],
  });
}
function headerRow(cells, widths) {
  return new TableRow({ tableHeader: true, children: cells.map((c, i) => new TableCell({
    width: { size: widths[i], type: WidthType.DXA },
    shading: { type: ShadingType.CLEAR, fill: "1F3864", color: "auto" },
    margins: { top: 60, bottom: 60, left: 90, right: 90 },
    children: [new Paragraph({ alignment: AlignmentType.CENTER, spacing: { line: 276, after: 0 },
      children: [new TextRun({ text: c, font: FONT, size: 20, bold: true, color: "FFFFFF" })] })],
  })) });
}
function makeTable(widths, header, rows, rowOpts = []) {
  return new Table({
    columnWidths: widths,
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
      ...rows.map((r) => new TableRow({ children: r.map((c, i) => cell(c, { w: widths[i], ...(rowOpts[i] || {}) })) }))],
  });
}

const children = [];

// Portada
children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 80 },
  children: [new TextRun({ text: "OBJETIVO ESPECÍFICO 2", font: FONT, size: 28, bold: true })] }));
children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 240 },
  children: [new TextRun({ text: "Diseño de la arquitectura tecnológica del MVP y del modelo de Machine Learning",
    font: FONT, size: 24, bold: true })] }));
children.push(p([t("Objetivo: ", { bold: true }),
  t("Diseñar la arquitectura tecnológica del Producto Mínimo Viable (MVP) y del modelo de Machine Learning, a partir del análisis de los requerimientos especificados, para estructurar lógicamente el sistema de detección de paquetes maliciosos.", { italics: true })]));

// 1. Introducción
children.push(h1("1. Enfoque del diseño"));
children.push(p(t("El diseño arquitectónico traduce los requerimientos del Objetivo 1 en una estructura lógica de componentes, flujos y decisiones tecnológicas. Cada decisión de diseño se justifica con referencia a un requerimiento funcional (RF) o no funcional (RNF) y a una característica del modelo de calidad ISO/IEC 25010:2023. La arquitectura se presenta mediante vistas complementarias: la vista de componentes describe la estructura estática del sistema; la vista de flujo de datos, su comportamiento dinámico durante un análisis; el modelo de dominio, las entidades que viajan entre módulos; y la arquitectura del modelo de Machine Learning, el diseño del componente de decisión y de su proceso de entrenamiento.")));

// 2. Estilo arquitectónico
children.push(h1("2. Estilo arquitectónico"));
children.push(p([
  t("El MVP adopta un "),
  t("monolito modular estructurado con el patrón Pipes and Filters", { bold: true }),
  t(". El sistema se organiza como una tubería en la que la salida de cada etapa (filtro) alimenta a la siguiente, comunicándose mediante estructuras de datos tipadas. Los tres extractores —metadatos, entropía y AST— son filtros independientes que no se conocen entre sí: reciben una entrada y devuelven un reporte, sin efectos colaterales sobre el resto del sistema."),
]));
children.push(p([
  t("Esta elección responde directamente a los requerimientos de mantenibilidad (RNF10–RNF12): la independencia de los filtros permite agregar, reemplazar o probar cada extractor en aislamiento (modularidad y capacidad de prueba), y las interfaces tipadas con Pydantic hacen explícito el contrato entre etapas (modificabilidad). Un monolito —frente a microservicios— es apropiado para un MVP de línea de comandos: reduce la complejidad operativa y de despliegue sin sacrificar la separación lógica de responsabilidades."),
]));

// 3. Vista de componentes
children.push(h1("3. Vista de componentes"));
children.push(p(t("La Figura 1 muestra la estructura estática del MVP. La interfaz de línea de comandos (Typer) orquesta el flujo; el Fetcher seguro descarga el paquete de PyPI y lo extrae con protección contra Zip-Slip y zip-bombs; los tres extractores producen reportes tipados; el Feature Builder los consolida en un FeatureVector; y el clasificador emite el veredicto, que se serializa como reporte JSON o SARIF. Los módulos transversales config.py (umbrales y rutas) y models.py (entidades) sostienen a todo el sistema.")));
children.push(figure("componentes.png", 1164, 858, 520));
children.push(caption("Figura 1. Vista de componentes del MVP (patrón Pipes and Filters)."));
children.push(p([
  t("La correspondencia entre componentes y requerimientos es directa: el Fetcher implementa RF01 y los RNF de fiabilidad y capacidad (RNF06–RNF07); los extractores implementan RF02–RF08 (un extractor por familia de vectores); el Feature Builder y el clasificador implementan RF09; y el serializador de reportes implementa RF10. El comando "),
  t("check-name", { italics: true }),
  t(" (RF11) reutiliza el extractor de metadatos sin invocar al Fetcher, habilitando el análisis offline."),
]));

// 4. Vista de flujo de datos
children.push(h1("4. Vista de flujo de datos"));
children.push(p(t("La Figura 2 describe el comportamiento dinámico durante un análisis. A partir del nombre del paquete, el Fetcher obtiene el sdist, verifica su integridad por sha256 y lo extrae de forma segura. El contenido extraído alimenta en paralelo a los tres extractores, cuyos reportes se consolidan en un FeatureVector de catorce características numéricas. El clasificador transforma ese vector en una predicción (score y veredicto), y el sistema emite el ScanReport final. El flujo es unidireccional y sin estado compartido, coherente con el estilo Pipes and Filters.")));
children.push(figure("flujo.png", 1569, 317, 540));
children.push(caption("Figura 2. Vista de flujo de datos de un análisis (scan)."));

// 5. Modelo de dominio
children.push(h1("5. Modelo de dominio"));
children.push(p(t("Las interfaces entre módulos se definen con modelos tipados de Pydantic, lo que valida los datos que viajan por la tubería y permite probar cada módulo en aislamiento (RNF11, RNF12). La Figura 3 presenta las entidades principales. ScanReport actúa como agregador del resultado: contiene el paquete, sus metadatos y los reportes de cada extractor, el vector de características y la predicción del modelo, además de una lista de errores para la degradación elegante.")));
children.push(figure("dominio.png", 898, 956, 430));
children.push(caption("Figura 3. Modelo de dominio (entidades Pydantic)."));

// 6. Arquitectura del modelo de ML
children.push(h1("6. Arquitectura del modelo de Machine Learning"));
children.push(p(t("El componente de decisión es un clasificador supervisado binario (benigno/malicioso). Su diseño abarca la ingeniería de características, la elección del algoritmo y el proceso de entrenamiento y evaluación, todos condicionados por dos hechos del dominio: el fuerte desbalance de clases (el malware es minoritario) y la prioridad del Recall (no dejar pasar paquetes maliciosos), conforme al RNF02.")));

children.push(h2("6.1 Ingeniería de características"));
children.push(p(t("Los tres extractores producen un vector de catorce características numéricas que resume las señales de los vectores de ataque: distancia mínima de nombre e indicadores de typosquatting/combosquatting; conteos de releases, dependencias y presencia de descripción; estadísticos de entropía; y conteos de llamadas peligrosas, literales de red y hook de instalación. Al operar sobre un vector numérico compacto —y no sobre el código crudo— el clasificador es rápido y liviano, apoyando los RNF de eficiencia (RNF04, RNF05).")));

children.push(h2("6.2 Algoritmos y manejo del desbalance"));
children.push(p([
  t("Se evalúan dos algoritmos de ensamble basados en árboles, robustos frente a características heterogéneas y de rápida inferencia: "),
  t("Random Forest", { bold: true }),
  t(" (con class_weight=\"balanced\") y "),
  t("XGBoost", { bold: true }),
  t(" (con scale_pos_weight). Ambos incorporan el desbalance en su función de costo. Adicionalmente se aplica SMOTE para sintetizar ejemplos de la clase minoritaria, pero "),
  t("únicamente dentro de cada partición de entrenamiento", { bold: true }),
  t(", nunca sobre los datos de validación, evitando la fuga de información."),
]));

children.push(h2("6.3 Pipeline de entrenamiento y evaluación"));
children.push(p(t("La Figura 4 resume el proceso. Sobre el dataset etiquetado y deduplicado por sha256, se extraen las características (con caché por hash para no repetir trabajo). Se emplea validación cruzada estratificada de cinco particiones que produce predicciones out-of-fold; sobre ellas se ajusta el umbral de decisión maximizando el F1 sujeto a un Recall mínimo de 0,90. Se selecciona el mejor algoritmo, se reentrena con todo el conjunto y se evalúa una sola vez en un hold-out con el umbral ya fijado, obteniendo una estimación honesta del desempeño. El artefacto resultante (model.joblib) empaqueta el modelo, el orden de las características y el umbral, junto a un informe de métricas.")));
children.push(figure("ml_pipeline.png", 406, 1462, 250));
children.push(caption("Figura 4. Arquitectura del pipeline de entrenamiento y evaluación del modelo."));

// 7. Stack tecnológico
children.push(h1("7. Stack tecnológico"));
children.push(p(t("La Tabla 1 justifica cada tecnología en función de los requerimientos que soporta.")));
{
  const w = [Math.round(CONTENT_W*0.24), Math.round(CONTENT_W*0.50), Math.round(CONTENT_W*0.26)];
  const rows = [
    ["Python 3.10+", "Lenguaje del ecosistema PyPI; librería estándar ast para análisis estático sin ejecutar código.", "RF04, RF05"],
    ["Pydantic", "Modelos tipados que validan las interfaces entre filtros y habilitan pruebas en aislamiento.", "RNF10–RNF12"],
    ["Typer", "Construcción de la CLI con subcomandos y códigos de salida aptos para CI.", "RF10, RF11"],
    ["RapidFuzz", "Distancia de Levenshtein optimizada en C++ para el análisis de typosquatting.", "RF02"],
    ["scikit-learn / XGBoost", "Clasificadores de ensamble con soporte de desbalance; validación cruzada y métricas.", "RF09, RNF02"],
    ["imbalanced-learn", "SMOTE para el tratamiento del desbalance dentro del pipeline de entrenamiento.", "RNF02"],
    ["Formato SARIF 2.1.0", "Estándar de resultados de análisis estático, integrable en pipelines de CI/CD.", "RF10"],
  ];
  children.push(makeTable(w, ["Tecnología", "Justificación", "Requerimientos"], rows,
    [{ bold: true }, {}, { align: AlignmentType.CENTER }]));
  children.push(caption("Tabla 1. Stack tecnológico y su trazabilidad a los requerimientos."));
}

// 8. Trazabilidad diseño-requerimientos
children.push(h1("8. Trazabilidad diseño ↔ requerimientos"));
children.push(p(t("La Tabla 2 verifica que cada decisión arquitectónica responde a requerimientos concretos del Objetivo 1, cerrando la cadena requerimiento → diseño.")));
{
  const w = [Math.round(CONTENT_W*0.34), Math.round(CONTENT_W*0.40), Math.round(CONTENT_W*0.26)];
  const rows = [
    ["Pipes and Filters / monolito modular", "Extractores independientes e intercambiables; contratos tipados", "RNF10, RNF11, RNF12"],
    ["Fetcher seguro", "Descarga verificada + extracción defensiva", "RF01, RNF06, RNF07"],
    ["Extractores (3)", "Un filtro por familia de vectores de ataque", "RF02–RF08"],
    ["Feature Builder + Classifier", "Consolidación y veredicto por ML", "RF09, RNF02, RNF03"],
    ["Serializador de reportes", "Salida JSON y SARIF con exit codes", "RF10, RNF09"],
    ["Vector de características compacto", "Inferencia rápida y de bajo consumo", "RNF04, RNF05"],
  ];
  children.push(makeTable(w, ["Decisión de diseño", "Cómo estructura el sistema", "Requerimientos"], rows,
    [{ bold: true }, {}, { align: AlignmentType.CENTER }]));
  children.push(caption("Tabla 2. Trazabilidad entre decisiones de diseño y requerimientos."));
}

// 9. Conclusión
children.push(h1("9. Conclusión del objetivo"));
children.push(p(t("El diseño propuesto estructura lógicamente el sistema de detección en componentes de responsabilidad única, articulados por un flujo de datos unidireccional y tipado, con un componente de decisión basado en Machine Learning cuyo pipeline de entrenamiento controla explícitamente el desbalance de clases y la fuga de datos. Cada decisión arquitectónica y tecnológica queda trazada a los requerimientos funcionales y no funcionales del Objetivo 1 y, a través de ellos, a las características de calidad de ISO/IEC 25010:2023. Con ello se cumple el segundo objetivo específico y se dispone de una arquitectura verificable que guía la implementación abordada en los objetivos siguientes.")));

// Referencias
children.push(h1("Referencias"));
const refs = [
  "[1] ISO/IEC 25010:2023, Systems and software engineering — Systems and software Quality Requirements and Evaluation (SQuaRE) — Product quality model. Ginebra: ISO, 2023.",
  "[2] M. Shaw y D. Garlan, Software Architecture: Perspectives on an Emerging Discipline. Prentice Hall, 1996.",
  "[3] N. V. Chawla, K. W. Bowyer, L. O. Hall y W. P. Kegelmeyer, “SMOTE: Synthetic Minority Over-sampling Technique,” Journal of Artificial Intelligence Research, vol. 16, pp. 321–357, 2002.",
  "[4] T. Chen y C. Guestrin, “XGBoost: A Scalable Tree Boosting System,” en Proc. 22nd ACM SIGKDD, 2016.",
];
refs.forEach((r) => children.push(new Paragraph({
  spacing: { line: 300, after: 120 }, alignment: AlignmentType.JUSTIFIED,
  indent: { left: 340, hanging: 340 },
  children: [new TextRun({ text: r, font: FONT, size: 22 })],
})));

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
      children: [new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 20 })],
    })] }) },
    children,
  }],
});

Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync("/tmp/Objetivo2_Arquitectura.docx", buf);
  console.log("DOCX escrito:", buf.length, "bytes");
});
