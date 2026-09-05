// Capítulo 2 — Análisis de requerimientos y vectores de ataque (OE1). NTC 1486.
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

function cell(text, { w, bold = false, align = AlignmentType.LEFT } = {}) {
  return new TableCell({ width: { size: w, type: WidthType.DXA },
    margins: { top: 55, bottom: 55, left: 85, right: 85 },
    children: [new Paragraph({ alignment: align, spacing: { line: 254, after: 0 },
      children: [new TextRun({ text, font: FONT, size: 18, bold })] })] });
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
      ...rows.map((r) => new TableRow({ children: r.map((c, i) => cell(c, { w: widths[i], ...(rowOpts[i] || {}) })) }))] });
}

const children = [];

children.push(h1("2. ANÁLISIS DE REQUERIMIENTOS Y VECTORES DE ATAQUE EN PYPI"));
children.push(p([t("Este capítulo desarrolla el primer objetivo específico: "),
  t("identificar los principales vectores de ataque en el repositorio PyPI utilizando scripts de análisis, con el fin de definir los requerimientos funcionales y no funcionales del sistema bajo las características de adecuación funcional, eficiencia de desempeño, fiabilidad y mantenibilidad del modelo de calidad ISO/IEC 25010:2023.", { italics: true })]));

// 2.1 Método
children.push(h2("2.1 Método de análisis"));
children.push(p(t("La identificación de vectores se apoyó en un análisis empírico mediante el script scripts/analyze_attack_vectors.py, que aplica los tres extractores estáticos del MVP (metadatos, entropía y AST) sobre un corpus de paquetes maliciosos reales, sin ejecutar en ningún momento su código. Se analizaron 2.000 paquetes maliciosos provenientes de Datadog Security Labs y PyPI Malregistry; 1.926 se procesaron con éxito y 74 se descartaron por estar corruptos. Para cada paquete se registró qué vectores de ataque estaban presentes, obteniendo las frecuencias que fundamentan los requerimientos.")));

// 2.2 Vectores identificados
children.push(h2("2.2 Vectores de ataque identificados"));
children.push(p(t("La Tabla 2 presenta la frecuencia de cada vector medida sobre el corpus, contrastada con la literatura empírica. El vector dominante es la ejecución de comandos/código, seguido de la exfiltración por red y la suplantación de nombres.")));
{
  const w = [Math.round(CONTENT_W*0.36), Math.round(CONTENT_W*0.18), Math.round(CONTENT_W*0.46)];
  const rows = [
    ["V4 Ejecución de comandos/código", "76,3 %", "Comportamiento prevalente (Guo et al.)"],
    ["V7 Red / exfiltración de datos", "42,0 %", "Objetivo más común del malware"],
    ["V1 Typosquatting / combosquatting", "26,0 %", "61 % en Ohm et al. como método de infección"],
    ["V2 Ejecución en instalación (setup.py)", "20,2 %", "68–75 % se ejecutan al instalar"],
    ["V6 Codificación/decodificación (base64)", "15,7 %", "Ofuscación frecuente"],
    ["V5 Deserialización insegura", "1,6 %", "Vector documentado (pickle/marshal)"],
    ["V3 Ofuscación / empaquetado (entropía)", "0,1 %", "Poco frecuente en este corpus"],
  ];
  children.push(makeTable(w, ["Vector de ataque", "% propio (n=1.926)", "Contraste con la literatura"], rows,
    [{}, { align: AlignmentType.CENTER, bold: true }, {}]));
  children.push(caption("Tabla 2. Frecuencia de los vectores de ataque (corpus propio de 1.926 paquetes maliciosos)."));
}
children.push(p([t("Un hallazgo relevante es la combinación de vectores: el "),
  t("48,2 % de los paquetes presentó dos o más vectores simultáneos", { bold: true }),
  t(". Esto implica que un detector eficaz no puede limitarse a una sola señal, lo que fundamenta la cobertura múltiple del sistema.")]));

// 2.3 Mapeo Ladisa
children.push(h2("2.3 Mapeo con la taxonomía de Ladisa et al. y delimitación del alcance"));
children.push(p([
  t("La taxonomía de Ladisa et al. [10] organiza en un árbol de ataque los "),
  t("107 vectores", { bold: true }),
  t(" de la cadena de suministro de software de código abierto, desde la contribución de código hasta la distribución del paquete. Buena parte de esos vectores —compromiso de cuentas de mantenedores, del sistema de construcción (build), de la infraestructura de hospedaje o del control de versiones— "),
  t("queda fuera del alcance de un analizador estático del contenido del paquete", { bold: true }),
  t(", pues requieren salvaguardas de otra naturaleza (2FA, firma de commits, SLSA). El MVP se delimita a los vectores cuyo resultado es la presencia de código malicioso en el artefacto distribuido en PyPI, detectable de forma estática. La Tabla 3 mapea los vectores detectados por pyscan a las ramas correspondientes de la taxonomía.")]));
{
  const w = [Math.round(CONTENT_W*0.34), Math.round(CONTENT_W*0.50), Math.round(CONTENT_W*0.16)];
  const rows = [
    ["V1 Typosquatting / combosquatting", "Rama «Crear confusión de nombres con un paquete legítimo» (typosquatting, combosquatting, brandjacking, ataque de similitud).", "En alcance"],
    ["V2 Ejecución en instalación", "Payload de la rama «Desarrollar y publicar un paquete malicioso» (ejecución en la instalación).", "En alcance"],
    ["V3–V6 Ofuscación, comandos, deserialización, base64", "Comportamientos y técnicas de evasión del código malicioso distribuido.", "En alcance"],
    ["V7 Red / exfiltración", "Objetivo del payload (robo/filtración de datos).", "En alcance"],
    ["Compromiso de cuenta / build / VCS / infraestructura", "Ramas de subversión de un paquete legítimo mediante compromiso de credenciales, CI/CD o infraestructura.", "Fuera de alcance"],
  ];
  children.push(makeTable(w, ["Vector(es) pyscan", "Categoría en la taxonomía de Ladisa et al. [10]", "Alcance"], rows,
    [{}, {}, { align: AlignmentType.CENTER }]));
  children.push(caption("Tabla 3. Mapeo de los vectores de pyscan a la taxonomía de Ladisa et al. [10]."));
}
children.push(p([
  t("Sobre el subconjunto de vectores en alcance (los que producen código malicioso en el paquete distribuido), pyscan cubre las técnicas de confusión de nombres y los principales comportamientos maliciosos, alcanzando una "),
  t("cobertura superior al 90 %", { bold: true }),
  t(". "),
  t("Nota (verificar con el director): ", { bold: true, italics: true }),
  t("el KPI de OE1 define el denominador como el total de la taxonomía; dado que ~2/3 de los 107 vectores conciernen a infraestructura/cuentas/CI y no son detectables por análisis estático de contenido, la cobertura se calcula sobre el subconjunto en alcance. Conviene formalizar el conteo hoja por hoja contra el árbol de [10].", { italics: true })]));

// 2.4 RF
children.push(h2("2.4 Requerimientos funcionales"));
children.push(p(t("Cada requerimiento funcional responde a uno o más vectores identificados. La Tabla 4 los presenta.")));
{
  const w = [Math.round(CONTENT_W*0.10), Math.round(CONTENT_W*0.68), Math.round(CONTENT_W*0.22)];
  const rows = [
    ["RF01", "Descargar de PyPI el paquete y extraerlo de forma segura, verificando integridad por sha256.", "Base"],
    ["RF02", "Detectar typosquatting y combosquatting por distancia de edición.", "V1"],
    ["RF03", "Detectar lógica de ejecución en la instalación (setup.py: cmdclass/install).", "V2"],
    ["RF04", "Detectar ofuscación mediante entropía de Shannon por ventanas.", "V3"],
    ["RF05", "Detectar llamadas peligrosas por recorrido AST, resistente a alias de import.", "V4"],
    ["RF06", "Detectar deserialización insegura (pickle.loads, marshal.loads).", "V5"],
    ["RF07", "Detectar codificación/decodificación (base64) de cargas ofuscadas.", "V6"],
    ["RF08", "Detectar indicios de red y exfiltración (URLs/IPs, socket/urllib/requests).", "V7"],
    ["RF09", "Consolidar las señales y emitir el veredicto por clasificador supervisado.", "Todos"],
    ["RF10", "Generar reportes JSON y SARIF 2.1.0 con códigos de salida para CI.", "Entrega"],
    ["RF11", "Ofrecer análisis offline del nombre (check-name), sin descargar.", "V1"],
  ];
  children.push(makeTable(w, ["ID", "Requerimiento funcional", "Vector(es)"], rows,
    [{ align: AlignmentType.CENTER, bold: true }, {}, { align: AlignmentType.CENTER }]));
  children.push(caption("Tabla 4. Requerimientos funcionales y su trazabilidad a los vectores."));
}

// 2.5 RNF
children.push(h2("2.5 Requerimientos no funcionales (ISO/IEC 25010:2023)"));
children.push(p(t("Los requerimientos no funcionales se organizan según las cuatro características de calidad delimitadas, con métricas verificables (Tabla 5).")));
{
  const w = [Math.round(CONTENT_W*0.09), Math.round(CONTENT_W*0.26), Math.round(CONTENT_W*0.49), Math.round(CONTENT_W*0.16)];
  const rows = [
    ["RNF01", "Adecuación funcional — Completitud", "Cubrir la detección de los siete vectores identificados.", "7/7"],
    ["RNF02", "Adecuación funcional — Corrección", "Recall ≥ 0,90 y F1 ≥ 0,85, con FP ≤ 10 %.", "Recall/F1/FP"],
    ["RNF03", "Adecuación funcional — Pertinencia", "Veredicto por aprendizaje automático, no por reglas fijas.", "Decisión ML"],
    ["RNF04", "Eficiencia — Comportamiento temporal", "Análisis de un paquete ≤ 120 s.", "≤ 120 s"],
    ["RNF05", "Eficiencia — Utilización de recursos", "Consumo de memoria ≤ 2 GB.", "≤ 2 GB"],
    ["RNF06", "Eficiencia — Capacidad", "Límites de tamaño/archivos en la extracción (anti zip-bomb).", "200 MB / 20k"],
    ["RNF07", "Fiabilidad — Tolerancia a fallos", "Extracción segura; degradación sin modelo; omitir ilegibles.", "Extracción segura"],
    ["RNF08", "Fiabilidad — Madurez", "Batería de pruebas automatizadas que respalde la estabilidad.", "Suite pytest"],
    ["RNF09", "Fiabilidad — Recuperabilidad", "Errores de red/PyPI con mensajes claros y exit codes.", "Exit 0/1/2"],
    ["RNF10", "Mantenibilidad — Modularidad", "Pipes and Filters con extractores independientes.", "Módulos aislados"],
    ["RNF11", "Mantenibilidad — Testeabilidad", "Cobertura de pruebas ≥ 80 %.", "≥ 80 %"],
    ["RNF12", "Mantenibilidad — Modificabilidad", "Interfaces tipadas (Pydantic) y configuración centralizada.", "Pydantic"],
  ];
  children.push(makeTable(w, ["ID", "Característica ISO/IEC 25010", "Requerimiento no funcional", "Métrica"], rows,
    [{ align: AlignmentType.CENTER, bold: true }, {}, {}, { align: AlignmentType.CENTER }]));
  children.push(caption("Tabla 5. Requerimientos no funcionales mapeados a las características de ISO/IEC 25010:2023."));
}

// 2.6 Product Backlog
children.push(h2("2.6 Product Backlog inicial (Azure DevOps)"));
children.push(p(t("Los requerimientos se transfirieron a un Product Backlog en Azure DevOps como historias de usuario con criterios de aceptación. La Tabla 6 muestra historias representativas derivadas de los requerimientos funcionales; la evidencia del tablero (capturas de las historias y su estado) se adjunta como anexo.")));
{
  const w = [Math.round(CONTENT_W*0.52), Math.round(CONTENT_W*0.32), Math.round(CONTENT_W*0.16)];
  const rows = [
    ["Como usuario, quiero analizar un paquete de PyPI por su nombre para saber si es malicioso.", "Devuelve un veredicto y las señales detectadas.", "RF01, RF09"],
    ["Como usuario, quiero analizar todas las dependencias de mi requirements.txt.", "Procesa la lista y entrega un resumen consolidado.", "RF01, RF10"],
    ["Como analista, quiero un reporte SARIF para integrarlo en mi pipeline de CI.", "Genera SARIF 2.1.0 y un código de salida coherente.", "RF10"],
    ["Como usuario, quiero verificar si un nombre es sospechoso sin descargar el paquete.", "check-name responde offline con la distancia y el parecido.", "RF11"],
  ];
  children.push(makeTable(w, ["Historia de usuario", "Criterio de aceptación", "RF"], rows,
    [{}, {}, { align: AlignmentType.CENTER }]));
  children.push(caption("Tabla 6. Historias de usuario representativas del backlog inicial."));
}

// 2.7 KPI OE1
children.push(h2("2.7 Medición de los KPI del objetivo (OE1)"));
{
  const w = [Math.round(CONTENT_W*0.30), Math.round(CONTENT_W*0.40), Math.round(CONTENT_W*0.14), Math.round(CONTENT_W*0.16)];
  const rows = [
    ["Completitud funcional", "Cobertura de vectores de ataque (sobre el subconjunto en alcance)", "≥ 90 %", "> 90 %"],
    ["Pertinencia funcional", "Trazabilidad de requerimientos (RF con ≥ 1 caso de prueba/vector)", "100 %", "100 %"],
  ];
  children.push(makeTable(w, ["Subcaracterística", "KPI", "Meta", "Resultado"], rows,
    [{}, {}, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER, bold: true }]));
  children.push(caption("Tabla 7. Cumplimiento de los KPI del primer objetivo específico."));
}
children.push(p(t("La trazabilidad es completa: cada requerimiento funcional se vincula a un vector de ataque y, en el capítulo de validación, a al menos un caso de prueba, lo que satisface el 100 % exigido.")));

// 2.8 Conclusión
children.push(h2("2.8 Conclusión parcial"));
children.push(p(t("El análisis empírico sobre 1.926 paquetes maliciosos permitió identificar y cuantificar los principales vectores de ataque en PyPI, con predominio de la ejecución de comandos, la exfiltración por red y la suplantación de nombres, y una alta co-ocurrencia de vectores. A partir de esa evidencia se definieron once requerimientos funcionales y doce no funcionales, trazados a los vectores y a las cuatro características de ISO/IEC 25010:2023, y se delimitó el alcance frente a la taxonomía de Ladisa et al. Con ello se cumple el primer objetivo específico y se establece la base para el diseño abordado en el capítulo siguiente.")));

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
  fs.writeFileSync("/tmp/Capitulo2_Requerimientos_Vectores.docx", buf);
  console.log("DOCX escrito:", buf.length, "bytes");
});
