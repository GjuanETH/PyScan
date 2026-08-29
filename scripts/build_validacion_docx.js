// Validación externa — señales de pyscan frente al estado del arte. NTC 1486.
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
  children: Array.isArray(runs) ? runs : [runs], ...opts,
});
const h1 = (text) => new Paragraph({
  heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 160 },
  children: [new TextRun({ text, font: FONT, size: 28, bold: true })],
});
const caption = (text) => new Paragraph({ spacing: { before: 20, after: 180 }, alignment: AlignmentType.CENTER,
  children: [new TextRun({ text, font: FONT, size: 20, italics: true })] });

function cell(text, { w, bold = false, align = AlignmentType.LEFT, size = 19 } = {}) {
  return new TableCell({ width: { size: w, type: WidthType.DXA },
    margins: { top: 55, bottom: 55, left: 85, right: 85 },
    children: [new Paragraph({ alignment: align, spacing: { line: 258, after: 0 },
      children: [new TextRun({ text, font: FONT, size, bold })] })] });
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
  children: [new TextRun({ text: "VALIDACIÓN EXTERNA", font: FONT, size: 28, bold: true })] }));
children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 240 },
  children: [new TextRun({ text: "Las señales detectadas por pyscan frente al estado del arte: herramientas y estándares de la industria",
    font: FONT, size: 24, bold: true })] }));
children.push(p(t("Este documento complementa el Objetivo 1. Contrasta las señales de código que pyscan detecta con más frecuencia en paquetes maliciosos —obtenidas empíricamente en el análisis de vectores— con las herramientas de seguridad y los catálogos de referencia que la industria y la academia ya reconocen como indicadores de código malicioso. El propósito es aportar validez externa: demostrar que las señales del sistema no son arbitrarias, sino coincidentes con el estado del arte.")));

// 1. Motivación
children.push(h1("1. Motivación"));
children.push(p(t("El análisis del Objetivo 1 identificó, sobre 1.926 paquetes maliciosos reales, las llamadas de código más frecuentes: subprocess.Popen, exec, base64.b64decode, requests.get, os.system, urllib.request.urlopen, entre otras. Una pregunta legítima de un revisor es si esas señales son realmente relevantes o simple ruido. Para responderla, se contrastan con tres tipos de fuentes reconocidas: (i) herramientas de análisis estático de seguridad para Python (Bandit); (ii) detectores de paquetes maliciosos de la industria (GuardDog, de Datadog); y (iii) catálogos internacionales de debilidades y técnicas de adversario (CWE de MITRE y MITRE ATT&CK).")));

// 2. Mapeo
children.push(h1("2. Mapeo de señales a herramientas y estándares"));
children.push(p(t("La Tabla 1 relaciona cada señal detectada por pyscan con la capacidad ofensiva que habilita, la herramienta que la vigila y el estándar internacional que la clasifica. La coincidencia es sistemática: cada señal frecuente corresponde a un indicador ya catalogado.")));
{
  const w = [Math.round(CONTENT_W*0.24), Math.round(CONTENT_W*0.24), Math.round(CONTENT_W*0.28), Math.round(CONTENT_W*0.24)];
  const rows = [
    ["subprocess.Popen/run/call, os.system, os.popen", "Ejecución de comandos del sistema", "Bandit B602–B607; GuardDog", "CWE-78; ATT&CK T1059"],
    ["exec, eval, compile, __import__", "Ejecución dinámica de código", "Bandit B102, B307; GuardDog (exec-base64)", "CWE-94, CWE-95"],
    ["base64.b64decode / b64encode", "Ofuscación de la carga maliciosa", "GuardDog (exec-base64, Semgrep taint)", "ATT&CK T1027"],
    ["pickle.loads, marshal.loads", "Deserialización insegura (RCE)", "Bandit B301, B302", "CWE-502"],
    ["requests.get, urllib.request.urlopen, socket.socket", "Conexión a red / exfiltración", "GuardDog (taint de exfiltración)", "ATT&CK T1041 / T1567"],
    ["Hook en setup.py (install/cmdclass)", "Ejecución en la instalación", "GuardDog (command overwrite)", "ATT&CK T1195.002"],
  ];
  children.push(makeTable(w, ["Señal (pyscan)", "Capacidad ofensiva", "Herramienta que la vigila", "Estándar"], rows,
    [{}, {}, {}, {}]));
  children.push(caption("Tabla 1. Correspondencia entre las señales de pyscan y el estado del arte."));
}
children.push(p([
  t("El hallazgo más significativo es que "),
  t("GuardDog —la herramienta de código abierto de Datadog, de cuyo conjunto de datos provienen muchas de las muestras analizadas— emplea exactamente las mismas señales", { bold: true }),
  t(": detecta la ejecución de contenido codificado en base64 (heurística exec-base64), la sobrescritura del comando de instalación en setup.py y la exfiltración de datos mediante seguimiento de flujo (taint tracking) con Semgrep. Que un detector de referencia de la industria vigile los mismos indicadores confirma la pertinencia de las señales elegidas."),
]));

// 3. Comparación
children.push(h1("3. Comparación de pyscan con herramientas del estado del arte"));
children.push(p(t("pyscan comparte con estas herramientas el uso de análisis estático y varias señales, pero difiere en su propósito y en su mecanismo de decisión. La Tabla 2 resume la comparación.")));
{
  const w = [Math.round(CONTENT_W*0.22), Math.round(CONTENT_W*0.26), Math.round(CONTENT_W*0.26), Math.round(CONTENT_W*0.26)];
  const rows = [
    ["Propósito", "Encontrar vulnerabilidades en el código propio", "Detectar paquetes maliciosos de terceros", "Detectar paquetes maliciosos de terceros"],
    ["Mecanismo de decisión", "Reglas / listas negras", "Heurísticas y reglas Semgrep", "Clasificador de ML supervisado"],
    ["Señales", "Llamadas peligrosas", "Llamadas, metadatos, taint tracking", "Metadatos + entropía + AST unificados"],
    ["Veredicto", "Lista de hallazgos (sin clasificar)", "Marca heurísticas activadas", "Probabilidad + veredicto binario"],
    ["Métricas de desempeño", "No aplica", "No publica Recall/F1 formal", "Recall 0,97 · F1 0,975 · FP 2,3 %"],
    ["Naturaleza", "Herramienta madura (PyCQA)", "Herramienta madura (Datadog)", "MVP académico reproducible"],
  ];
  children.push(makeTable(w, ["Aspecto", "Bandit", "GuardDog", "pyscan (este trabajo)"], rows,
    [{ bold: true }, {}, {}, {}]));
  children.push(caption("Tabla 2. Comparación de pyscan con Bandit y GuardDog."));
}
children.push(p([
  t("La diferencia esencial es el "),
  t("mecanismo de decisión", { bold: true }),
  t(". Bandit y GuardDog se basan en reglas y heurísticas: marcan la presencia de un patrón, pero una llamada como subprocess.Popen también aparece en código legítimo, lo que genera falsos positivos. pyscan, en cambio, consolida múltiples señales en un vector de características y delega el veredicto a un clasificador supervisado que aprende, a partir de datos etiquetados, a distinguir el uso malicioso del legítimo. Esta es la contribución del trabajo: no proponer nuevas señales, sino "),
  t("demostrar que las señales reconocidas por la industria son discriminantes cuando se combinan mediante aprendizaje automático", { bold: true }),
  t(", con un desempeño medible y reproducible."),
]));

// 4. Impacto
children.push(h1("4. Impacto para el proyecto"));
children.push(p(t("Este contraste aporta tres beneficios al trabajo de grado. Primero, validez externa: las señales de pyscan coinciden con las de Bandit, GuardDog y los catálogos CWE y MITRE ATT&CK, lo que respalda el diseño frente a un revisor. Segundo, posicionamiento: sitúa a pyscan dentro de una línea de herramientas activa y relevante, diferenciándolo por su enfoque de decisión basado en Machine Learning. Tercero, trazabilidad al riesgo real: cada señal queda vinculada a una debilidad catalogada (CWE) y a una técnica de adversario documentada (MITRE ATT&CK), lo que conecta el detector con marcos de referencia usados en la práctica profesional de ciberseguridad.")));

// 5. Conclusión
children.push(h1("5. Conclusión"));
children.push(p(t("Las señales que pyscan detecta con mayor frecuencia en paquetes maliciosos corresponden, una a una, con indicadores que herramientas consolidadas (Bandit, GuardDog) y estándares internacionales (CWE, MITRE ATT&CK) ya reconocen como propios del código malicioso. Esta convergencia valida externamente el enfoque del proyecto y refuerza su relevancia: pyscan no reinventa las señales, sino que aporta un mecanismo de decisión basado en Machine Learning sobre señales ya legitimadas por el estado del arte, con un desempeño cuantificado y reproducible.")));

// Referencias
children.push(h1("Referencias"));
const refs = [
  "[1] PyCQA, “Bandit: a tool designed to find common security issues in Python code,” documentación de blacklists (B102 exec, B301 pickle, B307 eval, B602/B605 subprocess). Disponible: https://bandit.readthedocs.io/en/latest/blacklists/",
  "[2] Datadog Security Labs, “Finding malicious PyPI packages through static code analysis: Meet GuardDog.” Disponible: https://securitylabs.datadoghq.com/articles/guarddog-identify-malicious-pypi-packages/",
  "[3] DataDog, “GuardDog — CLI tool to identify malicious PyPI and npm packages,” repositorio y reglas (exec-base64.yml). Disponible: https://github.com/DataDog/guarddog",
  "[4] MITRE, “CWE-78: OS Command Injection,” “CWE-94/95: Code/Eval Injection,” “CWE-502: Deserialization of Untrusted Data.” Disponible: https://cwe.mitre.org/",
  "[5] MITRE ATT&CK, “T1059: Command and Scripting Interpreter,” “T1027: Obfuscated Files or Information,” “T1195.002: Compromise Software Supply Chain.” Disponible: https://attack.mitre.org/",
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
      children: [new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 20 })] })] }) },
    children,
  }],
});

Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync("/tmp/Validacion_Externa_pyscan.docx", buf);
  console.log("DOCX escrito:", buf.length, "bytes");
});
