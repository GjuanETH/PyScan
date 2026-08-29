// Genera el documento del Objetivo 1 en formato NTC 1486 (Arial 12, márgenes 3-3-4-2 cm,
// interlineado 1.5, citación numérica ISO 690).
const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType, PageNumber, Footer,
} = require("docx");

const FONT = "Arial";
const CM = 567; // 1 cm en DXA
const CONTENT_W = Math.round(21 * CM) - (4 * CM) - (2 * CM); // A4 ancho - izq - der ≈ 8505 DXA

// Helpers ---------------------------------------------------------------
const t = (text, opts = {}) => new TextRun({ text, font: FONT, size: 24, ...opts });
const p = (runs, opts = {}) =>
  new Paragraph({
    spacing: { line: 360, after: 120 }, // 1.5 líneas
    alignment: AlignmentType.JUSTIFIED,
    children: Array.isArray(runs) ? runs : [runs],
    ...opts,
  });
const h1 = (text) =>
  new Paragraph({
    heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 160 },
    children: [new TextRun({ text, font: FONT, size: 28, bold: true })],
  });
const h2 = (text) =>
  new Paragraph({
    heading: HeadingLevel.HEADING_2, spacing: { before: 200, after: 120 },
    children: [new TextRun({ text, font: FONT, size: 24, bold: true })],
  });

// Tablas ----------------------------------------------------------------
function cell(text, { w, bold = false, shade = null, align = AlignmentType.LEFT } = {}) {
  return new TableCell({
    width: { size: w, type: WidthType.DXA },
    shading: shade ? { type: ShadingType.CLEAR, fill: shade, color: "auto" } : undefined,
    margins: { top: 60, bottom: 60, left: 90, right: 90 },
    children: [new Paragraph({
      alignment: align, spacing: { line: 276, after: 0 },
      children: [new TextRun({ text, font: FONT, size: 20, bold })],
    })],
  });
}
function headerRow(cells, widths, shade = "1F3864") {
  return new TableRow({
    tableHeader: true,
    children: cells.map((c, i) => new TableCell({
      width: { size: widths[i], type: WidthType.DXA },
      shading: { type: ShadingType.CLEAR, fill: shade, color: "auto" },
      margins: { top: 60, bottom: 60, left: 90, right: 90 },
      children: [new Paragraph({
        alignment: AlignmentType.CENTER, spacing: { line: 276, after: 0 },
        children: [new TextRun({ text: c, font: FONT, size: 20, bold: true, color: "FFFFFF" })],
      })],
    })),
  });
}
function dataRow(cells, widths, opts = []) {
  return new TableRow({
    children: cells.map((c, i) => cell(c, { w: widths[i], ...(opts[i] || {}) })),
  });
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
    rows: [headerRow(header, widths), ...rows.map((r) => dataRow(r, widths, rowOpts))],
  });
}
const caption = (text) => new Paragraph({
  spacing: { before: 60, after: 160 }, alignment: AlignmentType.LEFT,
  children: [new TextRun({ text, font: FONT, size: 20, italics: true })],
});

// ----------------------------------------------------------------------
const children = [];

// Portada de sección
children.push(new Paragraph({
  alignment: AlignmentType.CENTER, spacing: { after: 80 },
  children: [new TextRun({ text: "OBJETIVO ESPECÍFICO 1", font: FONT, size: 28, bold: true })],
}));
children.push(new Paragraph({
  alignment: AlignmentType.CENTER, spacing: { after: 240 },
  children: [new TextRun({
    text: "Identificación de vectores de ataque en PyPI y definición de requerimientos bajo ISO/IEC 25010:2023",
    font: FONT, size: 24, bold: true,
  })],
}));
children.push(p([
  t("Objetivo: ", { bold: true }),
  t("Identificar los principales vectores de ataque en el repositorio PyPI utilizando scripts de análisis, con el fin de definir los requerimientos funcionales y no funcionales del sistema bajo las características de adecuación funcional, eficiencia de desempeño, fiabilidad y mantenibilidad del modelo de calidad ISO/IEC 25010:2023.", { italics: true }),
]));

// 1. Introducción
children.push(h1("1. Alcance y enfoque del objetivo"));
children.push(p(t("Este objetivo cumple una función de fundamentación: antes de construir el detector es necesario establecer, con evidencia, qué comportamientos maliciosos predominan en el ecosistema PyPI. Para ello se combinan dos fuentes de evidencia. La primera es la literatura empírica reciente sobre ataques a la cadena de suministro de software, que aporta frecuencias medidas sobre miles de paquetes reales. La segunda es un análisis propio, ejecutado mediante scripts, que cuantifica los mismos vectores sobre el corpus de muestras maliciosas reunido para el proyecto. A partir de esa evidencia se derivan los requerimientos funcionales y no funcionales, y cada uno se asocia a una característica del modelo de calidad ISO/IEC 25010:2023.")));
children.push(p([
  t("La trazabilidad es el criterio rector: "),
  t("cada vector de ataque identificado justifica al menos un requerimiento funcional, y cada meta de calidad del proyecto se expresa como un requerimiento no funcional medible.", { bold: true }),
  t(" De este modo, el diseño del MVP no responde a decisiones arbitrarias sino a amenazas observadas."),
]));

// 2. Metodología
children.push(h1("2. Metodología de análisis mediante scripts"));
children.push(p(t("El análisis se apoya en los extractores de análisis estático desarrollados para el MVP, que en ningún momento ejecutan el código inspeccionado. El script scripts/analyze_attack_vectors.py recorre el corpus de paquetes maliciosos, descomprime cada muestra de forma segura y aplica tres extractores complementarios sobre su contenido: el extractor de metadatos (similitud léxica del nombre por distancia de Levenshtein), el extractor de entropía de Shannon por ventanas y el extractor de árbol de sintaxis abstracta (AST). Con las señales resultantes, el script clasifica cada paquete según los vectores de ataque presentes y produce un resumen cuantitativo en formato JSON y CSV, además de una tabla de frecuencias.")));
children.push(p([
  t("La correspondencia entre cada vector y la señal que lo evidencia se resume en la Tabla 1. El script se ejecutó sobre un corpus de "),
  t("2.000 paquetes maliciosos reales", { bold: true }),
  t(" provenientes de los conjuntos de datos de Datadog Security Labs [5] y PyPI Malregistry [1]; de ellos, 1.926 se procesaron con éxito y 74 se descartaron por estar corruptos o ilegibles. Los benignos (2.000 paquetes del Top de PyPI) se recolectaron con un script análogo. Las frecuencias medidas se contrastan con las reportadas por la literatura en la Sección 3, garantizando que ninguna cifra experimental sea inventada."),
]));

// Tabla 1: vector -> señal medida
{
  const w = [Math.round(CONTENT_W*0.28), Math.round(CONTENT_W*0.40), Math.round(CONTENT_W*0.32)];
  const rows = [
    ["V1 Typosquatting / combosquatting", "Nombre a distancia de edición ≤2 de un paquete legítimo, o núcleo legítimo envuelto en afijos", "Extractor de metadatos (Levenshtein/RapidFuzz)"],
    ["V2 Ejecución en instalación", "setup.py con cmdclass o clase que extiende install", "AST: detección de hook de instalación"],
    ["V3 Ofuscación / empaquetado", "Ventanas de 256 bytes con entropía ≥ umbral (~7,0)", "Extractor de entropía de Shannon"],
    ["V4 Ejecución de comandos/código", "Llamadas a eval, exec, compile, os.system, subprocess", "AST: llamadas peligrosas (resistente a alias)"],
    ["V5 Deserialización insegura", "Llamadas a pickle.loads o marshal.loads", "AST: llamadas peligrosas"],
    ["V6 Codificación/decodificación", "Llamadas a base64.b64decode / b64encode", "AST: llamadas peligrosas"],
    ["V7 Red / exfiltración", "Literales URL/IP e imports de socket, urllib, requests", "AST: literales de red e imports"],
  ];
  children.push(makeTable(w, ["Vector de ataque", "Señal observable (análisis estático)", "Extractor que lo mide"], rows));
  children.push(caption("Tabla 1. Correspondencia entre vectores de ataque y señales medidas por los scripts de análisis. Fuente: elaboración propia."));
}

// 3. Vectores identificados
children.push(h1("3. Vectores de ataque identificados en PyPI"));
children.push(p(t("La evidencia empírica converge en un hallazgo central: el ataque a la cadena de suministro en PyPI se apoya de forma dominante en la ejecución durante la instalación y en la suplantación de nombres, y con frecuencia combina varios vectores en un mismo paquete. Los estudios revisados coinciden en que más de la mitad de los paquetes maliciosos activan su comportamiento al instalarse y que el typosquatting es el método de infección más común, siendo la exfiltración de datos el objetivo predominante.")));
children.push(p([
  t("Un estudio empírico sobre el ecosistema PyPI encontró que el 74,81 % de los paquetes maliciosos logra ejecutarse en los proyectos de los usuarios finales a través de la instalación desde código fuente, y que más de la mitad exhibe múltiples comportamientos maliciosos simultáneos, con el robo de información y la ejecución de comandos como los más prevalentes [1]. "),
  t("El análisis de la colección Backstabber's Knife Collection reportó que el 56 % de los paquetes activa su carga maliciosa en la instalación, el 41 % emplea condiciones adicionales para decidir si ejecutarse, y el 61 % recurre al typosquatting para introducirse en el ecosistema [2]. "),
  t("Un análisis independiente sobre 846 paquetes maliciosos de PyPI clasificó el 68,6 % como ataques en tiempo de instalación, el 19 % en tiempo de importación y el 12,4 % en tiempo de ejecución [3]."),
]));

children.push(h2("3.1 Resultados del análisis propio"));
children.push(p([
  t("La ejecución del script sobre los 1.926 paquetes maliciosos procesados arrojó la distribución de la Tabla 2. El vector dominante fue la "),
  t("ejecución de comandos/código (76,32 %)", { bold: true }),
  t(", seguido de los indicios de red/exfiltración (41,95 %) y del typosquatting/combosquatting (25,96 %). La ejecución en instalación apareció en el 20,15 % de las muestras y la codificación con base64 en el 15,68 %. La deserialización insegura (1,61 %) y la ofuscación por alta entropía (0,10 %) resultaron poco frecuentes en este corpus."),
]));

// Tabla 2: frecuencias propias vs literatura
{
  const w = [Math.round(CONTENT_W*0.34), Math.round(CONTENT_W*0.16), Math.round(CONTENT_W*0.34), Math.round(CONTENT_W*0.16)];
  const rows = [
    ["V4 Ejecución de comandos/código", "76,32 %", "Comportamiento prevalente junto al robo de información", "[1]"],
    ["V7 Red / exfiltración de datos", "41,95 %", "Objetivo más común; robo de información predominante", "[1], [2]"],
    ["V1 Typosquatting / combosquatting", "25,96 %", "61 % usa suplantación de nombres para propagarse", "[2], [4]"],
    ["V2 Ejecución en instalación", "20,15 %", "68,6 %–74,81 % se ejecutan al instalarse", "[1], [2], [3]"],
    ["V6 Codificación/decodificación (base64)", "15,68 %", "Uso frecuente de base64 para evadir detección", "[1], [2]"],
    ["V5 Deserialización insegura", "1,61 %", "Vector documentado (pickle/marshal)", "[2]"],
    ["V3 Ofuscación / empaquetado (entropía)", "0,10 %", "Ofuscación frecuente, mayormente vía base64", "[1], [2]"],
  ];
  children.push(makeTable(w, ["Vector de ataque", "% propio (n=1.926)", "Contraste con la literatura", "Fuente"], rows,
    [{}, { align: AlignmentType.CENTER, bold: true }, {}, { align: AlignmentType.CENTER }]));
  children.push(caption("Tabla 2. Frecuencia de los vectores medida sobre el corpus propio (2.000 paquetes maliciosos de [1] y [5]; 1.926 procesados) y su contraste con la literatura. Fuente: elaboración propia."));
}

children.push(p([
  t("La combinación de vectores fue la norma: el "),
  t("48,23 % de los paquetes presentó dos o más vectores simultáneos", { bold: true }),
  t(", lo que coincide con el hallazgo de la literatura de que más de la mitad del malware exhibe múltiples comportamientos [1]. La Tabla 3 detalla esta co-ocurrencia."),
]));

// Tabla 3: co-ocurrencia
{
  const w = [Math.round(CONTENT_W*0.40), Math.round(CONTENT_W*0.30), Math.round(CONTENT_W*0.30)];
  const co = [["0 vectores", "53", "2,75 %"], ["1 vector", "944", "49,01 %"],
    ["2 vectores", "432", "22,43 %"], ["3 vectores", "318", "16,51 %"],
    ["4 vectores", "160", "8,31 %"], ["5 vectores", "15", "0,78 %"],
    ["6 vectores", "4", "0,21 %"]];
  children.push(makeTable(w, ["Vectores simultáneos", "Paquetes", "%"], co,
    [{}, { align: AlignmentType.CENTER }, { align: AlignmentType.CENTER }]));
  children.push(caption("Tabla 3. Co-ocurrencia de vectores por paquete en el corpus analizado."));
}

children.push(p(t("El desglose de las llamadas peligrosas detectadas por el recorrido AST refuerza el predominio del vector V4 y aporta evidencia concreta de los mecanismos empleados (Tabla 4).")));

// Tabla 4: top llamadas peligrosas
{
  const w = [Math.round(CONTENT_W*0.55), Math.round(CONTENT_W*0.45)];
  const calls = [["subprocess.Popen", "972"], ["exec", "260"], ["base64.b64decode", "243"],
    ["requests.get", "237"], ["os.system", "172"], ["urllib.request.urlopen", "163"],
    ["__import__", "115"], ["base64.b64encode", "99"], ["socket.socket", "93"],
    ["subprocess.run", "71"], ["eval", "52"], ["subprocess.call", "50"],
    ["compile", "41"], ["pickle.loads", "21"], ["os.popen", "14"]];
  children.push(makeTable(w, ["Llamada peligrosa", "Ocurrencias"], calls,
    [{}, { align: AlignmentType.CENTER }]));
  children.push(caption("Tabla 4. Llamadas peligrosas más frecuentes detectadas por el recorrido AST."));
}

children.push(h2("3.2 Contraste con la literatura e implicación de diseño"));
children.push(p(t("Los resultados propios concuerdan con la literatura en el panorama general —predominio de la ejecución de código, la exfiltración por red y el typosquatting, y alta co-ocurrencia de vectores— con una diferencia de énfasis esperable: al medir directamente las llamadas del código, la ejecución de comandos (V4) aparece como la señal más frecuente, mientras que los estudios que clasifican por momento de activación resaltan la instalación. Ambas visiones son complementarias y no contradictorias.")));
children.push(p([
  t("De este panorama se desprende una implicación de diseño directa: "),
  t("un detector para PyPI no puede limitarse a una sola señal.", { bold: true }),
  t(" Dado que los paquetes combinan vectores y que la instalación es un momento crítico, el sistema debe cubrir simultáneamente la suplantación de nombres, la lógica de instalación, la ofuscación, la ejecución de comandos, la deserialización insegura, la codificación y los indicios de red. Esta cobertura múltiple es precisamente lo que fundamenta el conjunto de requerimientos funcionales de la Sección 4."),
]));

// 4. Requerimientos
children.push(h1("4. Requerimientos derivados"));
children.push(h2("4.1 Requerimientos funcionales"));
children.push(p(t("Cada requerimiento funcional responde a uno o más vectores de la Sección 3. Los requerimientos RF01 a RF08 corresponden a las capacidades de detección; RF09 a RF11 corresponden a la decisión y la entrega de resultados.")));
{
  const w = [Math.round(CONTENT_W*0.10), Math.round(CONTENT_W*0.66), Math.round(CONTENT_W*0.24)];
  const rows = [
    ["RF01", "Descargar de PyPI el paquete indicado y extraerlo de forma segura (sdist/wheel), verificando la integridad mediante sha256.", "Base (todos)"],
    ["RF02", "Detectar typosquatting y combosquatting comparando el nombre contra un corpus de paquetes legítimos mediante distancia de edición.", "V1"],
    ["RF03", "Detectar lógica de ejecución en la instalación analizando setup.py (uso de cmdclass o clases que extienden install).", "V2"],
    ["RF04", "Detectar ofuscación o empaquetado calculando la entropía de Shannon por ventanas y reportando las ventanas sospechosas.", "V3"],
    ["RF05", "Detectar llamadas peligrosas de ejecución de comandos y código mediante recorrido AST, resistiendo la evasión por alias de import.", "V4"],
    ["RF06", "Detectar deserialización insegura (pickle.loads, marshal.loads) mediante recorrido AST.", "V5"],
    ["RF07", "Detectar el uso de codificación/decodificación (base64) asociada a cargas ofuscadas.", "V6"],
    ["RF08", "Detectar indicios de red y exfiltración: literales de URL/IP e imports de socket, urllib o requests.", "V7"],
    ["RF09", "Consolidar las señales en un vector de características y emitir el veredicto final mediante un clasificador supervisado (no por reglas fijas).", "Todos"],
    ["RF10", "Generar reportes en formato JSON y SARIF 2.1.0, con códigos de salida aptos para integración continua.", "Entrega"],
    ["RF11", "Ofrecer un modo de análisis offline (solo nombre) que no requiera descargar el paquete.", "V1"],
  ];
  children.push(makeTable(w, ["ID", "Requerimiento funcional", "Vector(es)"], rows,
    [{ align: AlignmentType.CENTER, bold: true }, {}, { align: AlignmentType.CENTER }]));
  children.push(caption("Tabla 5. Requerimientos funcionales y su trazabilidad a los vectores de ataque."));
}

children.push(h2("4.2 Requerimientos no funcionales (ISO/IEC 25010:2023)"));
children.push(p(t("Los requerimientos no funcionales se organizan según las cuatro características del modelo de calidad seleccionadas. Cada uno se expresa de forma medible para permitir su verificación durante la validación del MVP.")));
{
  const w = [Math.round(CONTENT_W*0.09), Math.round(CONTENT_W*0.24), Math.round(CONTENT_W*0.51), Math.round(CONTENT_W*0.16)];
  const rows = [
    ["RNF01", "Adecuación funcional — Completitud funcional", "El sistema debe cubrir la detección de los siete vectores de ataque identificados (V1–V7).", "7/7 vectores"],
    ["RNF02", "Adecuación funcional — Corrección funcional", "El clasificador debe alcanzar Recall ≥ 0,90 y F1 ≥ 0,85, con una tasa de falsos positivos ≤ 10 %. Verificado: Recall 0,971, F1 0,975, FP 2,3 % en hold-out.", "Recall, F1, FP"],
    ["RNF03", "Adecuación funcional — Pertinencia funcional", "El veredicto debe emitirse mediante aprendizaje automático supervisado, no mediante umbrales fijos.", "Decisión ML"],
    ["RNF04", "Eficiencia de desempeño — Comportamiento temporal", "El análisis completo de un paquete no debe superar 120 segundos.", "≤ 120 s/paquete"],
    ["RNF05", "Eficiencia de desempeño — Utilización de recursos", "El consumo de memoria durante el análisis no debe superar 2 GB.", "≤ 2 GB RAM"],
    ["RNF06", "Eficiencia de desempeño — Capacidad", "La extracción debe respetar límites de tamaño y número de archivos (anti zip-bomb).", "200 MB / 20k archivos"],
    ["RNF07", "Fiabilidad — Tolerancia a fallos", "La extracción debe rechazar rutas peligrosas (Zip Slip), enlaces y bombas; el sistema debe degradar sin modelo entrenado y omitir archivos ilegibles sin abortar.", "Extracción segura"],
    ["RNF08", "Fiabilidad — Ausencia de fallos", "El sistema debe contar con una batería de pruebas automatizadas que respalde su estabilidad.", "53 pruebas"],
    ["RNF09", "Fiabilidad — Recuperabilidad", "Los errores de red o de PyPI deben manejarse con mensajes claros y códigos de salida diferenciados.", "Exit codes 0/1/2"],
    ["RNF10", "Mantenibilidad — Modularidad", "La arquitectura debe seguir el patrón Pipes and Filters con extractores independientes e intercambiables.", "Módulos aislados"],
    ["RNF11", "Mantenibilidad — Capacidad de prueba", "La cobertura de pruebas del código debe ser ≥ 80 %.", "Cobertura ≥ 80 %"],
    ["RNF12", "Mantenibilidad — Modificabilidad / Reusabilidad", "Las interfaces entre módulos deben definirse con modelos tipados (Pydantic) y la configuración debe centralizarse; licencia MIT.", "Interfaces Pydantic"],
  ];
  children.push(makeTable(w, ["ID", "Característica ISO/IEC 25010:2023", "Requerimiento no funcional", "Métrica"], rows,
    [{ align: AlignmentType.CENTER, bold: true }, {}, {}, { align: AlignmentType.CENTER }]));
  children.push(caption("Tabla 6. Requerimientos no funcionales mapeados a las características de ISO/IEC 25010:2023 [6]."));
}

// 5. Trazabilidad
children.push(h1("5. Matriz de trazabilidad"));
children.push(p(t("La Tabla 7 sintetiza la cadena de justificación completa: desde la amenaza observada en PyPI hasta la característica de calidad que la gobierna. Esta trazabilidad permite verificar que ningún requerimiento carece de fundamento y que ninguna amenaza relevante quedó sin cubrir.")));
{
  const w = [Math.round(CONTENT_W*0.34), Math.round(CONTENT_W*0.22), Math.round(CONTENT_W*0.44)];
  const rows = [
    ["V1 Typosquatting / combosquatting", "RF02, RF11", "Adecuación funcional (RNF01, RNF02)"],
    ["V2 Ejecución en instalación", "RF03", "Adecuación funcional; Fiabilidad"],
    ["V3 Ofuscación / empaquetado", "RF04", "Adecuación funcional"],
    ["V4 Ejecución de comandos/código", "RF05", "Adecuación funcional; Corrección"],
    ["V5 Deserialización insegura", "RF06", "Adecuación funcional"],
    ["V6 Codificación/decodificación", "RF07", "Adecuación funcional"],
    ["V7 Red / exfiltración", "RF08", "Adecuación funcional"],
    ["Decisión y entrega", "RF09, RF10", "Pertinencia; Mantenibilidad"],
    ["Robustez y desempeño", "RF01", "Eficiencia; Fiabilidad (RNF04–RNF09)"],
  ];
  children.push(makeTable(w, ["Vector / aspecto", "Requerimientos funcionales", "Característica ISO/IEC 25010:2023"], rows));
  children.push(caption("Tabla 7. Matriz de trazabilidad vector → requerimiento funcional → característica de calidad."));
}

// 6. Amenazas a la validez
children.push(h1("6. Amenazas a la validez"));
children.push(p([
  t("El análisis de la importancia de características del clasificador entrenado reveló una dependencia elevada de las señales de nombre: "),
  t("la distancia mínima de nombre (0,62) y el indicador de typosquatting (0,15) concentran cerca del 77 % de la importancia", { bold: true }),
  t(". Esto se explica por la composición del conjunto de datos: los paquetes benignos provienen del Top de PyPI, que coincide con la lista de referencia usada para medir la similitud de nombres, por lo que su distancia tiende a cero; en cambio, los maliciosos —muchos de ellos typosquats— presentan distancias mayores. El modelo puede así aprender una diferencia parcialmente artificial del dataset (fuga de datos) en lugar de una señal de malicia intrínseca."),
]));
children.push(p([
  t("Esta amenaza no invalida los resultados —los KPI se cumplen con holgura— pero acota su interpretación y motiva un trabajo de robustez: "),
  t("incorporar paquetes benignos poco populares y fuera de la lista de referencia, y evaluar el modelo excluyendo las características de nombre", { bold: true }),
  t(", para confirmar que las señales de código (ejecución, red, instalación) aportan capacidad discriminante por sí mismas. Se documenta como línea de mejora para las siguientes iteraciones del MVP."),
]));

// 7. Conclusión
children.push(h1("7. Conclusión del objetivo"));
children.push(p(t("El análisis empírico sobre 1.926 paquetes maliciosos reales, contrastado con la literatura, permite concluir que los ataques a PyPI se concentran en la ejecución de comandos y código (76,3 %), la exfiltración por red (42,0 %) y la suplantación de nombres (26,0 %), y que tienden a combinar varios vectores: el 48,2 % de las muestras presentó dos o más. Este hallazgo, respaldado por datos propios, justifica un detector de cobertura múltiple cuya decisión final recae en un clasificador supervisado. Los once requerimientos funcionales y los doce requerimientos no funcionales derivados quedan trazados a los vectores observados y a las cuatro características del modelo ISO/IEC 25010:2023 seleccionadas. La corrección funcional exigida (RNF02) se verificó posteriormente: el modelo alcanzó Recall 0,971, F1 0,975 y una tasa de falsos positivos de 2,3 % en el conjunto de hold-out, cumpliendo con holgura las metas del proyecto. Con ello se cumple el primer objetivo específico y se establece una base fundamentada para el diseño e implementación abordados en los objetivos siguientes.")));

// Referencias
children.push(h1("Referencias"));
const refs = [
  "[1] W. Guo et al., “An Empirical Study of Malicious Code in PyPI Ecosystem,” en Proc. 38th IEEE/ACM Int. Conf. on Automated Software Engineering (ASE), 2023. Disponible: https://arxiv.org/abs/2309.11021",
  "[2] M. Ohm, H. Plate, A. Sykosch y M. Meier, “Backstabber’s Knife Collection: A Review of Open Source Software Supply Chain Attacks,” en Proc. DIMVA, 2020. Disponible: https://arxiv.org/abs/2005.09535",
  "[3] “An Analysis of Malicious Packages in Open-Source Software in the Wild,” 2024. Disponible: https://arxiv.org/abs/2404.04991",
  "[4] “Typosquatting and Combosquatting Attacks on the Python Ecosystem,” en IEEE European Symp. on Security and Privacy Workshops (EuroS&PW), 2020.",
  "[5] Datadog Security Labs, “Malicious Software Packages Dataset,” 2023–. Disponible: https://github.com/DataDog/malicious-software-packages-dataset",
  "[6] ISO/IEC 25010:2023, Systems and software engineering — Systems and software Quality Requirements and Evaluation (SQuaRE) — Product quality model. Ginebra: ISO, 2023.",
];
refs.forEach((r) => children.push(new Paragraph({
  spacing: { line: 300, after: 120 }, alignment: AlignmentType.JUSTIFIED,
  indent: { left: 340, hanging: 340 },
  children: [new TextRun({ text: r, font: FONT, size: 22 })],
})));

// Documento -------------------------------------------------------------
const doc = new Document({
  creator: "pyscan - Trabajo de Grado",
  styles: { default: { document: { run: { font: FONT, size: 24 } } } },
  sections: [{
    properties: {
      page: {
        size: { width: Math.round(21 * CM), height: Math.round(29.7 * CM) }, // A4
        margin: { top: 3 * CM, bottom: 3 * CM, left: 4 * CM, right: 2 * CM }, // NTC 1486
      },
    },
    footers: {
      default: new Footer({
        children: [new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 20 })],
        })],
      }),
    },
    children,
  }],
});

Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync("/tmp/Objetivo1_Vectores_y_Requisitos.docx", buf);
  console.log("DOCX escrito:", buf.length, "bytes");
});
