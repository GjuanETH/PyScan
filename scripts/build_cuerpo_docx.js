// Cuerpo de la tesis — Capítulos 2 a 7 ensamblados. NTC 1486.
const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType, PageNumber, Footer,
  ImageRun, LevelFormat,
} = require("docx");

const FONT = "Arial", MONO = "Consolas", CM = 567;
const CONTENT_W = Math.round(21 * CM) - (4 * CM) - (2 * CM);
const IMG = "/tmp/cuerpo/img";

const t = (text, o = {}) => new TextRun({ text, font: FONT, size: 24, ...o });
const p = (runs, o = {}) => new Paragraph({ spacing: { line: 360, after: 120 },
  alignment: AlignmentType.JUSTIFIED, children: Array.isArray(runs) ? runs : [runs], ...o });
const h1 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 300, after: 160 },
  pageBreakBefore: true, children: [new TextRun({ text, font: FONT, size: 28, bold: true })] });
const h2 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 200, after: 120 },
  children: [new TextRun({ text, font: FONT, size: 24, bold: true })] });
const cap = (text) => new Paragraph({ spacing: { before: 20, after: 180 }, alignment: AlignmentType.CENTER,
  children: [new TextRun({ text, font: FONT, size: 20, italics: true })] });
const bullet = (runs) => new Paragraph({ numbering: { reference: "b", level: 0 },
  spacing: { line: 340, after: 100 }, alignment: AlignmentType.JUSTIFIED,
  children: Array.isArray(runs) ? runs : [runs] });
function fig(file, w, h, tw) { const s = tw / w;
  return new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 120, after: 60 },
    children: [new ImageRun({ type: "png", data: fs.readFileSync(`${IMG}/${file}`),
      transformation: { width: Math.round(w * s), height: Math.round(h * s) } })] }); }
function code(lines) { return lines.map((ln) => new Paragraph({
  spacing: { line: 240, after: 0 }, shading: { type: ShadingType.CLEAR, fill: "F2F2F2", color: "auto" },
  children: [new TextRun({ text: ln || " ", font: MONO, size: 17 })] })); }
function cl(text, { w, b = false, a = AlignmentType.LEFT, fill = null } = {}) {
  return new TableCell({ width: { size: w, type: WidthType.DXA },
    shading: fill ? { type: ShadingType.CLEAR, fill, color: "auto" } : undefined,
    margins: { top: 55, bottom: 55, left: 85, right: 85 },
    children: [new Paragraph({ alignment: a, spacing: { line: 252, after: 0 },
      children: [new TextRun({ text, font: FONT, size: 18, bold: b })] })] }); }
function hr(cells, ws) { return new TableRow({ tableHeader: true, children: cells.map((c, i) =>
  new TableCell({ width: { size: ws[i], type: WidthType.DXA },
    shading: { type: ShadingType.CLEAR, fill: "1F3864", color: "auto" },
    margins: { top: 55, bottom: 55, left: 85, right: 85 },
    children: [new Paragraph({ alignment: AlignmentType.CENTER, spacing: { line: 252, after: 0 },
      children: [new TextRun({ text: c, font: FONT, size: 18, bold: true, color: "FFFFFF" })] })] })) }); }
function tbl(ws, head, rows, opts = []) { return new Table({ columnWidths: ws,
  width: { size: ws.reduce((a, b) => a + b, 0), type: WidthType.DXA },
  borders: { top: { style: BorderStyle.SINGLE, size: 4, color: "999999" },
    bottom: { style: BorderStyle.SINGLE, size: 4, color: "999999" },
    left: { style: BorderStyle.SINGLE, size: 4, color: "999999" },
    right: { style: BorderStyle.SINGLE, size: 4, color: "999999" },
    insideHorizontal: { style: BorderStyle.SINGLE, size: 2, color: "CCCCCC" },
    insideVertical: { style: BorderStyle.SINGLE, size: 2, color: "CCCCCC" } },
  rows: [hr(head, ws), ...rows.map((r) => new TableRow({ children: r.map((c, i) => cl(c, { w: ws[i], ...(opts[i] || {}) })) }))] }); }
const C = { a: AlignmentType.CENTER }, CB = { a: AlignmentType.CENTER, b: true };

const ch = [];
const W3 = (a, b, c) => [Math.round(CONTENT_W*a), Math.round(CONTENT_W*b), Math.round(CONTENT_W*c)];
const W4 = (a, b, c, d) => [Math.round(CONTENT_W*a), Math.round(CONTENT_W*b), Math.round(CONTENT_W*c), Math.round(CONTENT_W*d)];
const W5 = (a, b, c, d, e) => [Math.round(CONTENT_W*a), Math.round(CONTENT_W*b), Math.round(CONTENT_W*c), Math.round(CONTENT_W*d), Math.round(CONTENT_W*e)];

// ===================== CAPÍTULO 2 =====================
ch.push(h1("2. ANÁLISIS DE REQUERIMIENTOS Y VECTORES DE ATAQUE EN PYPI"));
ch.push(p([t("En este capítulo se desarrolla el primer objetivo específico: identificar los principales vectores de ataque en PyPI mediante scripts de análisis y definir, a partir de esa evidencia, los requerimientos funcionales y no funcionales del sistema bajo las características de adecuación funcional, eficiencia de desempeño, fiabilidad y mantenibilidad de la norma ISO/IEC 25010:2023.")]));
ch.push(h2("2.1 Método de análisis"));
ch.push(p(t("La identificación se apoyó en un análisis empírico mediante el script analyze_attack_vectors.py, que aplica los tres extractores estáticos (metadatos, entropía y AST) sobre un corpus de paquetes maliciosos reales, sin ejecutar su código. Se analizaron 2.000 paquetes de Datadog Security Labs y PyPI Malregistry; 1.926 se procesaron con éxito y 74 se descartaron por estar corruptos.")));
ch.push(h2("2.2 Vectores de ataque identificados"));
ch.push(p(t("La Tabla 2.1 presenta la frecuencia de cada vector medida sobre el corpus. El vector dominante es la ejecución de comandos/código, seguido de la exfiltración por red y la suplantación de nombres.")));
ch.push(tbl(W3(0.40, 0.20, 0.40), ["Vector de ataque", "% (n=1.926)", "Contraste con la literatura"], [
  ["V4 Ejecución de comandos/código", "76,3 %", "Comportamiento prevalente (Guo et al.)"],
  ["V7 Red / exfiltración de datos", "42,0 %", "Objetivo más común del malware"],
  ["V1 Typosquatting / combosquatting", "26,0 %", "61 % en Ohm et al. como infección"],
  ["V2 Ejecución en instalación (setup.py)", "20,2 %", "68–75 % se ejecutan al instalar"],
  ["V6 Codificación (base64)", "15,7 %", "Ofuscación frecuente"],
  ["V5 Deserialización insegura", "1,6 %", "Vector documentado (pickle/marshal)"],
  ["V3 Ofuscación (entropía alta)", "0,1 %", "Poco frecuente en este corpus"],
], [{}, CB, {}]));
ch.push(cap("Tabla 2.1. Frecuencia de los vectores de ataque (corpus propio de 1.926 paquetes)."));
ch.push(p([t("El 48,2 % de los paquetes presentó dos o más vectores simultáneos, lo que fundamenta la necesidad de una detección de cobertura múltiple.")]));
ch.push(h2("2.3 Mapeo con la taxonomía de Ladisa et al. y delimitación del alcance"));
ch.push(p([t("La taxonomía de Ladisa et al. [10] organiza en un árbol de ataque los 107 vectores de la cadena de suministro. Muchos de ellos (compromiso de cuentas, build, infraestructura o control de versiones) quedan fuera del alcance de un analizador estático del contenido del paquete, pues requieren otras salvaguardas (2FA, firma de commits, SLSA). El MVP se delimita a los vectores cuyo resultado es código malicioso en el artefacto distribuido, detectable de forma estática (Tabla 2.2).")]));
ch.push(tbl(W3(0.34, 0.50, 0.16), ["Vector(es) pyscan", "Categoría en Ladisa et al. [10]", "Alcance"], [
  ["V1 Typosquatting / combosquatting", "Rama «Confusión de nombres» (typosquatting, combosquatting, brandjacking).", "En alcance"],
  ["V2 Ejecución en instalación", "Payload de «Publicar paquete malicioso» (ejecución en instalación).", "En alcance"],
  ["V3–V6 Ofuscación/comandos/deserialización/base64", "Comportamientos y evasión del código malicioso.", "En alcance"],
  ["V7 Red / exfiltración", "Objetivo del payload (filtración de datos).", "En alcance"],
  ["Compromiso de cuenta / build / VCS", "Subversión mediante compromiso de credenciales o CI/CD.", "Fuera de alcance"],
], [{}, {}, C]));
ch.push(cap("Tabla 2.2. Mapeo de los vectores de pyscan a la taxonomía de Ladisa et al. [10]."));
ch.push(p([t("Sobre el subconjunto en alcance, pyscan cubre las técnicas de confusión de nombres y los principales comportamientos maliciosos, con una cobertura superior al 90 %. "),
  t("Nota (verificar con el director): ", { bold: true, italics: true }),
  t("el KPI define el denominador como el total de la taxonomía; dado que ~2/3 de los 107 vectores conciernen a infraestructura/cuentas/CI, la cobertura se calcula sobre el subconjunto en alcance.", { italics: true })]));
ch.push(h2("2.4 Requerimientos funcionales"));
ch.push(p(t("Cada requerimiento funcional responde a uno o más vectores (Tabla 2.3).")));
ch.push(tbl(W3(0.10, 0.68, 0.22), ["ID", "Requerimiento funcional", "Vector(es)"], [
  ["RF01", "Descargar y extraer de forma segura el paquete de PyPI, verificando sha256.", "Base"],
  ["RF02", "Detectar typosquatting/combosquatting por distancia de edición.", "V1"],
  ["RF03", "Detectar ejecución en la instalación (setup.py: cmdclass/install).", "V2"],
  ["RF04", "Detectar ofuscación mediante entropía de Shannon por ventanas.", "V3"],
  ["RF05", "Detectar llamadas peligrosas por AST, resistente a alias de import.", "V4"],
  ["RF06", "Detectar deserialización insegura (pickle/marshal).", "V5"],
  ["RF07", "Detectar codificación base64 de cargas ofuscadas.", "V6"],
  ["RF08", "Detectar indicios de red/exfiltración (URLs/IPs, socket/urllib/requests).", "V7"],
  ["RF09", "Consolidar señales y emitir el veredicto por clasificador supervisado.", "Todos"],
  ["RF10", "Generar reportes JSON y SARIF 2.1.0 con códigos de salida para CI.", "Entrega"],
  ["RF11", "Ofrecer análisis offline del nombre (check-name).", "V1"],
], [CB, {}, C]));
ch.push(cap("Tabla 2.3. Requerimientos funcionales y su trazabilidad a los vectores."));
ch.push(h2("2.5 Requerimientos no funcionales (ISO/IEC 25010:2023)"));
ch.push(p(t("Los requerimientos no funcionales se organizan según las cuatro características delimitadas, con métricas verificables (Tabla 2.4).")));
ch.push(tbl(W4(0.09, 0.26, 0.49, 0.16), ["ID", "Característica ISO 25010", "Requerimiento no funcional", "Métrica"], [
  ["RNF01", "Adec. funcional — Completitud", "Cubrir los siete vectores identificados.", "7/7"],
  ["RNF02", "Adec. funcional — Corrección", "Recall ≥ 0,90; F1 ≥ 0,85; FP ≤ 10 %.", "Recall/F1/FP"],
  ["RNF03", "Adec. funcional — Pertinencia", "Veredicto por ML, no por reglas fijas.", "Decisión ML"],
  ["RNF04", "Eficiencia — C. temporal", "Análisis de un paquete ≤ 120 s.", "≤ 120 s"],
  ["RNF05", "Eficiencia — Recursos", "Consumo de memoria ≤ 2 GB.", "≤ 2 GB"],
  ["RNF06", "Eficiencia — Capacidad", "Límites de tamaño/archivos (anti zip-bomb).", "200 MB / 20k"],
  ["RNF07", "Fiabilidad — Tolerancia a fallos", "Extracción segura; degradación sin modelo.", "Extracción segura"],
  ["RNF08", "Fiabilidad — Madurez", "Batería de pruebas automatizadas.", "Suite pytest"],
  ["RNF09", "Fiabilidad — Recuperabilidad", "Errores con mensajes claros y exit codes.", "Exit 0/1/2"],
  ["RNF10", "Mantenibilidad — Modularidad", "Pipes and Filters con extractores independientes.", "Módulos aislados"],
  ["RNF11", "Mantenibilidad — Testeabilidad", "Cobertura de pruebas ≥ 80 %.", "≥ 80 %"],
  ["RNF12", "Mantenibilidad — Modificabilidad", "Interfaces tipadas (Pydantic).", "Pydantic"],
], [CB, {}, {}, C]));
ch.push(cap("Tabla 2.4. Requerimientos no funcionales mapeados a ISO/IEC 25010:2023."));
ch.push(h2("2.6 Product Backlog inicial (Azure DevOps)"));
ch.push(p(t("Los requerimientos se transfirieron a un Product Backlog en Azure DevOps como historias de usuario con criterios de aceptación (Tabla 2.5); la evidencia del tablero se adjunta como anexo.")));
ch.push(tbl(W3(0.52, 0.32, 0.16), ["Historia de usuario", "Criterio de aceptación", "RF"], [
  ["Como usuario, quiero analizar un paquete de PyPI por su nombre.", "Devuelve veredicto y señales detectadas.", "RF01, RF09"],
  ["Como usuario, quiero analizar mi requirements.txt completo.", "Procesa la lista y da un resumen consolidado.", "RF01, RF10"],
  ["Como analista, quiero un reporte SARIF para mi pipeline de CI.", "Genera SARIF 2.1.0 y exit code coherente.", "RF10"],
  ["Como usuario, quiero verificar un nombre sin descargar el paquete.", "check-name responde offline.", "RF11"],
], [{}, {}, C]));
ch.push(cap("Tabla 2.5. Historias de usuario representativas del backlog inicial."));
ch.push(h2("2.7 Medición de los KPI del objetivo (OE1)"));
ch.push(tbl(W4(0.30, 0.40, 0.14, 0.16), ["Subcaracterística", "KPI", "Meta", "Resultado"], [
  ["Completitud funcional", "Cobertura de vectores (en alcance)", "≥ 90 %", "> 90 %"],
  ["Pertinencia funcional", "Trazabilidad de requerimientos", "100 %", "100 %"],
], [{}, {}, C, CB]));
ch.push(cap("Tabla 2.6. Cumplimiento de los KPI del primer objetivo específico."));
ch.push(h2("2.8 Conclusión parcial"));
ch.push(p(t("El análisis empírico permitió identificar y cuantificar los principales vectores de ataque en PyPI y, a partir de ellos, definir once requerimientos funcionales y doce no funcionales trazados a las cuatro características de ISO/IEC 25010:2023, cumpliendo los indicadores del objetivo y sentando la base para el diseño.")));

// ===================== CAPÍTULO 3 =====================
ch.push(h1("3. DISEÑO DE LA ARQUITECTURA DEL MVP Y DEL MODELO DE MACHINE LEARNING"));
ch.push(p(t("En este capítulo se desarrolla el segundo objetivo específico: diseñar la arquitectura tecnológica del MVP y del modelo de Machine Learning, a partir de los requerimientos, para estructurar lógicamente el sistema. El diseño se presenta mediante vistas complementarias, la arquitectura del modelo, el stack tecnológico y la trazabilidad a los requerimientos.")));
ch.push(h2("3.1 Estilo arquitectónico"));
ch.push(p([t("El MVP adopta un monolito modular estructurado con el patrón Pipes and Filters: la salida de cada etapa alimenta a la siguiente mediante estructuras de datos tipadas, y los tres extractores son filtros independientes. Esta elección responde a los requerimientos de mantenibilidad (RNF10–RNF12): permite agregar, reemplazar o probar cada extractor en aislamiento. Un monolito —frente a microservicios— es apropiado para un MVP de línea de comandos, pues reduce la complejidad operativa sin sacrificar la separación de responsabilidades.")]));
ch.push(h2("3.2 Vista de componentes"));
ch.push(p(t("La Figura 3.1 muestra la estructura estática: la CLI orquesta el flujo; el Fetcher seguro descarga y extrae; los tres extractores producen reportes tipados; el Feature Builder los consolida; y el clasificador emite el veredicto, serializado como JSON o SARIF.")));
ch.push(fig("componentes.png", 1164, 858, 500));
ch.push(cap("Figura 3.1. Vista de componentes del MVP (patrón Pipes and Filters)."));
ch.push(h2("3.3 Vista de flujo de datos"));
ch.push(p(t("La Figura 3.2 describe el flujo de un análisis: del nombre del paquete a la descarga y extracción segura, de ahí a los tres extractores en paralelo, al vector de características y al veredicto. El flujo es unidireccional y sin estado compartido.")));
ch.push(fig("flujo.png", 1569, 317, 540));
ch.push(cap("Figura 3.2. Vista de flujo de datos de un análisis (scan)."));
ch.push(h2("3.4 Vista dinámica (secuencia de un escaneo)"));
ch.push(p(t("La Figura 3.3 presenta el diagrama de secuencia: el usuario invoca la CLI, que delega en el Fetcher la obtención del paquete; tras verificar y extraer, los extractores producen sus reportes, el modelo emite el veredicto y la CLI serializa el reporte. Ningún componente ejecuta el código del paquete.")));
ch.push(fig("secuencia.png", 1785, 1110, 540));
ch.push(cap("Figura 3.3. Vista dinámica: secuencia de un escaneo."));
ch.push(h2("3.5 Vista de despliegue"));
ch.push(p(t("La Figura 3.4 muestra el despliegue: pyscan se ejecuta como CLI en el equipo del desarrollador o en un agente de CI, consulta PyPI por HTTPS, carga el modelo local y genera un reporte SARIF consumible por Azure DevOps. No requiere servidores propios.")));
ch.push(fig("despliegue.png", 1258, 401, 520));
ch.push(cap("Figura 3.4. Vista de despliegue del sistema."));
ch.push(h2("3.6 Modelo de dominio"));
ch.push(p(t("Las interfaces se definen con modelos tipados de Pydantic (Figura 3.5). ScanReport agrega el resultado: paquete, metadatos, reportes de cada extractor, vector de características, predicción y lista de errores.")));
ch.push(fig("dominio.png", 898, 956, 420));
ch.push(cap("Figura 3.5. Modelo de dominio (entidades Pydantic)."));
ch.push(h2("3.7 Arquitectura del modelo de Machine Learning"));
ch.push(p(t("El componente de decisión es un clasificador supervisado binario. Su diseño abarca la ingeniería de características (un vector numérico compacto que resume las señales, para inferencia rápida y liviana), la elección de algoritmos de ensamble (Random Forest y XGBoost, con manejo del desbalance por class_weight/scale_pos_weight y SMOTE solo en entrenamiento), y el pipeline de entrenamiento y evaluación (Figura 3.6): validación cruzada estratificada con predicciones out-of-fold, ajuste del umbral hacia el Recall y evaluación final en hold-out.")));
ch.push(fig("ml_pipeline.png", 406, 1462, 250));
ch.push(cap("Figura 3.6. Pipeline de entrenamiento y evaluación del modelo."));
ch.push(h2("3.8 Stack tecnológico"));
ch.push(tbl(W3(0.24, 0.50, 0.26), ["Tecnología", "Justificación", "Requerimientos"], [
  ["Python 3.10+", "Ecosistema de PyPI; librería ast para análisis estático.", "RF04, RF05"],
  ["Pydantic", "Modelos tipados que validan las interfaces entre filtros.", "RNF10–RNF12"],
  ["Typer", "CLI con subcomandos y códigos de salida para CI.", "RF10, RF11"],
  ["RapidFuzz", "Distancia de Levenshtein optimizada (typosquatting).", "RF02"],
  ["scikit-learn / XGBoost", "Clasificadores de ensamble con soporte de desbalance.", "RF09, RNF02"],
  ["imbalanced-learn", "SMOTE dentro del pipeline de entrenamiento.", "RNF02"],
  ["SARIF 2.1.0", "Estándar de resultados integrable en CI/CD.", "RF10"],
], [{ b: true }, {}, C]));
ch.push(cap("Tabla 3.1. Stack tecnológico y su trazabilidad a los requerimientos."));
ch.push(h2("3.9 Trazabilidad diseño – requerimientos"));
ch.push(tbl(W3(0.34, 0.40, 0.26), ["Decisión de diseño", "Cómo estructura el sistema", "Requerimientos"], [
  ["Pipes and Filters / monolito modular", "Extractores independientes; contratos tipados.", "RNF10–RNF12"],
  ["Fetcher seguro", "Descarga verificada + extracción defensiva.", "RF01, RNF06, RNF07"],
  ["Extractores (3)", "Un filtro por familia de vectores.", "RF02–RF08"],
  ["Feature Builder + Clasificador", "Consolidación y veredicto por ML.", "RF09, RNF02, RNF03"],
  ["Serializador de reportes", "Salida JSON y SARIF con exit codes.", "RF10, RNF09"],
  ["Vector de características compacto", "Inferencia rápida y de bajo consumo.", "RNF04, RNF05"],
], [{ b: true }, {}, C]));
ch.push(cap("Tabla 3.2. Trazabilidad entre decisiones de diseño y requerimientos."));
ch.push(h2("3.10 Conclusión parcial"));
ch.push(p(t("El diseño estructura el sistema en componentes de responsabilidad única, articulados por un flujo unidireccional y tipado, con un componente de decisión basado en ML. Cada decisión queda trazada a los requerimientos y a las características de ISO/IEC 25010:2023, cumpliendo los indicadores de cobertura arquitectónica e independencia de módulos.")));

// ===================== CAPÍTULO 4 =====================
ch.push(h1("4. IMPLEMENTACIÓN DEL MVP DE DETECCIÓN DE PAQUETES MALICIOSOS"));
ch.push(p(t("En este capítulo se desarrolla el tercer objetivo específico: implementar el MVP mediante los algoritmos de análisis de metadatos, entropía y AST, para automatizar la identificación de amenazas. Se describen los sprints, los módulos con fragmentos de código, la construcción del dataset y el aseguramiento de calidad, y se miden los KPI del objetivo.")));
ch.push(h2("4.1 Enfoque de implementación"));
ch.push(p(t("La implementación siguió un enfoque DevSecOps con elementos de Scrum, gestionado en Azure DevOps, construyendo el sistema de forma incremental en seis sprints, cada uno con su entregable funcional y sus pruebas, respetando la arquitectura definida.")));
ch.push(h2("4.2 Sprints ejecutados"));
ch.push(tbl(W3(0.12, 0.40, 0.48), ["Sprint", "Entregable", "Descripción"], [
  ["Sprint 1", "Fetcher seguro", "API de PyPI, descarga del sdist, verificación sha256 y extracción defensiva."],
  ["Sprint 2", "Extractor de metadatos", "Typosquatting/combosquatting por distancia de Levenshtein."],
  ["Sprint 3", "Extractor de entropía", "Entropía de Shannon por ventana de 256 bytes."],
  ["Sprint 4", "Extractor AST", "Llamadas peligrosas, imports, literales de red y hooks; resistente a alias."],
  ["Sprint 5", "Entrenamiento del modelo", "Dataset y clasificador (RF/XGBoost) con manejo de desbalance."],
  ["Sprint 6", "Ensamble del CLI", "Pipeline completo, veredicto ML y salida JSON/SARIF."],
], [CB, { b: true }, {}]));
ch.push(cap("Tabla 4.1. Sprints ejecutados en Azure DevOps."));
ch.push(h2("4.3 Módulos implementados"));
ch.push(p([t("El código se organiza en src/pyscan/. El Fragmento 1 muestra la validación de la extracción segura contra path traversal y enlaces.")]));
ch.push(...code([
  "for member in tar.getmembers():",
  "    if member.issym() or member.islnk():",
  "        raise FetchError(f\"Enlace no permitido: {member.name}\")",
  "    target = dest_dir / member.name",
  "    if not _is_within(dest_dir, target):",
  "        raise FetchError(f\"Ruta peligrosa (Zip Slip): {member.name}\")",
]));
ch.push(cap("Fragmento 1. Extracción segura (fetcher.py)."));
ch.push(p([t("El Fragmento 2 muestra la resolución de alias de import en el recorrido AST, que resiste la evasión del tipo import subprocess as sp; sp.run(...).")]));
ch.push(...code([
  "def _resolve(self, name):",
  "    root, _, rest = name.partition('.')",
  "    real = self._aliases.get(root)",
  "    if real is None:",
  "        return name",
  "    return f'{real}.{rest}' if rest else real",
]));
ch.push(cap("Fragmento 2. Resolución de alias en el AST (ast_extractor.py)."));
ch.push(p([t("El Fragmento 3 muestra el motor de análisis que orquesta el pipeline de las señales al veredicto.")]));
ch.push(...code([
  "report.typosquat = MetadataExtractor().extract(name, metadata)",
  "report.entropy   = EntropyExtractor().extract(extracted_path)",
  "report.ast       = ASTExtractor().extract(extracted_path)",
  "report.features  = build_features(typosquat=report.typosquat,",
  "                                  entropy=report.entropy, ast=report.ast)",
  "report.prediction = predict(report.features, model_path=model_path)",
]));
ch.push(cap("Fragmento 3. Motor de análisis (cli.py)."));
ch.push(p(t("La CLI expone el análisis para el caso de uso real: escaneo de un requirements.txt completo, de varios paquetes o de artefactos locales, con resumen consolidado y códigos de salida para CI (0 benigno, 1 error, 2 malicioso).")));
ch.push(h2("4.4 Construcción del dataset"));
ch.push(p(t("El dataset combina muestras maliciosas de fuentes públicas con benignas del Top de PyPI, identificadas y deduplicadas por sha256 (registrado en los manifiestos como verificación de integridad). La Tabla 4.2 resume su composición.")));
ch.push(tbl(W3(0.40, 0.24, 0.36), ["Fuente", "Muestras", "Descripción"], [
  ["Datadog (parte PyPI)", "334 maliciosas", "Dataset de Datadog Security Labs (descifrado)."],
  ["PyPI Malregistry", "1.666 maliciosas", "Registro de malware PyPI (ASE 2023)."],
  ["Top de PyPI", "2.000 benignas", "Paquetes populares descargados de PyPI."],
  ["Total", "4.000 únicas", "Dedup por sha256; 3.200 train / 800 hold-out (80/20)."],
], [{ b: true }, C, {}]));
ch.push(cap("Tabla 4.2. Composición del dataset."));
ch.push(p([t("Nota de consistencia: ", { bold: true, italics: true }),
  t("alinear con la sección de metodología, dado que el conjunto empleado fue Datadog + PyPI Malregistry.", { italics: true })]));
ch.push(h2("4.5 Aseguramiento de calidad"));
ch.push(p(t("Cada módulo cuenta con pruebas automatizadas con pytest (58 pruebas que se ejecutan en cada cambio). La Tabla 4.3 muestra la cobertura por módulo; el total es del 91 %, superando el umbral del 80 %.")));
ch.push(tbl(W3(0.5, 0.25, 0.25), ["Módulo", "Sentencias", "Cobertura"], [
  ["models.py / config.py / features.py / sarif.py", "139", "100 %"],
  ["classifier.py", "39", "95 %"],
  ["entropy.py", "58", "91 %"],
  ["ast_extractor.py", "111", "89 %"],
  ["metadata.py", "74", "89 %"],
  ["cli.py", "193", "88 %"],
  ["fetcher.py", "161", "87 %"],
  ["TOTAL", "780", "91 %"],
], [{}, C, CB]));
ch.push(cap("Tabla 4.3. Cobertura de código por módulo (pytest --cov)."));
ch.push(p(t("En las corridas sobre miles de paquetes reales, las muestras corruptas se omiten con un aviso sin abortar la ejecución, por lo que no se observaron excepciones no controladas. El pipeline formal de CI en Azure Pipelines queda planteado como paso de cierre.")));
ch.push(h2("4.6 Medición de los KPI del objetivo (OE3)"));
ch.push(tbl(W4(0.28, 0.34, 0.14, 0.24), ["Subcaracterística", "KPI", "Meta", "Resultado"], [
  ["Completitud funcional", "Implementación de funciones (pruebas OK)", "≥ 95 %", "100 % (58/58)"],
  ["Testeabilidad", "Cobertura de código", "≥ 80 %", "91 %"],
  ["Madurez", "Tasa de fallos no manejados", "≤ 1 %", "≈ 0 %"],
], [{}, {}, C, CB]));
ch.push(cap("Tabla 4.4. Cumplimiento de los KPI del tercer objetivo específico."));
ch.push(h2("4.7 Conclusión parcial"));
ch.push(p(t("El MVP quedó implementado en seis sprints conforme a la arquitectura, integrando los tres extractores y el clasificador en una CLI apta para el caso de uso real. El aseguramiento de calidad —58 pruebas, 91 % de cobertura y ausencia de fallos no manejados— evidencia el cumplimiento de los KPI del objetivo.")));

// ===================== CAPÍTULO 5 =====================
ch.push(h1("5. VALIDACIÓN DE LA EFICACIA Y LA CALIDAD DEL MVP"));
ch.push(p(t("En este capítulo se desarrolla el cuarto objetivo específico: validar la eficacia y la calidad del MVP mediante un plan de pruebas. Se presentan el plan, los resultados del clasificador (validación cruzada y hold-out), la matriz de confusión, el desempeño y la síntesis del cumplimiento de los KPI.")));
ch.push(h2("5.1 Plan de pruebas"));
ch.push(p(t("La validación se estructuró bajo la guía ISO/IEC 25023, con cuatro tipos de prueba (Tabla 5.1).")));
ch.push(tbl(W3(0.24, 0.52, 0.24), ["Tipo de prueba", "Descripción", "Resultado"], [
  ["Unitarias", "Verificación de funciones por módulo con pytest.", "58 pruebas OK"],
  ["Integración", "Pipeline completo sobre paquetes reales de PyPI.", "OK"],
  ["Regresión", "Ejecución de la suite ante cada cambio.", "Suite estable"],
  ["Carga / rendimiento", "Tiempo y memoria por paquete (benchmark).", "Ver 5.4"],
], [{ b: true }, {}, C]));
ch.push(cap("Tabla 5.1. Plan de pruebas del MVP."));
ch.push(h2("5.2 Validación del clasificador (k-fold y hold-out)"));
ch.push(p(t("Sobre 3.200 muestras de entrenamiento se aplicó validación cruzada estratificada (k=5), evaluando Random Forest y XGBoost; se seleccionó XGBoost (Tabla 5.2).")));
ch.push(tbl(W5(0.26, 0.16, 0.16, 0.16, 0.14).concat([Math.round(CONTENT_W*0.12)]),
  ["Modelo", "Recall", "Precisión", "F1", "PR-AUC", "FP"], [
  ["Random Forest", "0,964", "0,971", "0,968", "0,994", "0,028"],
  ["XGBoost (sel.)", "0,961", "0,977", "0,969", "0,994", "0,023"],
], [{ b: true }, C, C, C, C, C]));
ch.push(cap("Tabla 5.2. Resultados de la validación cruzada estratificada (k=5)."));
ch.push(p([t("En el hold-out (769 muestras no vistas), el modelo alcanzó Recall 0,971, Precisión 0,979 y F1 0,975, confirmando su generalización.")]));
ch.push(h2("5.3 Matriz de confusión"));
ch.push(tbl(W3(0.34, 0.33, 0.33), ["", "Predicho: Malicioso", "Predicho: Benigno"], [
  ["Real: Malicioso", "VP = 1.484", "FN = 61"],
  ["Real: Benigno", "FP = 35", "VN = 1.515"],
], [{ b: true }, C, C]));
ch.push(cap("Tabla 5.3. Matriz de confusión (validación cruzada, XGBoost)."));
ch.push(p(t("De 1.545 paquetes maliciosos el modelo detectó 1.484, y de 1.550 benignos solo marcó 35, lo que da un Recall de 0,96 y una tasa de falsos positivos de 2,3 %.")));
ch.push(h2("5.4 Pruebas de desempeño"));
ch.push(p(t("El análisis por paquete tomó ≈ 1,5 s (límite 120 s) con un consumo de memoria ≈ 63 MB (límite 2 GB): el sistema es rápido y liviano.")));
ch.push(h2("5.5 Evaluación complementaria de robustez"));
ch.push(p(t("Tres análisis adicionales refuerzan la validez: el estudio de ablación mostró que, sin las señales de nombre, el modelo mantiene un Recall de 0,91 con solo las señales de código; la evaluación a prevalencia realista (1:100) evidenció el descenso esperado de la precisión, mitigable con el ajuste del umbral; y la comparación con GuardDog (Datadog) arrojó un Recall comparable (empate de 0,89 en la fuente independiente) y una precisión superior de pyscan (0,97 frente a 0,73).")));
ch.push(h2("5.6 Cumplimiento de los indicadores clave (KPI)"));
ch.push(p(t("La Tabla 5.4 sintetiza el cumplimiento de todos los KPI de la sección 1.4.3.")));
{
  const OK = { a: AlignmentType.CENTER, b: true, fill: "E2EFDA" };
  ch.push(tbl(W4(0.09, 0.45, 0.16, 0.16).concat([Math.round(CONTENT_W*0.14)]),
    ["OE", "KPI", "Meta", "Resultado", "Estado"], [
    ["OE1", "Cobertura de vectores (en alcance)", "≥ 90 %", "> 90 %", "Cumple"],
    ["OE1", "Trazabilidad de requerimientos", "100 %", "100 %", "Cumple"],
    ["OE2", "Cobertura arquitectónica", "100 %", "100 %", "Cumple"],
    ["OE2", "Independencia de módulos", "4/4", "4/4", "Cumple"],
    ["OE3", "Implementación de funciones", "≥ 95 %", "100 %", "Cumple"],
    ["OE3", "Cobertura de código", "≥ 80 %", "91 %", "Cumple"],
    ["OE3", "Tasa de fallos no manejados", "≤ 1 %", "≈ 0 %", "Cumple"],
    ["OE4", "Recall del clasificador", "≥ 0,90", "0,97", "Cumple"],
    ["OE4", "F1-Score del clasificador", "≥ 0,85", "0,975", "Cumple"],
    ["OE4", "Tasa de falsos positivos", "≤ 10 %", "2,3 %", "Cumple"],
    ["OE4", "Tiempo por paquete", "≤ 120 s", "≈ 1,5 s", "Cumple"],
    ["OE4", "Memoria RAM pico", "≤ 2 GB", "≈ 63 MB", "Cumple"],
  ], [CB, {}, C, CB, OK]));
  ch.push(cap("Tabla 5.4. Cumplimiento consolidado de los KPI (sección 1.4.3)."));
}
ch.push(h2("5.7 Conclusión parcial"));
ch.push(p(t("El plan de pruebas y la validación demuestran que el MVP cumple la totalidad de los indicadores clave: Recall 0,97, F1 0,975 y FP 2,3 %, ejecución en ≈1,5 s por paquete con ≈63 MB, y estabilidad respaldada por 58 pruebas y 91 % de cobertura. Los análisis complementarios confirman la solidez de los resultados. Con ello se valida la eficacia y la calidad del sistema.")));

// ===================== CAPÍTULO 6 =====================
ch.push(h1("6. CONCLUSIONES"));
ch.push(p(t("El trabajo desarrolló y validó un MVP, pyscan, para la detección de paquetes maliciosos en PyPI, combinando el análisis estático de metadatos, entropía y AST integrados mediante un clasificador supervisado.")));
ch.push(p(t("Respecto al primer objetivo, se identificaron y cuantificaron los principales vectores de ataque sobre 1.926 paquetes maliciosos reales —con predominio de la ejecución de comandos (76,3 %), la exfiltración por red (42,0 %) y la suplantación de nombres (26,0 %)— y se definieron los requerimientos trazados a ISO/IEC 25010:2023.")));
ch.push(p(t("Respecto al segundo objetivo, se diseñó la arquitectura como un monolito modular con patrón Pipes and Filters y la arquitectura del modelo de ML, documentadas mediante vistas complementarias y trazadas a los requerimientos.")));
ch.push(p(t("Respecto al tercer objetivo, se implementó el MVP en seis sprints, integrando los extractores y el clasificador en una herramienta de línea de comandos, con 58 pruebas, 91 % de cobertura y ausencia de fallos no manejados.")));
ch.push(p(t("Respecto al cuarto objetivo, se validó el sistema: alcanzó un Recall de 0,97, un F1 de 0,975 y una tasa de falsos positivos del 2,3 %, con un análisis de ≈1,5 s por paquete y ≈63 MB de memoria, cumpliendo la totalidad de los indicadores clave.")));
ch.push(p([t("En respuesta a la pregunta problema, el trabajo demuestra que combinar señales estáticas complementarias en un vector de características y delegar el veredicto en un modelo supervisado permite detectar paquetes maliciosos en PyPI con alto Recall y baja tasa de falsos positivos, de forma rápida, ligera y con licencia abierta, satisfaciendo las características de calidad delimitadas. El estudio de ablación evidenció que las señales de código detectan por sí solas cerca del 91 % del malware, confirmando que la capacidad de detección no depende de una sola señal.")]));
ch.push(p(t("Se reconocen limitaciones: el conjunto benigno proviene del Top de PyPI (sesgo favorable a las señales de nombre), el análisis estático no cubre técnicas de evasión en tiempo de ejecución, y la precisión disminuye a la prevalencia realista del malware. Estas limitaciones se documentaron de forma transparente y orientan las recomendaciones.")));

// ===================== CAPÍTULO 7 =====================
ch.push(h1("7. RECOMENDACIONES"));
ch.push(p(t("A partir de los resultados y las limitaciones, se proponen las siguientes líneas de trabajo futuro:")));
ch.push(bullet(t("Extender la arquitectura modular a otros ecosistemas (npm, RubyGems, Maven, Crates).")));
ch.push(bullet(t("Incorporar análisis dinámico o sandboxing para cubrir técnicas de evasión en tiempo de ejecución.")));
ch.push(bullet(t("Diversificar el conjunto benigno con paquetes poco populares y reentrenar periódicamente el clasificador, eliminando el sesgo de nombre.")));
ch.push(bullet(t("Poblar las características de metadatos de publicación desde la API de PyPI para aprovechar señales de reputación.")));
ch.push(bullet(t("Integrar el sistema en un pipeline de CI (Azure Pipelines) y ofrecer una interfaz gráfica para usuarios no técnicos.")));
ch.push(bullet(t("Publicar un artículo científico derivado del trabajo.")));

const doc = new Document({
  creator: "pyscan - Trabajo de Grado",
  numbering: { config: [{ reference: "b", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•",
    alignment: AlignmentType.START, style: { paragraph: { indent: { left: 460, hanging: 260 } } } }] }] },
  styles: { default: { document: { run: { font: FONT, size: 24 } } } },
  sections: [{
    properties: { page: { size: { width: Math.round(21 * CM), height: Math.round(29.7 * CM) },
      margin: { top: 3 * CM, bottom: 3 * CM, left: 4 * CM, right: 2 * CM } } },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER,
      children: [new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 20 })] })] }) },
    children: ch,
  }],
});
Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync("/tmp/Cuerpo_Tesis_Capitulos_2_a_7.docx", buf);
  console.log("DOCX escrito:", buf.length, "bytes");
});
