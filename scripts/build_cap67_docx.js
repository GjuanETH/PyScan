// Capítulos 6 (Conclusiones) y 7 (Recomendaciones). NTC 1486.
const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  PageNumber, Footer, LevelFormat,
} = require("docx");

const FONT = "Arial";
const CM = 567;

const t = (text, opts = {}) => new TextRun({ text, font: FONT, size: 24, ...opts });
const p = (runs, opts = {}) => new Paragraph({
  spacing: { line: 360, after: 120 }, alignment: AlignmentType.JUSTIFIED,
  children: Array.isArray(runs) ? runs : [runs], ...opts });
const h1 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 160 },
  children: [new TextRun({ text, font: FONT, size: 28, bold: true })] });
const h2 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 200, after: 120 },
  children: [new TextRun({ text, font: FONT, size: 24, bold: true })] });
const bullet = (runs) => new Paragraph({
  numbering: { reference: "recos", level: 0 },
  spacing: { line: 340, after: 100 }, alignment: AlignmentType.JUSTIFIED,
  children: Array.isArray(runs) ? runs : [runs] });

const children = [];

// ================= 6. CONCLUSIONES =================
children.push(h1("6. CONCLUSIONES"));
children.push(p(t("El trabajo desarrolló y validó un Producto Mínimo Viable, pyscan, para la detección de paquetes maliciosos en el ecosistema PyPI, combinando el análisis estático de metadatos, la evaluación de entropía y el recorrido de árboles de sintaxis abstracta, integrados mediante un clasificador supervisado de Machine Learning. A continuación se presentan las conclusiones por cada objetivo específico y la respuesta a la pregunta problema.")));

children.push(h2("6.1 Sobre el primer objetivo"));
children.push(p(t("Se identificaron y cuantificaron empíricamente los principales vectores de ataque en PyPI mediante scripts de análisis sobre un corpus de 1.926 paquetes maliciosos reales. El análisis mostró el predominio de la ejecución de comandos y código (76,3 %), la exfiltración por red (42,0 %) y la suplantación de nombres (26,0 %), y que casi la mitad de las muestras combina dos o más vectores. A partir de esta evidencia se definieron once requerimientos funcionales y doce no funcionales, trazados a las cuatro características de calidad de ISO/IEC 25010:2023 delimitadas, cumpliendo los indicadores del objetivo.")));

children.push(h2("6.2 Sobre el segundo objetivo"));
children.push(p(t("Se diseñó la arquitectura tecnológica del MVP como un monolito modular con patrón Pipes and Filters, y la arquitectura del modelo de Machine Learning con su ingeniería de características, algoritmos y pipeline de entrenamiento. El diseño se documentó mediante vistas complementarias (componentes, flujo de datos, secuencia, despliegue y modelo de dominio) y se trazó de forma completa a los requerimientos, satisfaciendo los indicadores de cobertura arquitectónica e independencia de módulos.")));

children.push(h2("6.3 Sobre el tercer objetivo"));
children.push(p(t("Se implementó el MVP en seis sprints gestionados en Azure DevOps, integrando los tres extractores estáticos y el clasificador en una herramienta de línea de comandos apta para el caso de uso real: el análisis de las dependencias de un proyecto. La calidad del código se respaldó con 58 pruebas automatizadas, una cobertura del 91 % y la ausencia de fallos no manejados, superando los indicadores del objetivo.")));

children.push(h2("6.4 Sobre el cuarto objetivo"));
children.push(p(t("Se validó la eficacia y la calidad del MVP mediante un plan de pruebas. El clasificador alcanzó un Recall de 0,97, un F1-Score de 0,975 y una tasa de falsos positivos del 2,3 %, y el sistema completó el análisis en aproximadamente 1,5 segundos por paquete con un consumo de memoria cercano a 63 MB. La totalidad de los indicadores clave definidos al inicio del proyecto se cumplió. Análisis complementarios de ablación, de prevalencia realista y de comparación con la herramienta GuardDog confirmaron la robustez de los resultados y su interpretación honesta.")));

children.push(h2("6.5 Respuesta a la pregunta problema"));
children.push(p(t("La pregunta problema indagaba de qué manera un MVP basado en análisis de metadatos, entropía y AST, integrados mediante un clasificador supervisado, permite detectar paquetes maliciosos en PyPI bajo los criterios de calidad de ISO/IEC 25010:2023. El trabajo demuestra que esta combinación es viable y eficaz: al consolidar señales estáticas complementarias en un vector de características y delegar el veredicto en un modelo supervisado, el MVP identifica paquetes maliciosos con alto Recall y baja tasa de falsos positivos, de forma rápida, ligera y con licencia abierta, satisfaciendo las características de adecuación funcional, eficiencia de desempeño, fiabilidad y mantenibilidad delimitadas de la norma. El estudio de ablación evidenció, además, que las señales de código detectan por sí solas cerca del 91 % del malware, lo que confirma que la capacidad de detección no depende de una única señal.")));

children.push(h2("6.6 Consideraciones sobre la validez"));
children.push(p(t("Se reconocen limitaciones que acotan el alcance de las conclusiones. El conjunto benigno proviene del Top de PyPI, la misma lista usada como referencia de nombres, lo que introduce un sesgo favorable a las señales de nombre; el análisis estático no cubre técnicas de evasión en tiempo de ejecución; y, a la prevalencia realista del malware, la precisión disminuye, como en cualquier detector de eventos raros. Estas limitaciones se documentaron de forma transparente y orientan las recomendaciones.")));

// ================= 7. RECOMENDACIONES =================
children.push(h1("7. RECOMENDACIONES"));
children.push(p(t("A partir de los resultados y las limitaciones identificadas, se proponen las siguientes líneas de trabajo futuro:")));
children.push(bullet(t("Extender la arquitectura modular a otros ecosistemas de paquetes (npm, RubyGems, Maven, Crates), aprovechando la independencia de los extractores.")));
children.push(bullet(t("Incorporar análisis dinámico o ejecución en entornos aislados (sandboxing) para cubrir las técnicas de evasión que solo se manifiestan en tiempo de ejecución.")));
children.push(bullet(t("Diversificar el conjunto benigno con paquetes poco populares y fuera de la lista de referencia, y reentrenar periódicamente el clasificador, para eliminar el sesgo de nombre y mantener el modelo actualizado frente a nuevas campañas.")));
children.push(bullet(t("Poblar las características de metadatos de publicación desde la API de PyPI durante la construcción del dataset, de modo que el modelo aproveche también las señales de reputación.")));
children.push(bullet(t("Integrar el sistema en un pipeline de integración continua (Azure Pipelines) y ofrecer una interfaz gráfica que facilite su adopción por usuarios no técnicos.")));
children.push(bullet(t("Publicar un artículo científico derivado del trabajo, dado el valor de la evidencia empírica sobre vectores de ataque y de la comparación con el estado del arte.")));

const doc = new Document({
  creator: "pyscan - Trabajo de Grado",
  numbering: { config: [{ reference: "recos", levels: [{
    level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.START,
    style: { paragraph: { indent: { left: 460, hanging: 260 } } } }] }] },
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
  fs.writeFileSync("/tmp/Capitulos6y7_Conclusiones_Recomendaciones.docx", buf);
  console.log("DOCX escrito:", buf.length, "bytes");
});
