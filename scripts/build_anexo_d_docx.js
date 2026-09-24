// Anexo D — Evidencia del Product Backlog en Azure DevOps (plantilla para insertar capturas).
const { p, h1, title, caption, source, save, t } = require("./anexos_common");
const { Paragraph, AlignmentType, BorderStyle, TextRun } = require("docx");
const hueco = (txt) => new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 120, after: 120 },
  border: { top: { style: BorderStyle.DASHED, size: 6, color: "999999" }, bottom: { style: BorderStyle.DASHED, size: 6, color: "999999" },
    left: { style: BorderStyle.DASHED, size: 6, color: "999999" }, right: { style: BorderStyle.DASHED, size: 6, color: "999999" } },
  children: [new TextRun({ text: `[INSERTAR CAPTURA: ${txt}]`, font: "Arial", size: 22, bold: true, color: "C00000" })] });
const c = [];
c.push(...title("ANEXO D", "EVIDENCIA DE LA GESTIÓN DEL PROYECTO Y DEL REPOSITORIO"));
c.push(p("Este anexo presenta la evidencia de la gestión del proyecto citada en la sección 2.6. La planificación se llevó en Azure Boards (organización jdgutierrez017, proyecto Tesis) con la plantilla de proceso Basic: el Product Backlog se organizó en cinco épicas, una por fase del trabajo, desglosadas en issues y tareas, y se definieron cinco iteraciones, una por fase. Al cierre, cada tarea quedó con su estado final y, cuando correspondió, con la etiqueta «parcial» o «descartado» y un comentario que explica la decisión, de modo que el tablero refleja el alcance realmente implementado. El código se publicó en un repositorio abierto de GitHub con integración continua."));
const items = [
  ["D.1 Product Backlog por fases", "Figura D.1. Product Backlog en Azure Boards: épicas por fase, issues y tareas.", "Azure Boards > Backlogs, nivel Epics expandido (Fases 1 a 5)"],
  ["D.2 Estado final y decisiones de alcance", "Figura D.2. Tareas con etiqueta «parcial» o «descartado» y su comentario de cierre.", "una tarea descartada abierta (p. ej. «Programar Agregador de Scores ponderado») mostrando etiqueta y comentario"],
  ["D.3 Iteraciones", "Figura D.3. Iteraciones del proyecto (Fase 1 a Fase 5) con sus fechas.", "Project settings > Boards > Project configuration > Iterations"],
  ["D.4 Repositorio público e integración continua", "Figura D.4. Repositorio en GitHub con la ejecución de la integración continua en verde.", "https://github.com/GjuanETH/PyScan > pestaña Actions con la última ejecución de CI"],
];
for (const [h, cap, hint] of items) { c.push(h1(h)); c.push(caption(cap)); c.push(hueco(hint)); c.push(source()); }
save(c, "Anexo_D_Evidencia_gestion_y_repositorio.docx");
