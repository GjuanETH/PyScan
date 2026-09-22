// Anexo D — Evidencia del Product Backlog en Azure DevOps (plantilla para insertar capturas).
const { p, h1, title, caption, source, save, t } = require("./anexos_common");
const { Paragraph, AlignmentType, BorderStyle, TextRun } = require("docx");
const hueco = (txt) => new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 120, after: 120 },
  border: { top: { style: BorderStyle.DASHED, size: 6, color: "999999" }, bottom: { style: BorderStyle.DASHED, size: 6, color: "999999" },
    left: { style: BorderStyle.DASHED, size: 6, color: "999999" }, right: { style: BorderStyle.DASHED, size: 6, color: "999999" } },
  children: [new TextRun({ text: `[INSERTAR CAPTURA: ${txt}]`, font: "Arial", size: 22, bold: true, color: "C00000" })] });
const c = [];
c.push(...title("ANEXO D", "EVIDENCIA DEL PRODUCT BACKLOG EN AZURE DEVOPS"));
c.push(p("Este anexo presenta la evidencia de la gestión del proyecto en Azure DevOps (organización jdgutierrez017, proyecto Tesis), citada en la sección 2.6: el Product Backlog con historias de usuario y criterios de aceptación, los sprints ejecutados y el repositorio de código."));
const items = [
  ["D.1 Product Backlog", "Figura D.1. Product Backlog con historias de usuario (Azure Boards).", "vista Backlogs de Azure Boards con las historias de usuario y su estado"],
  ["D.2 Criterios de aceptación", "Figura D.2. Detalle de una historia de usuario con criterios de aceptación.", "una historia abierta mostrando descripción y criterios de aceptación"],
  ["D.3 Sprints ejecutados", "Figura D.3. Sprints del proyecto (Azure Boards).", "vista Sprints / Taskboard o la lista de iteraciones"],
  ["D.4 Repositorio y trazabilidad", "Figura D.4. Historial de commits del repositorio (Azure Repos).", "Azure Repos > Commits del repositorio Tesis"],
];
for (const [h, cap, hint] of items) { c.push(h1(h)); c.push(caption(cap)); c.push(hueco(hint)); c.push(source()); }
save(c, "Anexo_D_Evidencia_backlog_Azure_DevOps.docx");
