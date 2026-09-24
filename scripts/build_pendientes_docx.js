// Textos pendientes de la tesis (listos para pegar). Salida: carpeta "Trabajo de Grado (1)".
const path = require("path");
const fs = require("fs");
const C = require("./anexos_common");
const { t, p, h1, h2, bullet, caption, source, save } = C;
const { Paragraph, TextRun, AlignmentType, ImageRun, BorderStyle, ShadingType } = require("docx");

// Nota de ubicación (gris, no se pega)
const nota = (txt) => new Paragraph({ spacing: { before: 60, after: 160 },
  shading: { type: ShadingType.CLEAR, fill: "F2F2F2", color: "auto" },
  border: { left: { style: BorderStyle.SINGLE, size: 12, color: "1F3864", space: 6 } },
  children: [new TextRun({ text: txt, font: "Arial", size: 20, italics: true, color: "404040" })] });
const bloque = (titulo) => new Paragraph({ spacing: { before: 360, after: 80 }, pageBreakBefore: true,
  children: [new TextRun({ text: titulo, font: "Arial", size: 26, bold: true, color: "1F3864" })] });
// párrafo con *cursiva* y ^superíndice^
function pr(text) {
  const runs = [];
  for (const part of text.split(/(\*[^*]+\*|\^[^^]+\^)/)) {
    if (!part) continue;
    if (part.startsWith("*")) runs.push(t(part.slice(1, -1), { italics: true }));
    else if (part.startsWith("^")) runs.push(t(part.slice(1, -1), { superScript: true }));
    else runs.push(t(part));
  }
  return p(runs);
}
const IMG = path.resolve(__dirname, "..", "docs", "diagrams", "marco_conceptual.png");
function figura(file, w = 430) {
  const buf = fs.readFileSync(file); const iw = buf.readUInt32BE(16), ih = buf.readUInt32BE(20);
  return new Paragraph({ alignment: AlignmentType.CENTER, children: [new ImageRun({ type: "png", data: buf,
    transformation: { width: w, height: Math.round(ih * w / iw) } })] });
}

const c = [];
c.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 120 },
  children: [new TextRun({ text: "TEXTOS PENDIENTES DEL TRABAJO DE GRADO", font: "Arial", size: 28, bold: true })] }));
c.push(nota("Cada bloque indica dónde va. Lo que está en recuadro gris son instrucciones y no se pega. Las cifras provienen de data/models/metrics.json y data/analysis/*.json (modelo Random Forest). Los superíndices usan la numeración de referencias que ya tiene la tesis."));

// ---------------- RESUMEN ----------------
c.push(bloque("1. RESUMEN"));
c.push(nota("Reemplaza los tres párrafos actuales del RESUMEN y la nota [PENDIENTE]. Extensión: 316 palabras sin las palabras clave (límite 500)."));
c.push(pr("El desarrollo de software actual se apoya en paquetes de terceros descargados de repositorios públicos como PyPI, y esa confianza se convirtió en un vector de ataque: basta con publicar un paquete de nombre parecido al de uno popular, o con código que se ejecuta durante la instalación, para comprometer los equipos que lo incorporan. Este trabajo presenta pyscan, un producto mínimo viable (MVP) de código abierto que detecta paquetes maliciosos de PyPI sin ejecutarlos. La herramienta extrae tres familias de señales estáticas —la distancia de Levenshtein entre el nombre del paquete y los más descargados, la entropía de Shannon calculada por ventanas y el recorrido del árbol de sintaxis abstracta (AST)— y las reúne en un vector de nueve características que clasifica un modelo Random Forest."));
c.push(pr("El modelo se entrenó con 3.475 paquetes (1.545 maliciosos de Datadog y PyPI Malregistry, y 1.930 benignos del Top de PyPI y de una muestra aleatoria del índice) y se evaluó sobre 866 paquetes no vistos, donde alcanzó un *Recall* de 0,945, una precisión de 0,921 y un F1 de 0,933; en validación cruzada la tasa de falsos positivos fue del 6,1 %. Sobre las mismas 300 muestras, pyscan detectó más malware que GuardDog (*Recall* de 0,880 frente a 0,827) con cerca de seis veces menos falsas alarmas, mientras que el antivirus ClamAV no identificó ninguna muestra. Cada paquete se analizó en 0,91 s de media, con 353 MB de memoria."));
c.push(pr("El proyecto siguió DevSecOps con elementos de Scrum y QA/QC, se gestionó en Azure DevOps y se publicó en GitHub con integración continua. La calidad se verificó frente a cuatro características de la norma ISO/IEC 25010:2023 y se cumplieron todos los indicadores definidos. Cuando la proporción de paquetes maliciosos es la del mundo real, la precisión desciende, de modo que la herramienta resulta adecuada para priorizar los paquetes que requieren revisión dentro de un flujo de integración continua."));
c.push(pr("PALABRAS CLAVE: análisis estático, aprendizaje automático, cadena de suministro de software, código abierto, detección de anomalías, seguridad informática."));
c.push(nota("Las palabras clave se dejaron como estaban. Falta validarlas contra un tesauro (UNESCO o IEEE), como pide la nota original; «detección de anomalías» describe mal un clasificador supervisado y convendría cambiarla por «software malicioso» si el tesauro lo admite."));

// ---------------- ABSTRACT ----------------
c.push(bloque("2. ABSTRACT"));
c.push(nota("Reemplaza la nota [PENDIENTE] del ABSTRACT. Es la traducción del resumen anterior."));
c.push(pr("Modern software development relies on third-party packages downloaded from public repositories such as PyPI, and that trust has become an attack vector: publishing a package whose name resembles a popular one, or whose code runs at installation time, is enough to compromise the teams that adopt it. This work presents pyscan, an open-source minimum viable product (MVP) that detects malicious PyPI packages without executing them. The tool extracts three families of static signals —the Levenshtein distance between the package name and the most downloaded packages, window-based Shannon entropy, and abstract syntax tree (AST) traversal— and combines them into a nine-feature vector classified by a Random Forest model."));
c.push(pr("The model was trained on 3,475 packages (1,545 malicious packages from Datadog and PyPI Malregistry, and 1,930 benign packages from the PyPI top list and a random sample of the index) and evaluated on 866 unseen packages, where it reached a recall of 0.945, a precision of 0.921 and an F1 score of 0.933; under cross-validation the false positive rate was 6.1%. On the same 300 samples, pyscan detected more malware than GuardDog (recall 0.880 versus 0.827) with about six times fewer false alarms, while the ClamAV antivirus identified none. Each package was analyzed in 0.91 s on average using 353 MB of memory."));
c.push(pr("The project followed DevSecOps with Scrum and QA/QC elements, was managed in Azure DevOps and published on GitHub with continuous integration. Quality was verified against four characteristics of ISO/IEC 25010:2023 and every defined indicator was met. When the share of malicious packages matches real-world conditions, precision drops, so the tool is best suited to prioritizing packages for review within a continuous integration pipeline."));
c.push(pr("KEYWORDS: anomaly detection, computer security, machine learning, open source software, software supply chain, static analysis."));

// ---------------- INTRODUCCIÓN ----------------
c.push(bloque("3. INTRODUCCIÓN"));
c.push(nota("Reemplaza todo el texto actual de la INTRODUCCIÓN (cuatro bloques y viñetas) y la nota [PENDIENTE]. Tres párrafos, 396 palabras. Se conservan las referencias 10, 12, 18, 22, 42 y 48 que ya citaba la introducción."));
c.push(pr("Más del 90 % del código de una aplicación moderna proviene de librerías externas alojadas en ecosistemas como PyPI^10^. Los atacantes ya lo aprovechan: en lugar de atacar el producto final, comprometen su cadena de suministro con paquetes que suplantan nombres conocidos, ejecutan código al instalarse u ocultan cargas ofuscadas. Casos como SolarWinds^12^ y XZ Utils^22^ mostraron que las defensas habituales, basadas en firmas o en el perímetro, no bastan frente a código malicioso que llega por canales legítimos, y el OWASP Top 10 de 2025 elevó este riesgo a la categoría A03^18^. Para equipos pequeños, que no pueden costear plataformas comerciales ni infraestructura de análisis dinámico, el problema es todavía más difícil de atender."));
c.push(pr("Este trabajo desarrolla pyscan, un producto mínimo viable (MVP) de código abierto que detecta paquetes maliciosos de PyPI con análisis estático, es decir, sin ejecutarlos. La herramienta combina tres señales —distancia de Levenshtein sobre el nombre, entropía de Shannon por ventanas y recorrido del árbol de sintaxis abstracta— en un vector de características que clasifica un modelo supervisado. Se compararon Random Forest y XGBoost y se descartaron los modelos de lenguaje y las arquitecturas multiagente por su costo computacional y su dependencia de servicios externos. El modelo se entrenó con muestras maliciosas de Datadog y PyPI Malregistry y con benignas del Top de PyPI y de una muestra aleatoria del índice. El proyecto siguió DevSecOps con elementos de Scrum y QA/QC, se gestionó en Azure DevOps y se publicó en GitHub con licencia MIT, en línea con las medidas de gestión de riesgos de seguridad digital del Decreto 1078 de 2015^42^ y con la Estrategia Nacional de Seguridad Digital 2025-2027^48^."));
c.push(pr("El documento se organiza en siete capítulos. El capítulo 1 presenta el problema, los objetivos, los marcos de referencia y la metodología. Los capítulos 2 a 5 desarrollan los cuatro objetivos específicos: la identificación de los vectores de ataque y de los requerimientos bajo ISO/IEC 25010:2023, el diseño de la arquitectura del MVP y del modelo, su implementación y la validación de su eficacia y calidad, que incluye un estudio de ablación, la evaluación a prevalencia realista y la comparación con GuardDog, ClamAV y VirusTotal. Los capítulos 6 y 7 recogen las conclusiones y las recomendaciones, y los anexos reúnen la evidencia de gestión, el manejo de los datos, los análisis completos del modelo y los manuales técnico y de usuario."));

// ---------------- ODS ----------------
c.push(bloque("4. SECCIÓN 1.3.1 — APORTE A LOS ODS"));
c.push(nota("Reemplaza la nota [PENDIENTE] de la sección 1.3.1. Texto de las metas tomado de la página oficial de Naciones Unidas. Se propone el ODS 9 con la meta 9.5 como principal y la 9.1 como complementaria; se descartó la meta 16.6 porque la relación con este trabajo es indirecta."));
c.push(pr("El trabajo contribuye al Objetivo de Desarrollo Sostenible 9, «Industria, innovación e infraestructura», y en particular a la meta 9.5: «Aumentar la investigación científica y mejorar la capacidad tecnológica de los sectores industriales de todos los países, en particular los países en desarrollo, entre otras cosas fomentando la innovación [...]». pyscan es un resultado de investigación aplicada, de código abierto y reproducible, que pone al alcance de equipos de desarrollo colombianos una capacidad de detección que hoy se concentra en productos comerciales."));
c.push(pr("De forma complementaria, el trabajo se relaciona con la meta 9.1, que busca «desarrollar infraestructuras fiables, sostenibles, resilientes y de calidad [...] para apoyar el desarrollo económico y el bienestar humano». Los repositorios de paquetes y las cadenas de integración continua son hoy parte de la infraestructura digital sobre la que operan empresas y entidades públicas; detectar paquetes maliciosos antes de que entren a un proyecto reduce el riesgo de que esa infraestructura se convierta en la vía de un incidente."));

// ---------------- LÍNEA DE INVESTIGACIÓN ----------------
c.push(bloque("5. SECCIÓN 1.3.2 — LÍNEA DE INVESTIGACIÓN"));
c.push(nota("Reemplaza la nota [PENDIENTE] de la sección 1.3.2. No encontré publicadas las líneas de investigación oficiales del programa. En la ponencia de ustedes aparece «Línea: Gestión y Tecnología»; confirma con el director el nombre exacto antes de pegar y ajusta el texto entre corchetes."));
c.push(pr("El proyecto se inscribe en la línea de investigación [Gestión y Tecnología — confirmar nombre exacto] del programa de Ingeniería de Sistemas y Computación de la Universidad Católica de Colombia. Su aporte a la línea consiste en aplicar técnicas de análisis estático y aprendizaje automático a un problema de gestión del riesgo tecnológico, la seguridad de la cadena de suministro de software, y en entregar un artefacto verificable: una herramienta de código abierto, un conjunto de datos documentado y un protocolo de evaluación reproducible."));
c.push(pr("El trabajo también responde a la política pública nacional. El CONPES 3995 de 2020^44^ define como objetivo fortalecer las capacidades de seguridad digital de los ciudadanos y de los sectores público y privado, y la Estrategia Nacional de Seguridad Digital 2025-2027^48^ mantiene ese horizonte; una herramienta gratuita que se integra al ciclo de desarrollo contribuye a esa capacidad en los equipos que construyen software en el país."));

// ---------------- MARCO CONCEPTUAL ----------------
c.push(bloque("6. SECCIÓN 1.5.1 — FIGURA DEL MARCO CONCEPTUAL"));
c.push(nota("Va al final de la sección 1.5.1 (Marco Conceptual), en lugar de la nota [PENDIENTE]. La imagen también está en pyscan/docs/diagrams/marco_conceptual.png (fuente .dot editable). Si se numeran las figuras del capítulo 1, esta es la Figura 1.1."));
c.push(pr("La Figura 1.1 articula los conceptos del marco con los objetivos del trabajo. La cadena de suministro de software expone a los proyectos a paquetes maliciosos cuyos vectores de ataque se identifican en el primer objetivo; esos vectores son detectables con análisis estático a partir de tres señales que, consolidadas en un vector de características, alimentan el clasificador supervisado diseñado en el segundo objetivo e implementado en el tercero. El veredicto se integra en el flujo DevSecOps y su calidad se evalúa en el cuarto objetivo frente a los indicadores de la norma ISO/IEC 25010:2023."));
c.push(caption("Figura 1.1. Mapa conceptual del trabajo."));
c.push(figura(IMG));
c.push(source());

// ---------------- CONCLUSIONES ----------------
c.push(bloque("7. CAPÍTULO 6 — CONCLUSIONES"));
c.push(nota("Reemplaza la nota [PENDIENTE] del capítulo 6. Párrafos cortos en pasado, uno por objetivo más la respuesta a la pregunta problema."));
c.push(pr("Un MVP que combina señales estáticas de metadatos, entropía y AST con un clasificador supervisado sí logró detectar paquetes maliciosos de PyPI dentro de los criterios de calidad definidos con la norma ISO/IEC 25010:2023. El Random Forest seleccionado alcanzó en la evaluación final un *Recall* de 0,945 y un F1 de 0,933, con una tasa de falsos positivos del 6,1 % en validación cruzada, por encima de las metas de 0,90, 0,85 y 10 % fijadas al inicio del proyecto."));
c.push(pr("Respecto al primer objetivo, el análisis empírico de 1.926 paquetes maliciosos reales permitió cuantificar siete vectores de ataque. La ejecución de comandos apareció en el 76,3 % de las muestras, la comunicación de red en el 42,0 % y la suplantación de nombres en el 26,0 %, y casi la mitad de los paquetes (48,2 %) combinaba dos o más vectores. A partir de esa evidencia se definieron once requerimientos funcionales y doce no funcionales, trazados a cuatro características de la norma."));
c.push(pr("En cuanto al segundo objetivo, la arquitectura de monolito modular con patrón Pipes and Filters resultó adecuada para una herramienta de línea de comandos: cada extractor se diseñó y se probó por separado, y las interfaces tipadas con Pydantic mantuvieron el acoplamiento bajo. Durante el diseño del modelo se retiraron cinco características de metadatos que permanecían constantes en el entrenamiento, y el vector final quedó en nueve características."));
c.push(pr("El tercer objetivo se cumplió con un MVP funcional publicado en GitHub con licencia MIT. La herramienta descarga y extrae los paquetes con validaciones contra Zip Slip y zip-bomb, genera reportes JSON y SARIF con códigos de salida para CI, se integra como *hook* de pre-commit y cuenta con 66 pruebas automatizadas, un 91 % de cobertura e integración continua en tres versiones de Python."));
c.push(pr("El cuarto objetivo confirmó la eficacia y la calidad del sistema. Además de cumplir los indicadores del clasificador, el análisis de un paquete tomó 0,91 s de media y 353 MB de memoria, lejos de los límites de 120 s y 2 GB. El estudio de ablación mostró que, sin las señales del nombre, el modelo conserva un F1 de 0,909, lo que indica que la detección se sostiene en el contenido del código. Frente a GuardDog, sobre las mismas muestras, pyscan detectó más malware y generó cerca de seis veces menos falsas alarmas; ClamAV no detectó ninguna muestra y VirusTotal detectó el 55 %."));
c.push(pr("La ampliación del conjunto de datos fue decisiva para la validez de los resultados. La primera versión del modelo, entrenada solo con paquetes benignos populares, reportaba métricas más altas que en buena parte se explicaban por la popularidad del nombre; al incorporar una muestra aleatoria del índice de PyPI, la importancia de la distancia del nombre bajó de 0,62 a 0,24 y las métricas descendieron a valores más realistas y defendibles."));
c.push(pr("Por último, la evaluación a prevalencia realista delimitó el uso adecuado de la herramienta. Con un paquete malicioso por cada cien, la precisión proyectada fue de 0,13, de modo que pyscan resulta más útil como filtro que prioriza paquetes para revisión dentro del flujo de integración continua que como juez definitivo de un paquete."));

// ---------------- RECOMENDACIONES ----------------
c.push(bloque("8. CAPÍTULO 7 — RECOMENDACIONES"));
c.push(nota("Reemplaza la nota [PENDIENTE] y las viñetas actuales del capítulo 7 (las cuatro viñetas originales quedan incluidas)."));
c.push(bullet([t("Validación temporal. ", { bold: true }), t("Evaluar el modelo entrenándolo con paquetes publicados antes de una fecha y probándolo con paquetes posteriores, para medir cómo se degrada frente a campañas nuevas; ese tipo de validación es poco frecuente en la literatura revisada.")]));
c.push(bullet([t("Datos más diversos. ", { bold: true }), t("Ampliar la muestra aleatoria de paquetes benignos (hoy de 479), donde se concentran los falsos positivos, e incorporar nuevas fuentes de malware como Backstabber's Knife Collection. Mantener un reentrenamiento periódico del clasificador.")]));
c.push(bullet([t("Umbral según el contexto. ", { bold: true }), t("Exponer el umbral de decisión como parámetro y calibrar las probabilidades del modelo, para que cada equipo elija el equilibrio entre detección y falsas alarmas que le conviene; el análisis de sensibilidad mostró que con un umbral de 0,65 la tasa de falsos positivos baja a 2,7 % manteniendo un Recall de 0,906.")]));
c.push(bullet([t("Señales adicionales. ", { bold: true }), t("Incorporar las señales que quedaron fuera del alcance —filtro por tipo de archivo, análisis de archivos distintos de .py y anomalías de publicación obtenidas de la API de PyPI— y medir su aporte con el mismo protocolo de ablación.")]));
c.push(bullet([t("Otros ecosistemas. ", { bold: true }), t("Aprovechar la arquitectura modular para extender la herramienta a npm, RubyGems, Maven o Crates, agregando extractores específicos de cada lenguaje.")]));
c.push(bullet([t("Análisis dinámico complementario. ", { bold: true }), t("Enviar a un entorno aislado (sandbox) solo los paquetes que el modelo marque como dudosos, para cubrir las técnicas de evasión que se manifiestan en tiempo de ejecución sin encarecer el análisis de todos los paquetes.")]));
c.push(bullet([t("Trazabilidad del desarrollo. ", { bold: true }), t("En futuras versiones, trabajar con cuentas individuales y solicitudes de integración (pull requests) revisadas, para que el historial del repositorio refleje la autoría y la revisión de cada cambio.")]));
c.push(bullet([t("Difusión. ", { bold: true }), t("Publicar un artículo científico con los resultados de la evaluación, incluidos el estudio de ablación y la comparación con otras herramientas.")]));

// ---------------- AGRADECIMIENTOS ----------------
c.push(bloque("9. AGRADECIMIENTOS (PROPUESTA)"));
c.push(nota("Opcional: ajústalo a su gusto. La dedicatoria es personal y no la redacté. En la plantilla va centrado y breve."));
c.push(pr("Los autores agradecen al director, M.Sc. Juan Carlos Navarro Beltrán, y a la codirectora, Solangie Paola Garavito Mendivelso, por su acompañamiento y sus observaciones durante el desarrollo del trabajo; a la Facultad de Ingeniería de la Universidad Católica de Colombia, y a los equipos de Datadog Security Labs y de PyPI Malregistry, cuyos conjuntos de datos públicos hicieron posible entrenar y evaluar el modelo."));

// ---------------- LISTAS ----------------
c.push(bloque("10. LISTA DE TABLAS Y LISTA DE FIGURAS"));
c.push(nota("Hoy hay dos numeraciones mezcladas: las tablas del anteproyecto (Tabla 1 a 5) y las de los capítulos (Tabla 2.1, 3.1...). Además, «Tabla 4» y «Tabla 5» del cronograma y el presupuesto chocan con las tablas del capítulo 4 y 5. Propuesta: numerar por capítulo y por anexo, como abajo. Los números de página los pone Word: da a los títulos el estilo «Descripción» y usa Referencias → Insertar tabla de ilustraciones."));
const tablas = [
  "Tabla 1.1. Indicadores clave por objetivo específico (antes Tabla 1)",
  "Tabla 1.2. Entidades del sistema y responsabilidades (antes Tabla 2)",
  "Tabla 2.1. Frecuencia de los vectores de ataque (corpus propio de 1.926 paquetes)",
  "Tabla 2.2. Mapeo de los vectores de pyscan a la taxonomía de Ladisa et al.",
  "Tabla 2.3. Requerimientos funcionales y su trazabilidad a los vectores",
  "Tabla 2.4. Requerimientos no funcionales mapeados a ISO/IEC 25010:2023",
  "Tabla 2.5. Historias de usuario derivadas de los requerimientos",
  "Tabla 2.6. Cumplimiento de los KPI del primer objetivo específico",
  "Tabla 3.1. Stack tecnológico y su trazabilidad a los requerimientos",
  "Tabla 3.2. Trazabilidad entre decisiones de diseño y requerimientos",
  "Tabla 4.1. Iteraciones de desarrollo del MVP",
  "Tabla 4.2. Composición del dataset",
  "Tabla 4.3. Cobertura de código por módulo (pytest --cov)",
  "Tabla 4.4. Cumplimiento de los KPI del tercer objetivo específico",
  "Tabla 5.1. Plan de pruebas del MVP",
  "Tabla 5.2. Resultados de la validación cruzada estratificada (k = 5)",
  "Tabla 5.3. Matriz de confusión (validación cruzada, Random Forest)",
  "Tabla 5.4. Ablación por grupo de características",
  "Tabla 5.5. Precisión proyectada según la prevalencia de paquetes maliciosos",
  "Tabla 5.6. pyscan frente a GuardDog y ClamAV",
  "Tabla 5.7. pyscan frente a VirusTotal",
  "Tabla 5.8. Cumplimiento consolidado de los KPI",
  "Tabla A.1. Cronograma por fases (antes Tabla 4)",
  "Tabla B.1. Presupuesto del proyecto (antes Tabla 5)",
  "Tabla C.1. Productos a entregar (antes Tabla 3)",
];
c.push(h2("LISTA DE TABLAS"));
tablas.forEach((x) => c.push(pr(x)));
c.push(h2("LISTA DE FIGURAS"));
["Figura 1.1. Mapa conceptual del trabajo", "Figura 3.1. Vista de componentes del MVP (patrón Pipes and Filters)",
 "Figura 3.2. Vista de flujo de datos de un análisis", "Figura 3.3. Vista dinámica: secuencia de un escaneo",
 "Figura 3.4. Vista de despliegue del sistema", "Figura 3.5. Modelo de dominio (entidades Pydantic)",
 "Figura 3.6. Pipeline de entrenamiento y evaluación del modelo"].forEach((x) => c.push(pr(x)));
c.push(nota("LISTA DE CUADROS: el documento no tiene cuadros; se puede eliminar esa sección, como indica la nota."));

// ---------------- BIBLIOGRAFÍA ----------------
c.push(bloque("11. BIBLIOGRAFÍA — ENTRADAS NUEVAS"));
c.push(nota("Fuentes que el texto nuevo menciona y que no están en la bibliografía. Siguen el formato de las entradas actuales. PackAttack (ref. 9) ya no se cita en el cuerpo: elimínala o cítala donde corresponda, y ajusta la numeración. Sigue pendiente confirmar con el director NTC 1486 frente a IEEE."));
[
  "CISCO TALOS. ClamAV: open source antivirus engine [en línea]. [s.f.]. Disponible en: https://www.clamav.net",
  "DATADOG SECURITY LABS. Malicious Software Packages Dataset [en línea]. GitHub, [s.f.]. Disponible en: https://github.com/DataDog/malicious-software-packages-dataset",
  "DUAN, Ruian et al. Towards Measuring Supply Chain Attacks on Package Managers for Interpreted Languages. En: Network and Distributed System Security Symposium (NDSS). Internet Society, 2021.",
  "GITHUB. GitHub Actions documentation [en línea]. [s.f.]. Disponible en: https://docs.github.com/actions",
  "NACIONES UNIDAS. Objetivo 9: Construir infraestructuras resilientes, promover la industrialización sostenible y fomentar la innovación [en línea]. [s.f.]. Disponible en: https://www.un.org/sustainabledevelopment/es/infrastructure/",
  "VIRUSTOTAL. VirusTotal [en línea]. [s.f.]. Disponible en: https://www.virustotal.com",
].forEach((x) => c.push(pr(x)));

// ---------------- LO QUE NO SE PUEDE REDACTAR ----------------
c.push(bloque("12. PENDIENTES QUE DEBEN COMPLETAR USTEDES"));
[
  "Portada: correo del director; título académico y correo de la codirectora; fecha de sustentación.",
  "Dedicatoria (personal).",
  "Línea de investigación: confirmar el nombre oficial (sección 1.3.2).",
  "Número de objetivos específicos (cuatro frente a tres de la plantilla) y KPI «4/4 módulos»: decisión con el director.",
  "Norma de citación (NTC 1486 o IEEE) y orden de la bibliografía: decisión con el director.",
  "Anexos A y B: el cronograma y el presupuesto están como imágenes; conviene rehacerlos como tablas de Word si el director los conserva.",
  "Anexo D: insertar las cuatro capturas.",
  "Pasada de humanización y nueva verificación en Turnitin sobre los textos nuevos.",
].forEach((x) => c.push(bullet(x)));

save(c, "Textos_pendientes_tesis.docx", path.resolve(__dirname, "..", ".."));
