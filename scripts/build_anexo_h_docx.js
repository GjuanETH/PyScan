// Anexo H — Análisis complementarios del modelo. Todas las cifras se leen de los JSON.
const C = require("./anexos_common");
const { t, p, h1, h2, bullet, title, caption, source, figure, table, n, pct, miles, save, readJSON } = C;
const m = readJSON("data/models/metrics.json");
const abl = readJSON("data/analysis/ablation.json");
const imb = readJSON("data/analysis/imbalance.json");
const gd = readJSON("data/analysis/compare_guarddog.json");
const av = readJSON("data/analysis/compare_antivirus.json");
const vt = readJSON("data/analysis/compare_virustotal.json");
const rf = m.cv_results.random_forest, xg = m.cv_results.xgboost, ho = m.holdout;
const cm = rf.confusion_matrix;

const c = [];
c.push(...title("ANEXO H", "ANÁLISIS COMPLEMENTARIOS DEL MODELO"));
c.push(p("Este anexo reúne la evidencia completa de la validación del clasificador de pyscan: la selección del modelo, la importancia de las características, el estudio de ablación, la evaluación a prevalencia realista y la comparación con otras herramientas. El capítulo 5 del documento presenta la síntesis; aquí se documentan el método, las tablas completas y las amenazas a la validez."));

// H.1
c.push(h1("H.1 Protocolo de evaluación"));
c.push(p(`El modelo se entrenó sobre ${miles(m.n_samples)} muestras (${miles(m.n_malicious)} maliciosas y ${miles(m.n_benign)} benignas) con validación cruzada estratificada de k = ${m.k_folds} particiones. En cada partición se aplicó SMOTE solo a los datos de entrenamiento y el umbral de decisión se ajustó con las predicciones fuera de partición para alcanzar un Recall objetivo de ${n(m.target_recall, 2)}. El modelo final se evaluó una sola vez sobre el hold-out de ${miles(ho.n_samples)} muestras no vistas (Anexo G).`));

// H.2
c.push(h1("H.2 Selección del modelo"));
c.push(p("Se compararon Random Forest y XGBoost (Tabla H.1)."));
c.push(caption("Tabla H.1. Validación cruzada estratificada (k = 5)."));
c.push(table([0.26, 0.11, 0.12, 0.14, 0.12, 0.13, 0.12], ["Modelo", "Umbral", "Recall", "Precisión", "F1", "PR-AUC", "FP"], [
  ["Random Forest (sel.)", n(rf.threshold, 2), n(rf.recall), n(rf.precision), n(rf.f1), n(rf.pr_auc), n(rf.false_positive_rate)],
  ["XGBoost", n(xg.threshold, 2), n(xg.recall), n(xg.precision), n(xg.f1), n(xg.pr_auc), n(xg.false_positive_rate)],
], { boldRows: [0] }));
c.push(source());
c.push(p(`Ambos algoritmos alcanzaron el mismo F1 (${n(rf.f1)}). Se seleccionó Random Forest porque el Recall es la métrica prioritaria del proyecto —un paquete malicioso no detectado tiene un costo mayor que una falsa alarma— y XGBoost quedó en el límite de la meta (${n(xg.recall)} frente a 0,90), mientras que Random Forest la supera con margen (${n(rf.recall)}). El costo de esa elección es una tasa de falsos positivos mayor (${pct(rf.false_positive_rate)} frente a ${pct(xg.false_positive_rate)}), que se mantiene dentro del límite del 10 %.`));
c.push(caption("Tabla H.2. Evaluación final en el hold-out (Random Forest, umbral 0,45)."));
c.push(table([0.25, 0.25, 0.25, 0.25], ["Muestras", "Recall", "Precisión", "F1"], [
  [miles(ho.n_samples), n(ho.recall), n(ho.precision), n(ho.f1)]], { firstLeft: false }));
c.push(source());
c.push(p(`La tasa de falsos positivos medida en el hold-out fue ${n(imb.measured.fpr)}, coherente con la de validación cruzada (${n(rf.false_positive_rate)}).`));
c.push(caption("Tabla H.3. Matriz de confusión (validación cruzada, Random Forest)."));
c.push(table([0.34, 0.33, 0.33], ["", "Predicho: malicioso", "Predicho: benigno"], [
  ["Real: malicioso", `VP = ${miles(cm.tp)}`, `FN = ${miles(cm.fn)}`],
  ["Real: benigno", `FP = ${miles(cm.fp)}`, `VN = ${miles(cm.tn)}`],
]));
c.push(source());

// H.3
c.push(h1("H.3 Importancia de las características"));
c.push(p("La Figura H.1 muestra la importancia de cada característica en el Random Forest seleccionado. La entropía media es la señal más discriminante, seguida de la distancia del nombre y de la entropía máxima."));
c.push(caption("Figura H.1. Importancia de las características (Random Forest)."));
c.push(figure("importancia.png"));
c.push(source());
c.push(p("En la primera versión del modelo, entrenada solo con benignos del Top de PyPI, la distancia del nombre concentraba 0,62 de la importancia. Al incorporar paquetes benignos poco conocidos bajó a 0,24: el modelo dejó de apoyarse en la popularidad del nombre y pasó a depender principalmente del contenido del código."));

// H.4
c.push(h1("H.4 Estudio de ablación"));
c.push(p("Para medir la dependencia del modelo respecto a cada grupo de señales se reentrenó con subconjuntos de características, con el mismo protocolo de validación cruzada (Tabla H.4 y Figura H.2). La pregunta central es si existe fuga de información por el nombre: si el modelo solo aprendiera a reconocer nombres de paquetes populares, perdería su capacidad al retirar esas señales."));
const ORD = [["Todas (baseline)", "Todas"], ["Sin nombre (solo código)", "Sin nombre (solo código)"], ["Solo entropía", "Solo entropía"], ["Solo AST", "Solo AST"], ["Solo nombre", "Solo nombre"]];
c.push(caption("Tabla H.4. Ablación por grupo de características (validación cruzada, Random Forest)."));
c.push(table([0.24, 0.07, 0.1, 0.1, 0.14, 0.1, 0.12, 0.13], ["Configuración", "N.°", "Umbral", "Recall", "Precisión", "F1", "PR-AUC", "FP"],
  ORD.map(([k, lab]) => { const r = abl.configs[k], mm = r.metrics;
    return [lab, String(r.n_features), n(mm.threshold, 2), n(mm.recall), n(mm.precision), n(mm.f1), n(mm.pr_auc), n(mm.false_positive_rate)]; }),
  { boldRows: [0] }));
c.push(source());
c.push(caption("Figura H.2. F1 y tasa de falsos positivos por configuración."));
c.push(figure("ablacion.png"));
c.push(source());
const sn = abl.configs["Sin nombre (solo código)"].metrics, on = abl.configs["Solo nombre"].metrics;
c.push(p(`Sin las señales del nombre, el modelo conserva un F1 de ${n(sn.f1)} con una tasa de falsos positivos de ${n(sn.false_positive_rate)}, prácticamente igual a la del modelo completo. En cambio, el nombre por sí solo produce una tasa de falsos positivos de ${n(on.false_positive_rate)}. La fuga por el nombre, que sí existía en la primera versión del dataset, quedó acotada: la detección descansa en el análisis del código. Ningún grupo aislado alcanza el desempeño del conjunto completo, lo que justifica combinar las tres familias de señales.`));

// H.5
c.push(h1("H.5 Evaluación a prevalencia realista"));
c.push(p("El dataset está casi balanceado, pero en PyPI los paquetes maliciosos son una minoría pequeña. El Recall (TPR) y la tasa de falsos positivos (FPR) son propiedades del clasificador y no dependen de la prevalencia; la precisión sí. A partir de las tasas medidas en el hold-out se proyectó la precisión para distintas prevalencias π con la identidad precisión(π) = TPR·π / (TPR·π + FPR·(1 − π)), sin necesidad de recolectar más benignos."));
c.push(caption(`Tabla H.5. Proyección según la prevalencia (umbral ${n(imb.operating_threshold, 2)}; TPR ${n(imb.measured.tpr)}, FPR ${n(imb.measured.fpr)}).`));
c.push(table([0.2, 0.2, 0.2, 0.2, 0.2], ["Prevalencia", "Precisión", "F1", "Alarmas por 10.000", "Falsas por acierto"],
  Object.entries(imb.projection_by_prevalence).map(([k, r]) => [k, n(r.precision), n(r.f1), n(r.alarmas_por_10k, 1), n(r.falsas_por_acierto, 2)]),
  { firstLeft: false }));
c.push(source());
c.push(caption("Figura H.3. Precisión proyectada según la prevalencia."));
c.push(figure("prevalencia.png"));
c.push(source());
const p99 = imb.projection_by_prevalence["1:99"];
c.push(p(`Con un paquete malicioso por cada cien, la precisión proyectada es ${n(p99.precision)}: unas ${n(p99.falsas_por_acierto, 1)} alarmas falsas por cada detección verdadera. Este comportamiento, conocido como la paradoja del falso positivo, afecta a cualquier detector de eventos raros y define el uso adecuado de la herramienta: priorizar paquetes para revisión, no emitir un veredicto definitivo sin verificación.`));
c.push(h2("Sensibilidad al umbral de decisión"));
c.push(p("La Tabla H.6 y la Figura H.4 muestran el compromiso entre Recall y precisión al variar el umbral, a prevalencia 1:100."));
const pick = [0.45, 0.5, 0.6, 0.65, 0.7, 0.8, 0.9, 0.95];
const sw = imb.threshold_sweep.filter((r) => pick.some((v) => Math.abs(r.threshold - v) < 1e-6));
c.push(caption("Tabla H.6. Barrido de umbral a prevalencia 1:100 (hold-out)."));
c.push(table([0.2, 0.2, 0.2, 0.2, 0.2], ["Umbral", "Recall", "FPR", "Precisión (1:100)", "Falsas por acierto"],
  sw.map((r) => [n(r.threshold, 2), n(r.recall), n(r.fpr), n(r.precision), n(r.falsas_por_acierto, 2)]),
  { firstLeft: false, boldRows: [0], highlightRows: [3] }));
c.push(source());
c.push(caption("Figura H.4. Recall y precisión (1:100) según el umbral."));
c.push(figure("umbral.png"));
c.push(source());
const s65 = imb.threshold_sweep.find((r) => Math.abs(r.threshold - 0.65) < 1e-6);
c.push(p(`El umbral de 0,65 es el más alto que mantiene el Recall por encima de la meta (${n(s65.recall)}); con él la tasa de falsos positivos baja a ${n(s65.fpr)} y la precisión proyectada a 1:100 sube a ${n(s65.precision)}. Este análisis de sensibilidad no modifica el umbral de operación (0,45): elegirlo mirando el hold-out sería ajustar el modelo con los datos de evaluación. Sí justifica que el umbral sea configurable según el contexto de despliegue, decisión que corresponde a quien opera la herramienta.`));

// H.6
c.push(h1("H.6 Comparación con otras herramientas"));
c.push(p(`pyscan se comparó con GuardDog (reglas especializadas en paquetes, de Datadog) y con ClamAV (antivirus de firmas) sobre el mismo subconjunto del hold-out de ${gd.n_samples} muestras (${gd.n_malicious} por clase). En GuardDog se consideró malicioso un paquete con al menos ${gd.threat_min} regla de amenaza activada; presentó ${gd.guarddog_errors} errores de análisis en muestras benignas, que se excluyeron de su cálculo. VirusTotal (agregado de más de 60 motores) se evaluó sobre un subconjunto de ${vt.n_samples} muestras (${vt.n_malicious} por clase) por el límite de consultas de su API gratuita, considerando malicioso un paquete detectado por al menos ${vt.min_detections} motores.`));
c.push(caption(`Tabla H.7. pyscan frente a GuardDog y ClamAV (${gd.n_samples} muestras).`));
const row = (lab, d) => [lab, n(d.recall), d.tp + d.fp === 0 ? "n/d" : n(d.precision), n(d.f1), n(d.false_positive_rate), `${d.tp}/${d.fp}/${d.tn}/${d.fn}`];
c.push(table([0.26, 0.12, 0.13, 0.11, 0.12, 0.26], ["Herramienta", "Recall", "Precisión", "F1", "FP", "VP/FP/VN/FN"], [
  row("pyscan (ML)", gd.pyscan), row("GuardDog (reglas)", gd.guarddog), row("ClamAV (firmas)", av.clamav)], { boldRows: [0] }));
c.push(source("Fuente: elaboración propia. n/d: ClamAV no emitió ninguna alerta, por lo que su precisión no está definida."));
c.push(caption("Tabla H.8. Recall por fuente de malware."));
c.push(table([0.25, 0.25, 0.25, 0.25], ["Fuente", "pyscan", "GuardDog", "ClamAV"], [
  ["Datadog", n(gd.recall_by_source.datadog.pyscan), n(gd.recall_by_source.datadog.guarddog), n(av.recall_by_source.datadog.clamav)],
  ["Malregistry", n(gd.recall_by_source.malregistry.pyscan), n(gd.recall_by_source.malregistry.guarddog), n(av.recall_by_source.malregistry.clamav)],
]));
c.push(source());
c.push(caption("Figura H.5. pyscan, GuardDog y ClamAV sobre las mismas muestras."));
c.push(figure("comparativa_300.png"));
c.push(source());
c.push(p(`pyscan superó a GuardDog en Recall en ambas fuentes y, sobre todo, en falsas alarmas: ${gd.pyscan.fp} frente a ${gd.guarddog.fp} sobre los mismos paquetes benignos. Se incluye la fuente Datadog aunque GuardDog es desarrollado por la misma empresa, y no se observó una ventaja de GuardDog en ella. ClamAV no detectó ninguna de las ${av.n_malicious} muestras maliciosas: las firmas de un antivirus tradicional no cubren el malware de la cadena de suministro.`));
c.push(caption(`Tabla H.9. pyscan frente a VirusTotal (${vt.n_samples} muestras).`));
c.push(table([0.26, 0.12, 0.13, 0.11, 0.12, 0.26], ["Herramienta", "Recall", "Precisión", "F1", "FP", "VP/FP/VN/FN"], [
  row("pyscan (ML)", vt.pyscan), row(`VirusTotal (≥ ${vt.min_detections} motores)`, vt.virustotal)], { boldRows: [0] }));
c.push(source());
c.push(caption("Figura H.6. pyscan frente a VirusTotal."));
c.push(figure("comparativa_vt.png"));
c.push(source());
const top = Object.entries(vt.engines_top).slice(0, 5);
c.push(caption("Tabla H.10. Motores individuales de VirusTotal con mayor detección."));
c.push(table([0.4, 0.3, 0.3], ["Motor", "Malware detectado", "Recall"],
  top.map(([k, r]) => [k, `${r.malware_detectado} de ${vt.n_malicious}`, n(r.recall)])));
c.push(source());
c.push(p(`VirusTotal detectó el ${pct(vt.virustotal.recall, 0)} del malware, sin falsos positivos; ${vt.n_samples - vt.vt_hashes_found} de las ${vt.n_samples} muestras (maliciosas y benignas) ni siquiera figuraban en su base. El mejor motor individual (${top[0][0]}) llegó a ${n(top[0][1].recall)}. Por fuente, pyscan obtuvo ${n(vt.recall_by_source.datadog.pyscan)} en Datadog y ${n(vt.recall_by_source.malregistry.pyscan)} en Malregistry, frente a ${n(vt.recall_by_source.datadog.virustotal)} y ${n(vt.recall_by_source.malregistry.virustotal)} de VirusTotal.`));
c.push(h2("Falsos positivos según el origen del paquete benigno"));
c.push(p("En el subconjunto de 300 muestras, de los 6 falsos positivos de pyscan, 1 correspondió a los 127 benignos del Top de PyPI (0,8 %) y 5 a los 23 benignos de la muestra aleatoria (21,7 %). En un archivo de dependencias típico, compuesto sobre todo por paquetes populares, la tasa de falsas alarmas esperable es menor que la global; a la vez, el resultado muestra que el modelo conserva un sesgo residual hacia la popularidad. La muestra aleatoria es pequeña, por lo que estas proporciones son indicativas."));

// H.7
c.push(h1("H.7 Amenazas a la validez"));
c.push(bullet([t("Tamaño de los subconjuntos comparativos. ", { bold: true }), t(`El Recall de pyscan en las comparaciones (${n(vt.pyscan.recall)}–${n(gd.pyscan.recall)}) es menor que en el hold-out completo (${n(ho.recall)}). Con 150 y 40 muestras maliciosas la variación muestral es alta, aunque no explica por sí sola toda la diferencia; las comparaciones deben leerse como relativas entre herramientas sobre las mismas muestras. La cifra oficial del modelo es la del hold-out.`)]));
c.push(bullet([t("Prevalencia. ", { bold: true }), t("Las métricas balanceadas sobrestiman la precisión en producción (H.5).")]));
c.push(bullet([t("Validez temporal. ", { bold: true }), t("No se evaluó con una partición temporal; el desempeño frente a campañas futuras no está medido.")]));
c.push(bullet([t("Configuración de las herramientas. ", { bold: true }), t("En GuardDog bastó una regla de amenaza activada para marcar un paquete; otros umbrales o conjuntos de reglas podrían cambiar su balance entre Recall y falsos positivos.")]));
c.push(bullet([t("Muestras descartadas. ", { bold: true }), t("El modelo se entrenó antes de corregir el manejo de enlaces en el extractor; parte de las muestras descartadas contenía enlaces (Anexo G).")]));

// H.8
c.push(h1("H.8 Conclusión"));
c.push(p(`El clasificador Random Forest cumple las metas del proyecto (Recall ${n(ho.recall)} y F1 ${n(ho.f1)} en el hold-out; falsos positivos ${pct(rf.false_positive_rate)} en validación cruzada). La ablación muestra que la detección se apoya en el contenido del código y no en el nombre del paquete. Frente a GuardDog, la herramienta especializada de referencia, pyscan obtiene mayor Recall y cerca de seis veces menos falsas alarmas sobre las mismas muestras, y supera con amplitud a un antivirus de firmas y al agregado de VirusTotal en detección. A prevalencias realistas, su uso adecuado es la priorización de paquetes para revisión, con un umbral ajustable al contexto de despliegue.`));

save(c, "Anexo_H_Analisis_complementarios_del_modelo.docx");
