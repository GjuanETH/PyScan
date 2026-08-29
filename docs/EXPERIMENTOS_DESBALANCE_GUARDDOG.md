# Experimentos: desbalance realista y comparación con GuardDog

Dos evaluaciones que refuerzan la validez del modelo frente a un jurado exigente.
Ambas corren en la VM y usan el modelo y el hold-out ya generados.

---

## 1. Evaluación bajo prevalencia realista

**Problema.** El modelo se evalúa con balance ~1:1, pero en producción el malware
es rarísimo (~1:100 a 1:1000). A esa prevalencia, aunque el Recall no cambia, la
**precisión se desploma**: los benignos son mayoría, así que incluso un FPR bajo
produce muchas alarmas falsas por cada acierto.

**Método.** No hace falta descargar más benignos. El Recall (TPR) y el FPR son
independientes de la prevalencia; se miden en el hold-out y se proyecta la
precisión esperada a cualquier prevalencia π con la fórmula:

```
precision(π) = TPR·π / ( TPR·π + FPR·(1-π) )
```

**Correr:**

```bash
cd ~/Tesis && source .venv/bin/activate
python scripts/experiment_imbalance.py
```

**Salidas** (`data/analysis/`): `imbalance.json`, `imbalance_projection.csv`,
`imbalance.png` (precisión vs prevalencia).

**Cómo interpretar.** Se espera ver que a 1:100 la precisión cae bastante (p. ej.
del ~97 % a ~30 %). Eso **no es un fallo del modelo**: es la realidad de detectar
eventos raros, y afecta por igual a cualquier detector. La lectura para la tesis:
en despliegue real conviene subir el umbral para ganar precisión (a costa de algo
de Recall) o usar el detector como primer filtro seguido de revisión. El script
sugiere un punto de operación a 1:100 mediante un barrido de umbral.

---

## 2. Comparación empírica con GuardDog

**Qué hace.** Evalúa pyscan y GuardDog (detector de código abierto de Datadog)
sobre el mismo subconjunto del hold-out y compara Recall, Precisión, F1 y FP.
Desglosa por fuente del malware (DataDog vs Malregistry).

**Instalar GuardDog en la VM:**

```bash
source .venv/bin/activate
pip install guarddog
```

**Correr** (empieza con pocas muestras; GuardDog tarda ~2–8 s por paquete):

```bash
python scripts/experiment_compare_guarddog.py --limit-per-class 150
```

**Salidas** (`data/analysis/`): `compare_guarddog.json`,
`compare_guarddog_per_sample.csv`.

**Decisión de cada detector.** pyscan usa el veredicto del clasificador;
GuardDog se considera que marca malicioso si activa ≥1 regla de amenaza
(`threat-*`). Las reglas `capability-*` (neutras, presentes también en software
legítimo) no cuentan por sí solas, para no penalizar injustamente a GuardDog.

### Interpretación honesta (importante para la sustentación)

- **Sesgo a favor de GuardDog en muestras de DataDog.** Las heurísticas de
  GuardDog se desarrollaron a partir del dataset de DataDog; sobre esas muestras
  puede tener ventaja "de casa". Por eso el desglose por fuente: mira el Recall en
  **Malregistry**, que es más independiente, para una comparación más justa.
- **No es una competencia de quién gana.** GuardDog es una herramienta madura y
  basada en reglas; pyscan es un MVP académico basado en ML. El valor del
  experimento es **posicionar** pyscan frente al estado del arte y mostrar en qué
  coinciden y en qué difieren (reglas vs aprendizaje), no "vencer" a GuardDog.
- Si pyscan iguala o se acerca a GuardDog en muestras independientes, es un
  resultado fuerte. Si GuardDog detecta casos que pyscan no, esos casos son
  material valioso para la sección de trabajo futuro.

### Notas técnicas

- GuardDog usa un sandbox de kernel por defecto; el script pasa `--no-sandbox`
  automáticamente (en la VM el sandbox suele no estar disponible).
- En su primer arranque GuardDog intenta descargar listas de caché desde
  internet; si falla, las reglas de código igual funcionan (solo se omiten
  algunas reglas de metadatos como typosquatting por nombre).
- Ajusta `--limit-per-class` según el tiempo disponible; con 150 por clase la
  corrida toma del orden de 10–30 minutos.
