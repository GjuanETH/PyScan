#!/usr/bin/env python3
"""Interfaz web local de pyscan (Flask) con panel de métricas.

Dos vistas:
  - Escanear: pega paquetes o un requirements.txt, o sube un archivo local, y ve
    el veredicto de cada dependencia.
  - Panel: métricas del modelo (KPI), matriz de confusión, vectores de ataque y
    composición del dataset, leídas de data/models y data/analysis.

Reutiliza el mismo motor del CLI; no cambia la arquitectura. Corre solo en local
(127.0.0.1) y nunca ejecuta el código de los paquetes.

Ejecutar:
    pip install flask
    python scripts/webapp.py            # http://127.0.0.1:5000
"""

from __future__ import annotations

import csv
import functools
import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from werkzeug.utils import secure_filename  # noqa: E402
from flask import Flask, jsonify, request, Response  # noqa: E402

from pyscan import __version__, config  # noqa: E402
from pyscan.cli import _scan_pypi, _scan_local, _parse_requirements  # noqa: E402
from pyscan.models import Verdict, ScanReport  # noqa: E402

app = Flask(__name__)

# Literales tipo "0.3.30.0": son números de versión que el extractor AST toma por
# direcciones IPv4 (0.x.x.x no es una IP enrutable). Solo se ocultan en pantalla;
# la característica del modelo no cambia (el modelo se entrenó con ella tal cual).
_VERSION_LIKE = re.compile(r"^0\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _is_version_like(lit: str) -> bool:
    return lit != "0.0.0.0" and bool(_VERSION_LIKE.match(lit))


@functools.lru_cache(maxsize=1)
def _threshold():
    """Umbral de decisión del modelo entrenado (None si no hay modelo)."""
    try:
        from pyscan.classifier import load_bundle
        return float(load_bundle().get("threshold", config.ML_DEFAULT_THRESHOLD))
    except Exception:  # noqa: BLE001
        return None


def _report_dict(report: ScanReport, note) -> dict:
    r = {"package": report.package.name, "version": report.package.version,
         "verdict": "sin modelo", "score": None, "reasons": [], "error": None,
         "features": None, "suggestion": report.suggestion}
    r["detail"] = None
    if report.features is not None:
        r["features"] = {k: round(float(v), 3)
                         for k, v in report.features.model_dump().items()}

    def _uniq(seq, n):
        return list(dict.fromkeys(seq))[:n]

    # Evidencia concreta (qué, cuál, de dónde) para desglosar el veredicto.
    det = {"dangerous_calls": [], "network_literals": [], "imports": [],
           "install_hook": False, "typosquat_of": None, "typosquat_distance": None,
           "entropy_max": None, "entropy_suspicious_windows": 0, "locations": []}
    if report.ast:
        det["dangerous_calls"] = _uniq(report.ast.dangerous_calls, 30)
        lits = list(dict.fromkeys(report.ast.network_literals))
        det["network_literals"] = [x for x in lits if not _is_version_like(x)][:30]
        det["version_like_omitted"] = sum(1 for x in lits if _is_version_like(x))
        det["imports"] = _uniq(report.ast.imports, 40)
        det["install_hook"] = bool(report.ast.has_install_hook)
        det["locations"] = [{"kind": f.kind, "name": f.name, "file": f.file,
                             "line": f.line}
                            for f in report.ast.findings if f.kind != "network"][:15]
    if report.typosquat and report.typosquat.is_typosquat:
        det["typosquat_of"] = report.typosquat.similar_package
        det["typosquat_distance"] = report.typosquat.min_distance
    if report.entropy:
        det["entropy_max"] = round(report.entropy.max, 2)
        det["entropy_suspicious_windows"] = report.entropy.suspicious_windows
    r["detail"] = det

    if report.errors:
        missing = any("no existe en PyPI" in e for e in report.errors)
        if missing:
            # No se puede instalar hoy: no es una amenaza activa sino un nombre
            # mal escrito (aunque un atacante podría registrarlo después).
            r["verdict"] = "no existe"
            if report.typosquat and report.typosquat.is_typosquat:
                r["reasons"].append(
                    f"no existe en PyPI; se parece a '{report.typosquat.similar_package}' "
                    f"(posible error de tipeo)")
            else:
                r["reasons"].append("no existe en PyPI (revisa el nombre)")
            return r
        r["verdict"] = "error"; r["error"] = report.errors[0]; return r
    if report.prediction:
        r["verdict"] = ("MALICIOSO" if report.prediction.verdict == Verdict.MALICIOUS
                        else "benigno")
        r["score"] = round(report.prediction.score, 3)
    if report.typosquat and report.typosquat.is_typosquat:
        r["reasons"].append(f"typosquat de '{report.typosquat.similar_package}'")
    signals = []
    if det["install_hook"]:
        signals.append("hook de instalación (ejecuta código al instalar)")
    if det["dangerous_calls"]:
        shown = ", ".join(det["dangerous_calls"][:3])
        extra = f" +{len(det['dangerous_calls']) - 3}" if len(det["dangerous_calls"]) > 3 else ""
        signals.append(f"llamadas sensibles: {shown}{extra}")
    if det["network_literals"]:
        shown = ", ".join(det["network_literals"][:2])
        extra = f" +{len(det['network_literals']) - 2}" if len(det["network_literals"]) > 2 else ""
        signals.append(f"conexiones/URLs: {shown}{extra}")
    if det["entropy_suspicious_windows"]:
        signals.append(f"{det['entropy_suspicious_windows']} ventanas de entropía alta")
    if r["verdict"] == "benigno" and signals:
        # En una librería legítima estas señales son habituales; se muestran
        # como observación, no como motivo del veredicto.
        r["reasons"].append("observado, no concluyente: " + "; ".join(signals))
    else:
        r["reasons"].extend(signals)
    return r


@app.post("/api/scan")
def api_scan():
    data = request.get_json(force=True) or {}
    text = (data.get("text") or "").strip()
    import re
    names = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)", line)
        if m:
            names.append(m.group(1))
    names = list(dict.fromkeys(names))[:100]
    results = [_report_dict(*_scan_pypi(n, None, None)) for n in names]
    mal = sum(1 for r in results if r["verdict"] == "MALICIOSO")
    return jsonify({"results": results, "total": len(results), "maliciosos": mal})


@app.post("/api/scan-local")
def api_scan_local():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "No se recibió ningún archivo."}), 400
    name = secure_filename(f.filename)
    with tempfile.TemporaryDirectory(prefix="pyscan_web_") as tmp:
        path = Path(tmp) / name
        f.save(str(path))
        report, note = _scan_local(path, None)
    return jsonify(_report_dict(report, note))


@app.post("/api/update")
def api_update():
    import subprocess
    if getattr(sys, "frozen", False):
        model_info = ("Modelo entrenado presente" if config.MODEL_FILE.exists()
                      else "Modelo: no entrenado")
        return jsonify({"ok": False, "model": model_info,
                        "message": ("La actualización de la lista se hace desde el "
                                    "código fuente; el ejecutable usa la carpeta data/ "
                                    "que tiene al lado.")})
    try:
        out = subprocess.run([sys.executable, str(ROOT / "scripts" / "fetch_top_pypi.py"),
                              "--limit", "5000"], capture_output=True, text=True, timeout=120)
        ok = out.returncode == 0
        msg = out.stdout.strip().splitlines()[-1] if out.stdout.strip() else out.stderr.strip()
    except Exception as exc:  # noqa: BLE001
        ok, msg = False, str(exc)
    model_info = ("Modelo entrenado presente" if config.MODEL_FILE.exists()
                  else "Modelo: no entrenado")
    return jsonify({"ok": ok, "message": msg, "model": model_info})


@app.get("/api/status")
def api_status():
    return jsonify({"version": __version__, "model": config.MODEL_FILE.exists(),
                    "threshold": _threshold()})


@app.get("/api/metrics")
def api_metrics():
    d = config.DATA_DIR

    def load(rel):
        try:
            return json.loads((d / rel).read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return None

    metrics = load("models/metrics.json")
    vectors = load("analysis/attack_vectors.json")
    benchmark = load("analysis/benchmark.json")
    guarddog = load("analysis/compare_guarddog.json")
    antivirus = load("analysis/compare_antivirus.json")
    virustotal = load("analysis/compare_virustotal.json")

    comp = None
    try:
        c = {"malicious": 0, "benign": 0}
        with open(d / "dataset.csv", newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                if row["label"] in c:
                    c[row["label"]] += 1
        comp = c
    except Exception:  # noqa: BLE001
        comp = None

    return jsonify({"metrics": metrics, "vectors": vectors,
                    "benchmark": benchmark, "dataset": comp,
                    "guarddog": guarddog, "antivirus": antivirus,
                    "virustotal": virustotal, "threshold": _threshold(),
                    "has_model": config.MODEL_FILE.exists()})


@app.get("/")
def index():
    return Response(PAGE, mimetype="text/html")


PAGE = r"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>pyscan — Detección de paquetes maliciosos</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
:root{--navy:#1F3864;--blue:#2E5C9E;--orange:#E8791E;--gray:#3a3a3a;--card:#eef1f7;}
*{box-sizing:border-box;font-family:Segoe UI,Calibri,Arial,sans-serif;}
body{margin:0;background:#f4f6fa;color:var(--gray);}
header{background:var(--navy);color:#fff;padding:14px 28px;display:flex;align-items:center;gap:16px;}
header h1{font-size:20px;margin:0;font-weight:700;}
header .tag{background:var(--orange);color:#fff;font-size:12px;padding:3px 9px;border-radius:10px;}
nav{margin-left:auto;display:flex;gap:8px;}
nav button{background:transparent;color:#cdd8ec;border:0;padding:8px 14px;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;}
nav button.active{background:#2c4a7a;color:#fff;}
main{max-width:1020px;margin:26px auto;padding:0 20px;}
label{font-weight:600;color:var(--navy);display:block;margin-bottom:6px;}
textarea{width:100%;height:170px;border:1px solid #c9d3e4;border-radius:8px;padding:12px;font-family:Consolas,monospace;font-size:14px;resize:vertical;}
input[type=file]{font-size:13px;}
.btns{margin-top:12px;display:flex;gap:10px;flex-wrap:wrap;}
button.act{border:0;border-radius:8px;padding:11px 18px;font-size:14px;font-weight:600;cursor:pointer;}
.primary{background:var(--navy);color:#fff;}
.ghost{background:#fff;color:var(--navy);border:1px solid var(--navy);}
button:disabled{opacity:.6;cursor:default;}
.hint{font-size:12.5px;color:#6a7180;margin-top:6px;}
#summary{margin:22px 0 10px;font-size:16px;font-weight:700;color:var(--navy);}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.06);}
th{background:var(--navy);color:#fff;text-align:left;padding:10px 12px;font-size:13px;}
td{padding:10px 12px;border-top:1px solid #eef1f7;font-size:14px;vertical-align:top;}
.badge{padding:3px 10px;border-radius:12px;font-size:12px;font-weight:700;white-space:nowrap;}
.mal{background:#fdecea;color:#c0392b;}
.ben{background:#e7f4ea;color:#1e8449;}
.non{background:#eef1f7;color:#5b6472;}
.err{background:#fff3e0;color:#b9770e;}
.sus{background:#fdecd7;color:#b9600e;}
.nex{background:#e8eaf6;color:#3f4a8a;}
.ev .muted{color:#6a7180;font-size:12.5px;}
.spin{display:none;margin-top:14px;color:var(--navy);font-weight:600;}
.note{background:var(--card);border-radius:8px;padding:10px 12px;font-size:13px;margin-top:8px;}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin:8px 0 24px;}
.kpi{background:#fff;border-radius:12px;padding:16px;box-shadow:0 1px 3px rgba(0,0,0,.06);}
.kpi .v{font-size:30px;font-weight:800;color:var(--navy);}
.kpi .l{font-size:12.5px;color:#6a7180;margin-top:4px;}
.kpi .l .i{color:#9aa3b2;font-size:11px;margin-left:2px;}
[data-tip]{position:relative;cursor:help;}
[data-tip]:hover::after{content:attr(data-tip);position:absolute;left:0;top:100%;z-index:40;width:250px;white-space:normal;background:var(--navy);color:#fff;font-size:12px;font-weight:400;line-height:1.45;padding:10px 12px;border-radius:8px;box-shadow:0 6px 16px rgba(0,0,0,.22);margin-top:6px;text-align:left;}
.panel .sub{font-size:12px;color:#8a90a0;margin:-6px 0 12px;line-height:1.4;}
.row.clk{cursor:pointer;}
.row.clk:hover td{background:#f7f9fc;}
.caret{color:#8a90a0;font-size:11px;}
.det td{background:#f7f9fc;}
.feat{width:100%;border-collapse:collapse;box-shadow:none;overflow:visible;}
.feat th{background:#eef1f7;color:#33415c;font-size:12px;padding:6px 10px;}
.feat td{font-size:13px;padding:6px 10px;border-top:1px solid #e3e8f0;}
.feat td.muted{color:#8a90a0;font-size:12px;}
.feat tr.on td{background:#fdecea;}
.feat tr.on td:first-child{color:#c0392b;font-weight:700;}
.why{font-size:13.5px;color:#33415c;margin:2px 0 10px;line-height:1.5;}
.ev{margin:0 0 6px;padding-left:18px;font-size:13px;color:#3a3a3a;}
.ev li{margin:6px 0;line-height:1.5;}
.chip{display:inline-block;background:#eef1f7;color:#33415c;border-radius:6px;padding:2px 7px;margin:2px 3px 2px 0;font-family:Consolas,monospace;font-size:12px;word-break:break-all;}
.chip.bad{background:#fdecea;color:#b0331f;}
.sugg{background:#e7f4ea;color:#1e6b3a;border-radius:8px;padding:9px 12px;margin:0 0 10px;font-size:13.5px;}
.cards{display:grid;grid-template-columns:1fr 1fr;gap:18px;}
.panel{background:#fff;border-radius:12px;padding:16px 18px;box-shadow:0 1px 3px rgba(0,0,0,.06);}
.panel h3{margin:0 0 12px;color:var(--navy);font-size:15px;}
.cm{width:100%;border-collapse:collapse;overflow:visible;}
.cm td[data-tip]:hover::after{top:auto;bottom:100%;margin:0 0 6px;left:50%;transform:translateX(-50%);}
.cm td,.cm th{border:1px solid #e3e8f0;padding:10px;text-align:center;font-size:13px;}
.cm .vp{background:#e7f4ea;color:#1e8449;font-weight:700;}
.cm .vn{background:#e7f4ea;color:#1e8449;font-weight:700;}
.cm .fp,.cm .fn{background:#fdecea;color:#c0392b;font-weight:700;}
footer{max-width:1020px;margin:20px auto;padding:0 20px;color:#8a90a0;font-size:12px;}
@media(max-width:760px){.cards{grid-template-columns:1fr;}}
</style></head><body>
<header><h1>pyscan</h1><span class="tag">detección de paquetes maliciosos en PyPI</span>
 <nav><button id="nav-scan" class="active" onclick="show('scan')">Escanear</button>
      <button id="nav-analysis" onclick="show('analysis')">Análisis</button>
      <button id="nav-general" onclick="show('general')">General</button></nav></header>
<main>
 <section id="view-scan">
   <label for="pkgs">Paquetes o requirements.txt</label>
   <textarea id="pkgs" placeholder="Escribe los nombres (uno por línea) o pega tu requirements.txt&#10;requests&#10;flask&#10;numpy"></textarea>
   <div class="hint">Se analiza cada dependencia descargándola de PyPI (nunca se ejecuta su código).</div>
   <div class="btns">
     <button class="act primary" id="scanBtn" onclick="scan()">Analizar</button>
     <button class="act ghost" id="updBtn" onclick="update()">Actualizar lista de referencia</button>
   </div>
   <div class="spin" id="spin">Analizando… puede tardar unos segundos por paquete.</div>
   <div class="note" id="updNote" style="display:none"></div>
   <div style="margin-top:18px;border-top:1px solid #e3e8f0;padding-top:14px">
     <label>… o analiza un paquete ya descargado (archivo local)</label>
     <input type="file" id="file" accept=".gz,.tgz,.whl,.zip,.egg,.tar">
     <button class="act ghost" id="locBtn" onclick="scanLocal()" style="margin-left:8px">Analizar archivo</button>
     <div class="hint">Útil para revisar un .tar.gz o .whl que ya tienes en disco.</div>
   </div>
   <div id="summary"></div>
   <div id="out"></div>
 </section>

 <section id="view-analysis" style="display:none">
   <div class="note" style="margin-bottom:16px">Esta pestaña resume <b>lo que tú has analizado</b> en esta sesión. Se actualiza con cada escaneo.</div>
   <div class="kpis" id="aKpis"></div>
   <div class="cards">
     <div class="panel"><h3>Veredictos de tus escaneos</h3>
       <div class="sub">Cómo se repartió lo que analizaste (benigno / malicioso / no existe en PyPI).</div>
       <canvas id="chVerdict" height="220"></canvas></div>
     <div class="panel"><h3>Señales más frecuentes en lo analizado</h3>
       <div class="sub">Cuántos de tus paquetes activaron cada señal, y de qué paquetes vienen.</div>
       <canvas id="chSignals" height="220"></canvas>
       <div id="signalsBreak" style="margin-top:10px"></div></div>
   </div>
   <div class="panel" style="margin-top:18px"><h3>Historial de la sesión</h3>
     <div class="sub">Todo lo que has analizado desde que abriste la página. Descárgalo como evidencia o para un pipeline.</div>
     <div class="btns" style="margin-top:4px">
       <button class="act ghost" onclick="downloadHist('json')">Descargar JSON</button>
       <button class="act ghost" onclick="downloadHist('csv')">Descargar CSV</button></div>
     <div id="hist" style="margin-top:12px"></div></div>
 </section>

 <section id="view-general" style="display:none">
   <div class="note" style="margin-bottom:16px">Estas cifras son del <b>modelo entrenado y los experimentos</b>. Son fijas: no cambian con lo que escaneas.</div>
   <div class="kpis" id="kpis"></div>
   <div class="cards">
     <div class="panel"><h3>Vectores de ataque detectados</h3>
       <div class="sub">Frecuencia de cada técnica maliciosa hallada en las muestras del dataset (análisis estático). Pasa el mouse sobre cada barra para ver qué significa.</div>
       <canvas id="chVec" height="220"></canvas></div>
     <div class="panel"><h3>Composición del dataset</h3>
       <div class="sub">Paquetes usados para entrenar y validar el modelo. Pasa el mouse sobre cada mitad para ver su origen.</div>
       <canvas id="chData" height="220"></canvas></div>
   </div>
   <div class="cards" style="margin-top:18px">
     <div class="panel"><h3>Matriz de confusión (validación cruzada)</h3>
       <div class="sub">Aciertos y errores del modelo sobre datos de prueba (5 particiones). Pasa el mouse sobre cada celda.</div>
       <div id="cm"></div></div>
     <div class="panel"><h3>Importancia de características</h3>
       <div class="sub">Qué señales pesan más en la decisión del modelo. Pasa el mouse sobre cada barra para ver qué mide.</div>
       <canvas id="chImp" height="240"></canvas></div>
   </div>
   <div class="panel" style="margin-top:18px"><h3>pyscan frente a GuardDog y ClamAV</h3>
     <div class="sub" id="cmpSub1">Mismo subconjunto del hold-out para las tres herramientas. En Falsos positivos, más bajo es mejor.</div>
     <canvas id="chCmp" height="150"></canvas>
     <div class="sub" id="cmpNote" style="display:none;margin-top:10px"></div></div>
   <div class="panel" style="margin-top:18px"><h3>pyscan frente a VirusTotal</h3>
     <div class="sub" id="cmpSub2">Subconjunto más pequeño por el límite de consultas de la API gratuita de VirusTotal; no es comparable directamente con el gráfico anterior.</div>
     <canvas id="chCmpVT" height="150"></canvas></div>
   <div class="note" id="dashNote" style="display:none;margin-top:16px"></div>
 </section>
</main>
<footer>pyscan — Universidad Católica de Colombia. Ejecución local (127.0.0.1).</footer>
<script>
let sess={analizados:0,benignos:0,sospechosos:0,maliciosos:0,noexiste:0,errores:0};
let TH=null;
function NF(x,d){return Number(x).toLocaleString('es-CO',{minimumFractionDigits:d,maximumFractionDigits:d});}
function PCT(x,d){return NF(x*100,d==null?1:d)+' %';}
function SC(v){return v!=null?NF(v,3):'—';}
fetch('/api/status').then(r=>r.json()).then(d=>{TH=d.threshold;}).catch(()=>{});
const valueLabels={id:'vl',afterDatasetsDraw(ch){const c=ch.ctx;c.save();c.font='11px Segoe UI, Arial';c.fillStyle='#33415c';c.textAlign='center';
  ch.data.datasets.forEach((ds,i)=>{const m=ch.getDatasetMeta(i);if(m.hidden)return;
    m.data.forEach((b,j)=>{const v=ds.data[j];if(v==null)return;c.fillText(NF(v,2),b.x,b.y-4);});});c.restore();}};
let history=[];
let dashLoaded=false, charts={};
const VIEWS=['scan','analysis','general'];
function show(v){
  for(const x of VIEWS){
    document.getElementById('view-'+x).style.display=(v===x)?'block':'none';
    document.getElementById('nav-'+x).classList.toggle('active',v===x);
  }
  if(v==='general'){ loadGeneral(); }
  if(v==='analysis'){ renderAnalysis(); }
}
function tally(rs){const t=new Date().toLocaleTimeString('es-CO');
  for(const r of rs){sess.analizados++;
    if(r.verdict==='MALICIOSO')sess.maliciosos++;else if(r.verdict==='benigno')sess.benignos++;
    else if(r.verdict==='sospechoso')sess.sospechosos++;else if(r.verdict==='no existe')sess.noexiste++;
    else if(r.verdict==='error')sess.errores++;
    history.push(Object.assign({time:t},r));}
  if(document.getElementById('view-analysis').style.display!=='none')renderAnalysis();}
async function scan(){
  const text=document.getElementById('pkgs').value.trim();
  if(!text){alert('Escribe al menos un paquete.');return;}
  const b=document.getElementById('scanBtn'); b.disabled=true;
  document.getElementById('spin').style.display='block';
  document.getElementById('out').innerHTML=''; document.getElementById('summary').textContent='';
  try{const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text})});
    const d=await r.json(); tally(d.results); render(d);
  }catch(e){document.getElementById('out').innerHTML='<p>Error de conexión.</p>';}
  b.disabled=false; document.getElementById('spin').style.display='none';
}
async function scanLocal(){
  const inp=document.getElementById('file');
  if(!inp.files||!inp.files.length){alert('Selecciona un archivo (.tar.gz o .whl).');return;}
  const b=document.getElementById('locBtn'); b.disabled=true;
  document.getElementById('spin').style.display='block';
  document.getElementById('out').innerHTML=''; document.getElementById('summary').textContent='';
  try{const fd=new FormData(); fd.append('file', inp.files[0]);
    const r=await fetch('/api/scan-local',{method:'POST',body:fd}); const res=await r.json();
    if(res.error){document.getElementById('out').innerHTML='<p>'+res.error+'</p>';}
    else{tally([res]); render({results:[res],total:1,maliciosos:res.verdict==='MALICIOSO'?1:0});}
  }catch(e){document.getElementById('out').innerHTML='<p>Error de conexión.</p>';}
  b.disabled=false; document.getElementById('spin').style.display='none';
}
const FEAT={
 name_min_distance:{l:'Distancia del nombre',d:'Distancia de edición al paquete legítimo más parecido. Menor = más sospechoso de typosquatting.'},
 is_typosquat:{l:'¿Typosquatting?',d:'1 si el nombre imita a un paquete popular del Top de PyPI.'},
 has_combo_affix:{l:'Afijo combo',d:'1 si añade prefijos/sufijos (python-, -dev...) a un nombre conocido.'},
 entropy_max:{l:'Entropía máxima',d:'Máxima aleatoriedad del contenido; alta sugiere ofuscación o datos empaquetados.'},
 entropy_mean:{l:'Entropía media',d:'Aleatoriedad promedio del contenido del paquete.'},
 entropy_suspicious_windows:{l:'Ventanas de alta entropía',d:'Nº de bloques con entropía sospechosa (posible código ofuscado).'},
 ast_dangerous_calls:{l:'Llamadas sensibles',d:'Nº de os.system/eval/exec/subprocess hallados en el código.'},
 ast_network_literals:{l:'Literales de red',d:'Nº de URLs/IPs/sockets en el código (posible exfiltración).'},
 ast_has_install_hook:{l:'Hook de instalación',d:'1 si ejecuta código al instalarse (setup.py).'}};
function fActive(k,v){
  if(k==='name_min_distance')return v>=1&&v<=2;  // 0 = es el propio paquete legítimo
  if(k==='entropy_max')return v>=4.5;
  if(k==='entropy_mean')return v>=4.0;
  return v>=1;}
function badge(v){const m={'MALICIOSO':'mal','benigno':'ben','sospechoso':'sus','no existe':'nex','sin modelo':'non','error':'err'};
  return '<span class="badge '+(m[v]||'non')+'">'+v+'</span>';}
function esc(s){return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function chips(arr,cls){return arr.map(x=>'<span class="chip '+(cls||'')+'">'+esc(x)+'</span>').join(' ');}
function whyText(r){
  const th=TH!=null?' (umbral '+NF(TH,2)+')':'';
  if(r.verdict==='MALICIOSO')return 'El modelo lo clasificó <b>MALICIOSO</b>: score '+SC(r.score)+th+'. Encontró la combinación de señales típica del malware:';
  if(r.verdict==='benigno')return 'El modelo lo clasificó <b>benigno</b>: score '+SC(r.score)+th+'. No presenta la combinación de señales del malware. Las llamadas o conexiones listadas abajo son habituales en librerías legítimas y, por sí solas, no indican malware.';
  if(r.verdict==='no existe')return '<b>Este nombre no existe en PyPI</b>, así que hoy no se puede instalar y no es una amenaza activa. Si se parece a un paquete conocido, probablemente es un error de tipeo; ojo: un atacante podría registrar ese nombre más adelante.';
  if(r.verdict==='sospechoso')return 'Marcado <b>sospechoso</b> por el nombre, antes incluso de analizar el código:';
  return 'Se muestran las señales encontradas (sin modelo entrenado no hay veredicto):';
}
function detailRows(r){
  const f=r.features, det=r.detail||{};
  let h='<div class="why">'+whyText(r)+'</div>';
  if(r.suggestion)h+='<div class="sugg">✅ ¿Querías instalar <b>'+esc(r.suggestion)+
    '</b>? Es el paquete legítimo más parecido; revísalo como alternativa segura.</div>';
  // Evidencia concreta desmenuzada
  const ev=[];
  if(det.typosquat_of)ev.push('<b>Suplanta el nombre</b> de <code>'+esc(det.typosquat_of)+'</code>'+
    (det.typosquat_distance!=null?' (distancia '+det.typosquat_distance+')':''));
  if(det.install_hook)ev.push('<b>Hook de instalación:</b> ejecuta código al instalar (setup.py)');
  if(det.dangerous_calls&&det.dangerous_calls.length)
    ev.push('<b>Llamadas sensibles ('+det.dangerous_calls.length+'):</b><br>'+chips(det.dangerous_calls,r.verdict==='benigno'?'':'bad'));
  if(det.network_literals&&det.network_literals.length)
    ev.push('<b>Conexiones / URLs ('+det.network_literals.length+'):</b><br>'+chips(det.network_literals,r.verdict==='benigno'?'':'bad'));
  if(det.version_like_omitted)
    ev.push('<span class="muted">Se omitieron '+det.version_like_omitted+' literal(es) tipo «0.x.x.x» que son números de versión, no direcciones IP (limitación conocida del extractor).</span>');
  if(det.entropy_suspicious_windows)
    ev.push('<b>Entropía alta:</b> '+det.entropy_suspicious_windows+' ventana(s) sospechosa(s) (máx '+det.entropy_max+') → posible ofuscación');
  if(det.locations&&det.locations.length)
    ev.push('<b>Dónde (archivo:línea):</b><br>'+det.locations.map(l=>
      '<span class="chip bad">'+esc(l.name)+' <i>'+esc(l.file)+':'+l.line+'</i></span>').join(' '));
  if(det.imports&&det.imports.length)
    ev.push('<b>Imports detectados:</b><br>'+chips(det.imports.slice(0,20)));
  if(ev.length)h+='<ul class="ev"><li>'+ev.join('</li><li>')+'</li></ul>';
  else if(r.verdict==='benigno')h+='<div class="sub">No se hallaron señales de riesgo relevantes en el código.</div>';
  // Tabla de las 9 características del modelo
  if(f&&r.verdict!=='no existe'){
    h+='<div class="sub" style="margin-top:10px"><b>Las 9 características que ve el modelo</b> (⚑ = activa):</div>';
    h+='<table class="feat"><tr><th>Señal</th><th>Valor</th><th>Qué significa</th></tr>';
    for(const k in FEAT){const v=f[k],a=fActive(k,v);
      h+='<tr class="'+(a?'on':'')+'"><td>'+(a?'⚑ ':'')+FEAT[k].l+'</td><td>'+v+'</td><td class="muted">'+FEAT[k].d+'</td></tr>';}
    h+='</table>';
  }
  return h;
}
function render(d){
  const mal=d.maliciosos>0;
  document.getElementById('summary').innerHTML='Analizados: '+d.total+' · '+
    '<span style="color:'+(mal?'#c0392b':'#1e8449')+'">'+d.maliciosos+' maliciosos</span>'+
    '<div class="sub" style="margin-top:4px">Haz clic en una fila para ver, desmenuzado, por qué el modelo decidió eso.</div>';
  let h='<table><tr><th>Paquete</th><th>Veredicto</th><th>Score'+(TH!=null?' <span style="font-weight:400">(umbral '+NF(TH,2)+')</span>':'')+'</th><th>Motivos / señales</th></tr>';
  d.results.forEach((r,i)=>{const can=!!(r.features||r.detail);
    h+='<tr class="row'+(can?' clk':'')+'"'+(can?' onclick="tgl('+i+')"':'')+'>'+
      '<td>'+(can?'<span class="caret" id="cr'+i+'">▸</span> ':'')+'<b>'+esc(r.package)+'</b> '+esc(r.version||'')+'</td>'+
      '<td>'+badge(r.verdict)+'</td><td>'+SC(r.score)+'</td>'+
      '<td>'+(r.error?('<i>'+esc(r.error)+'</i>'):(r.reasons.map(esc).join('; ')||'—'))+'</td></tr>';
    if(can)h+='<tr class="det" id="det'+i+'" style="display:none"><td colspan="4">'+detailRows(r)+'</td></tr>';});
  h+='</table>'; document.getElementById('out').innerHTML=h;
}
function tgl(i){const d=document.getElementById('det'+i),c=document.getElementById('cr'+i);
  if(!d)return; const open=d.style.display!=='none';
  d.style.display=open?'none':'table-row'; if(c)c.textContent=open?'▸':'▾';}
async function update(){
  const b=document.getElementById('updBtn'); b.disabled=true; b.textContent='Actualizando…';
  const n=document.getElementById('updNote');
  try{const r=await fetch('/api/update',{method:'POST'});const d=await r.json();
    n.style.display='block'; n.textContent=(d.ok?'✔ ':'✖ ')+d.message+'  ·  '+d.model;
  }catch(e){n.style.display='block';n.textContent='Error al actualizar.';}
  b.disabled=false; b.textContent='Actualizar lista de referencia';
}
function kpi(v,l,tip){
  const attr=tip?(' data-tip="'+tip.replace(/"/g,'&quot;')+'"'):'';
  const ic=tip?' <span class="i">&#9432;</span>':'';
  return '<div class="kpi"'+attr+'><div class="v">'+v+'</div><div class="l">'+l+ic+'</div></div>';}
function wrap(s,n){n=n||42;const w=s.split(' ');const out=[];let ln='';
  for(const x of w){if((ln+' '+x).trim().length>n){out.push(ln.trim());ln=x;}else{ln+=' '+x;}}
  if(ln.trim())out.push(ln.trim());return out;}
const VEC={
 V1_typosquatting:"Typosquatting: nombres casi idénticos a paquetes populares (ej. 'reqursts' por 'requests') para engañar a quien instala. Se mide por distancia de Levenshtein contra el Top de PyPI.",
 V2_install_execution:"Ejecución en instalación: código que corre solo al instalar el paquete (hooks en setup.py). Detectado por el análisis AST.",
 V3_obfuscation:"Ofuscación: código escondido con nombres sin sentido o cadenas codificadas. Detectado por la entropía de Shannon.",
 V4_command_execution:"Ejecución de comandos: uso de os.system, subprocess, eval o exec para correr órdenes del sistema. Detectado por el análisis AST.",
 V5_insecure_deserialization:"Deserialización insegura: pickle o marshal, que pueden ejecutar código arbitrario al cargarse.",
 V6_encoding:"Codificación: uso de base64/hex para ocultar cargas o URLs maliciosas.",
 V7_network_exfiltration:"Exfiltración de red: conexiones para descargar o enviar datos (URLs, sockets, requests). Detectado por AST."};
async function loadGeneral(){
  if(dashLoaded) return;
  const r=await fetch('/api/metrics'); const d=await r.json();
  const m=d.metrics, sel=m?m.selected_model:null, cv=(m&&sel)?m.cv_results[sel]:null, ho=m?m.holdout:null;
  let k='';
  if(ho){k+=kpi(PCT(ho.recall),'Recall (hold-out)',
      'De cada 100 paquetes maliciosos reales, el modelo detecta ~'+NF(ho.recall*100,0)+'. Medido sobre los '+NF(ho.n_samples||0,0).replace(/^0$/,'')+' paquetes que el modelo nunca vio al entrenar (hold-out). Es la métrica clave: mide cuánto malware NO se escapa.');
         k+=kpi(NF(ho.f1,3),'F1-Score (hold-out)',
      'Equilibrio entre detectar malware (recall) y no dar falsas alarmas (precisión); cerca de 1 es mejor. Medido en el hold-out.');}
  if(cv){k+=kpi(PCT(cv.false_positive_rate),'Falsos positivos (val. cruzada)',
      'De cada 100 paquetes benignos, ~'+NF(cv.false_positive_rate*100,1)+' se marcan por error como maliciosos. Medido en validación cruzada estratificada de 5 particiones.');
         k+=kpi(NF(cv.pr_auc,3),'PR-AUC (val. cruzada)',
      'Área bajo la curva Precisión-Recall; mide qué tan bien separa malicioso de benigno con clases desbalanceadas (1 es perfecto). Medido en validación cruzada.');}
  const ts=d.benchmark&&d.benchmark.tiempo_seg;
  if(ts&&ts.media!=null){k+=kpi(NF(ts.media,2)+' s','Tiempo medio por paquete',
      'Descarga desde PyPI + análisis estático + veredicto del modelo. Mediana '+NF(ts.mediana,2)+' s, p95 '+NF(ts.p95,2)+' s, máximo '+NF(ts.max,2)+' s (paquetes muy grandes). Medido con benchmark_performance.py.');}
  const used=(m&&ho&&m.n_samples&&ho.n_samples)?m.n_samples+ho.n_samples:null;
  if(used){const man=d.dataset?(d.dataset.malicious+d.dataset.benign):null;
    k+=kpi(NF(used,0),'Muestras usadas',
      'Entrenamiento: '+NF(m.n_samples,0)+' ('+NF(m.n_malicious,0)+' maliciosos y '+NF(m.n_benign,0)+' benignos). Evaluación final (hold-out): '+NF(ho.n_samples,0)+'.'+
      (man?' El manifiesto tiene '+NF(man,0)+' muestras; '+NF(man-used,0)+' se descartaron en la extracción (archivos ilegibles o sin código analizable).':''));}
  else if(d.dataset){k+=kpi(NF(d.dataset.malicious+d.dataset.benign,0),'Muestras del manifiesto','Total de paquetes del manifiesto del dataset.');}
  document.getElementById('kpis').innerHTML=k||'<div class="kpi"><div class="v">—</div><div class="l">Entrena el modelo para ver métricas</div></div>';
  if(!m){document.getElementById('dashNote').style.display='block';
    document.getElementById('dashNote').textContent='No se encontró data/models/metrics.json. Entrena el modelo (train_model.py) para poblar el panel.';}
  // Vectores
  if(d.vectors&&d.vectors.vectors){
    const arr=Object.entries(d.vectors.vectors)
      .map(([kk,v])=>({label:v.label,pct:v.percentage,desc:VEC[kk]||''}))
      .sort((a,b)=>b.pct-a.pct);
    new Chart(document.getElementById('chVec'),{type:'bar',
      data:{labels:arr.map(x=>x.label),datasets:[{label:'% de paquetes',data:arr.map(x=>x.pct),backgroundColor:'#1F3864'}]},
      options:{indexAxis:'y',plugins:{legend:{display:false},tooltip:{callbacks:{
        label:c=>NF(c.parsed.x,1)+' % de las muestras maliciosas',
        afterLabel:c=>arr[c.dataIndex].desc?wrap(arr[c.dataIndex].desc):[]}}},
        scales:{x:{beginAtZero:true,ticks:{callback:v=>v+' %'}}}}});
  }
  // Dataset
  if(d.dataset){new Chart(document.getElementById('chData'),{type:'doughnut',
    data:{labels:['Maliciosas ('+NF(d.dataset.malicious,0)+')','Benignas ('+NF(d.dataset.benign,0)+')'],datasets:[{data:[d.dataset.malicious,d.dataset.benign],backgroundColor:['#c0392b','#1e8449']}]},
    options:{plugins:{legend:{position:'bottom'},tooltip:{callbacks:{
      label:c=>' '+c.label.split(' (')[0]+': '+NF(c.parsed,0)+' paquetes del manifiesto',
      afterLabel:c=>wrap(c.dataIndex===0
        ?'Muestras reales de malware de los repositorios DataDog y PyPI Malregistry.'
        :'Paquetes legítimos del Top de PyPI y de una muestra aleatoria del índice.')}}}}});}
  // Matriz de confusión
  if(cv&&cv.confusion_matrix){const c=cv.confusion_matrix;
    const T={vp:'Verdaderos positivos: malware correctamente detectado.',
             fn:'Falsos negativos: malware que se le escapó al modelo. Es el error más costoso; por eso se optimiza el Recall para reducirlo.',
             fp:'Falsos positivos: paquetes benignos marcados por error como maliciosos (falsas alarmas).',
             vn:'Verdaderos negativos: paquetes benignos correctamente aprobados.'};
    document.getElementById('cm').innerHTML=
    '<table class="cm"><tr><th></th><th>Pred. Malicioso</th><th>Pred. Benigno</th></tr>'+
    '<tr><th>Real Malicioso</th><td class="vp" data-tip="'+T.vp+'">VP '+c.tp+'</td><td class="fn" data-tip="'+T.fn+'">FN '+c.fn+'</td></tr>'+
    '<tr><th>Real Benigno</th><td class="fp" data-tip="'+T.fp+'">FP '+c.fp+'</td><td class="vn" data-tip="'+T.vn+'">VN '+c.tn+'</td></tr></table>';}
  // Comparativas: cada gráfico usa su propio subconjunto (no se mezclan tamaños)
  const MK=['recall','precision','f1','false_positive_rate'], ML=['Recall','Precisión','F1','Falsos pos.'];
  const cmpOpts=()=>({plugins:{legend:{position:'bottom'},tooltip:{callbacks:{
        label:c=>c.dataset.label+': '+NF(c.parsed.y,3),
        afterLabel:c=>c.dataIndex===3?wrap('En Falsos positivos, más bajo es mejor.'):[]}}},
        scales:{y:{beginAtZero:true,max:1.1,ticks:{callback:v=>v<=1?NF(v,1):''}}}});
  const g=d.guarddog, av=d.antivirus;
  if(g||av){const base=(g&&g.pyscan)||(av&&av.pyscan); const n=(g&&g.n_samples)||(av&&av.n_samples);
    const ds=[{label:'pyscan (ML)',data:MK.map(k=>base[k]),backgroundColor:'#1F3864'}];
    if(g&&g.guarddog)ds.push({label:'GuardDog (reglas)',data:MK.map(k=>g.guarddog[k]),backgroundColor:'#E8791E'});
    if(av&&av.clamav)ds.push({label:'ClamAV (antivirus)',data:MK.map(k=>av.clamav[k]),backgroundColor:'#7a7f8a'});
    new Chart(document.getElementById('chCmp'),{type:'bar',data:{labels:ML,datasets:ds},options:cmpOpts(),plugins:[valueLabels]});
    let sub=n?(NF(n,0)+' muestras del hold-out ('+NF(n/2,0)+' maliciosas y '+NF(n/2,0)+' benignas), las mismas para las tres herramientas. En Falsos positivos, más bajo es mejor.'):'';
    if(av&&av.clamav&&av.clamav.tp===0)sub+=' ClamAV no detectó ninguna muestra (recall 0): sus barras valen 0.';
    if(sub)document.getElementById('cmpSub1').textContent=sub;
  }else{const nn=document.getElementById('cmpNote'); nn.style.display='block';
    nn.textContent='Corre experiment_compare_guarddog.py y experiment_compare_antivirus.py para poblar esta comparación.';}
  const vt=d.virustotal;
  if(vt&&vt.virustotal&&vt.pyscan){
    new Chart(document.getElementById('chCmpVT'),{type:'bar',data:{labels:ML,datasets:[
      {label:'pyscan (ML)',data:MK.map(k=>vt.pyscan[k]),backgroundColor:'#1F3864'},
      {label:'VirusTotal (60+ motores)',data:MK.map(k=>vt.virustotal[k]),backgroundColor:'#1e8449'}]},options:cmpOpts(),plugins:[valueLabels]});
    document.getElementById('cmpSub2').textContent=NF(vt.n_samples,0)+' muestras ('+NF(vt.n_malicious,0)+' maliciosas y '+NF(vt.n_benign,0)+
      ' benignas), limitadas por la cuota de la API gratuita de VirusTotal; malicioso si al menos '+vt.min_detections+' motores lo detectan. No es comparable directamente con el gráfico anterior.';
  }else{document.getElementById('chCmpVT').parentElement.style.display='none';}
  // Importancia de características
  if(m&&m.feature_importance){const fi=m.feature_importance;const ks=Object.keys(fi);
    new Chart(document.getElementById('chImp'),{type:'bar',
      data:{labels:ks.map(k=>FEAT[k]?FEAT[k].l:k),datasets:[{data:ks.map(k=>fi[k]),backgroundColor:'#2E5C9E'}]},
      options:{indexAxis:'y',plugins:{legend:{display:false},tooltip:{callbacks:{
        label:c=>'importancia '+NF(c.parsed.x,3),
        afterLabel:c=>FEAT[ks[c.dataIndex]]?wrap(FEAT[ks[c.dataIndex]].d):[]}}},
        scales:{x:{beginAtZero:true,ticks:{callback:v=>NF(v,2)}}}}});}
  dashLoaded=true;
}
function renderHist(){const el=document.getElementById('hist'); if(!el)return;
  if(!history.length){el.innerHTML='<i>Aún no has analizado nada en esta sesión.</i>';return;}
  let h='<table><tr><th>Hora</th><th>Paquete</th><th>Veredicto</th><th>Score</th><th>Motivos</th></tr>';
  for(const r of history){h+='<tr><td>'+r.time+'</td><td><b>'+r.package+'</b> '+(r.version||'')+'</td><td>'+
    badge(r.verdict)+'</td><td>'+SC(r.score)+'</td><td>'+esc(r.error||r.reasons.join('; ')||'—')+'</td></tr>';}
  el.innerHTML=h+'</table>';}
function downloadHist(fmt){
  if(!history.length){alert('No hay nada que exportar todavía.');return;}
  let blob,name;
  if(fmt==='json'){blob=new Blob([JSON.stringify(history,null,2)],{type:'application/json'});name='pyscan_historial.json';}
  else{const hdr=['hora','paquete','version','veredicto','score','motivos'];
    const rows=history.map(r=>[r.time,r.package,r.version||'',r.verdict,r.score!=null?r.score:'',
      (r.error||r.reasons.join(' | '))].map(x=>'"'+String(x).replace(/"/g,'""')+'"').join(','));
    blob=new Blob([hdr.join(',')+'\n'+rows.join('\n')],{type:'text/csv'});name='pyscan_historial.csv';}
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;a.click();
  setTimeout(()=>URL.revokeObjectURL(a.href),1000);}
function renderAnalysis(){
  renderHist();
  // Tarjetas
  document.getElementById('aKpis').innerHTML=
    kpi(sess.analizados,'analizados')+
    kpi(sess.maliciosos,'maliciosos')+
    kpi(sess.benignos,'benignos')+
    kpi(sess.noexiste,'no existen en PyPI');
  // Gráfica de veredictos
  const labels=['Benigno','Malicioso','No existe en PyPI','Error / sin modelo'];
  const vals=[sess.benignos,sess.maliciosos,sess.noexiste,
              sess.analizados-sess.benignos-sess.maliciosos-sess.noexiste];
  const cols=['#1e8449','#c0392b','#5c6bc0','#9aa3b2'];
  if(charts.verdict)charts.verdict.destroy();
  charts.verdict=new Chart(document.getElementById('chVerdict'),{type:'doughnut',
    data:{labels,datasets:[{data:vals,backgroundColor:cols}]},
    options:{plugins:{legend:{position:'bottom'},tooltip:{callbacks:{
      label:c=>' '+c.label+': '+c.parsed}}}}});
  // Gráfica de señales activas en lo analizado
  const counts={}; for(const k in FEAT)counts[k]=0;
  for(const r of history){if(!r.features)continue;
    for(const k in FEAT)if(fActive(k,r.features[k]))counts[k]++;}
  // paquetes por señal (trazabilidad)
  const pkgs={}; for(const k in FEAT)pkgs[k]=[];
  for(const r of history){if(!r.features)continue;
    for(const k in FEAT)if(fActive(k,r.features[k]))pkgs[k].push(r.package);}
  const ks=Object.keys(FEAT).filter(k=>counts[k]>0).sort((a,b)=>counts[b]-counts[a]);
  if(charts.signals)charts.signals.destroy();
  const bk=document.getElementById('signalsBreak');
  if(ks.length){
    charts.signals=new Chart(document.getElementById('chSignals'),{type:'bar',
      data:{labels:ks.map(k=>FEAT[k].l),datasets:[{data:ks.map(k=>counts[k]),backgroundColor:'#2E5C9E'}]},
      options:{indexAxis:'y',plugins:{legend:{display:false},tooltip:{callbacks:{
        label:c=>c.parsed.x+' paquete(s)',
        afterLabel:c=>FEAT[ks[c.dataIndex]]?wrap(FEAT[ks[c.dataIndex]].d):[]}}},
        scales:{x:{beginAtZero:true,ticks:{precision:0}}}}});
    let t='<table class="feat"><tr><th>Señal</th><th>Paquetes que la activaron</th></tr>';
    for(const k of ks)t+='<tr><td>'+FEAT[k].l+'</td><td class="muted">'+
      [...new Set(pkgs[k])].map(esc).join(', ')+'</td></tr>';
    bk.innerHTML=t+'</table>';
  }else{
    const cv=document.getElementById('chSignals');
    cv.getContext('2d').clearRect(0,0,cv.width,cv.height);
    bk.innerHTML='<div class="sub">Escanea paquetes para ver aquí qué señales activan y de dónde vienen.</div>';
  }
}
</script></body></html>"""


if __name__ == "__main__":
    print("pyscan web  →  http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
