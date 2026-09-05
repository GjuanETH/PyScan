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
import json
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


def _report_dict(report: ScanReport, note) -> dict:
    r = {"package": report.package.name, "version": report.package.version,
         "verdict": "sin modelo", "score": None, "reasons": [], "error": None}
    if report.errors:
        if report.typosquat and report.typosquat.is_typosquat:
            r["verdict"] = "sospechoso"
            r["reasons"].append(
                f"nombre similar a '{report.typosquat.similar_package}' (posible typosquatting)")
            r["reasons"].append("paquete no disponible en PyPI")
            return r
        r["verdict"] = "error"; r["error"] = report.errors[0]; return r
    if report.prediction:
        r["verdict"] = ("MALICIOSO" if report.prediction.verdict == Verdict.MALICIOUS
                        else "benigno")
        r["score"] = round(report.prediction.score, 3)
    if report.typosquat and report.typosquat.is_typosquat:
        r["reasons"].append(f"typosquat de '{report.typosquat.similar_package}'")
    if report.ast and report.ast.has_install_hook:
        r["reasons"].append("hook de instalación")
    if report.ast and report.ast.dangerous_calls:
        r["reasons"].append(f"{len(report.ast.dangerous_calls)} llamadas peligrosas")
    if report.ast and report.ast.network_literals:
        r["reasons"].append(f"{len(report.ast.network_literals)} literales de red")
    if report.entropy and report.entropy.suspicious_windows:
        r["reasons"].append(f"{report.entropy.suspicious_windows} ventanas de entropía alta")
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
    return jsonify({"version": __version__, "model": config.MODEL_FILE.exists()})


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
.spin{display:none;margin-top:14px;color:var(--navy);font-weight:600;}
.note{background:var(--card);border-radius:8px;padding:10px 12px;font-size:13px;margin-top:8px;}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin:8px 0 24px;}
.kpi{background:#fff;border-radius:12px;padding:16px;box-shadow:0 1px 3px rgba(0,0,0,.06);}
.kpi .v{font-size:30px;font-weight:800;color:var(--navy);}
.kpi .l{font-size:12.5px;color:#6a7180;margin-top:4px;}
.cards{display:grid;grid-template-columns:1fr 1fr;gap:18px;}
.panel{background:#fff;border-radius:12px;padding:16px 18px;box-shadow:0 1px 3px rgba(0,0,0,.06);}
.panel h3{margin:0 0 12px;color:var(--navy);font-size:15px;}
.cm{width:100%;border-collapse:collapse;}
.cm td,.cm th{border:1px solid #e3e8f0;padding:10px;text-align:center;font-size:13px;}
.cm .vp{background:#e7f4ea;color:#1e8449;font-weight:700;}
.cm .vn{background:#e7f4ea;color:#1e8449;font-weight:700;}
.cm .fp,.cm .fn{background:#fdecea;color:#c0392b;font-weight:700;}
footer{max-width:1020px;margin:20px auto;padding:0 20px;color:#8a90a0;font-size:12px;}
@media(max-width:760px){.cards{grid-template-columns:1fr;}}
</style></head><body>
<header><h1>pyscan</h1><span class="tag">detección de paquetes maliciosos en PyPI</span>
 <nav><button id="nav-scan" class="active" onclick="show('scan')">Escanear</button>
      <button id="nav-dash" onclick="show('dash')">Panel</button></nav></header>
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

 <section id="view-dash" style="display:none">
   <div class="kpis" id="kpis"></div>
   <div class="cards">
     <div class="panel"><h3>Vectores de ataque detectados</h3><canvas id="chVec" height="220"></canvas></div>
     <div class="panel"><h3>Composición del dataset</h3><canvas id="chData" height="220"></canvas></div>
   </div>
   <div class="cards" style="margin-top:18px">
     <div class="panel"><h3>Matriz de confusión (validación cruzada)</h3><div id="cm"></div></div>
     <div class="panel"><h3>En esta sesión</h3><div id="sess"></div></div>
   </div>
   <div class="note" id="dashNote" style="display:none;margin-top:16px"></div>
 </section>
</main>
<footer>pyscan — Universidad Católica de Colombia. Ejecución local (127.0.0.1).</footer>
<script>
let sess={analizados:0,benignos:0,sospechosos:0,maliciosos:0,errores:0};
let dashLoaded=false, charts={};
function show(v){
  document.getElementById('view-scan').style.display=(v==='scan')?'block':'none';
  document.getElementById('view-dash').style.display=(v==='dash')?'block':'none';
  document.getElementById('nav-scan').classList.toggle('active',v==='scan');
  document.getElementById('nav-dash').classList.toggle('active',v==='dash');
  if(v==='dash'){ loadDash(); }
}
function tally(rs){for(const r of rs){sess.analizados++;
  if(r.verdict==='MALICIOSO')sess.maliciosos++;else if(r.verdict==='benigno')sess.benignos++;
  else if(r.verdict==='sospechoso')sess.sospechosos++;else if(r.verdict==='error')sess.errores++;}}
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
function badge(v){const m={'MALICIOSO':'mal','benigno':'ben','sospechoso':'sus','sin modelo':'non','error':'err'};
  return '<span class="badge '+(m[v]||'non')+'">'+v+'</span>';}
function render(d){
  const mal=d.maliciosos>0;
  document.getElementById('summary').innerHTML='Analizados: '+d.total+' · '+
    '<span style="color:'+(mal?'#c0392b':'#1e8449')+'">'+d.maliciosos+' maliciosos</span>';
  let h='<table><tr><th>Paquete</th><th>Veredicto</th><th>Score</th><th>Motivos / señales</th></tr>';
  for(const r of d.results){h+='<tr><td><b>'+r.package+'</b> '+(r.version||'')+'</td><td>'+badge(r.verdict)+'</td>'+
    '<td>'+(r.score!=null?r.score:'—')+'</td><td>'+(r.error?('<i>'+r.error+'</i>'):(r.reasons.join('; ')||'—'))+'</td></tr>';}
  h+='</table>'; document.getElementById('out').innerHTML=h;
}
async function update(){
  const b=document.getElementById('updBtn'); b.disabled=true; b.textContent='Actualizando…';
  const n=document.getElementById('updNote');
  try{const r=await fetch('/api/update',{method:'POST'});const d=await r.json();
    n.style.display='block'; n.textContent=(d.ok?'✔ ':'✖ ')+d.message+'  ·  '+d.model;
  }catch(e){n.style.display='block';n.textContent='Error al actualizar.';}
  b.disabled=false; b.textContent='Actualizar lista de referencia';
}
function kpi(v,l){return '<div class="kpi"><div class="v">'+v+'</div><div class="l">'+l+'</div></div>';}
async function loadDash(){
  renderSession();
  if(dashLoaded) return;
  const r=await fetch('/api/metrics'); const d=await r.json();
  const m=d.metrics, sel=m?m.selected_model:null, cv=(m&&sel)?m.cv_results[sel]:null, ho=m?m.holdout:null;
  let k='';
  if(ho){k+=kpi((ho.recall*100).toFixed(1)+'%','Recall (hold-out)');
         k+=kpi(ho.f1.toFixed(3),'F1-Score (hold-out)');}
  if(cv){k+=kpi((cv.false_positive_rate*100).toFixed(1)+'%','Falsos positivos');
         k+=kpi(cv.pr_auc.toFixed(3),'PR-AUC');}
  if(d.benchmark&&d.benchmark.tiempo_seg){k+=kpi(d.benchmark.tiempo_seg.max+' s','Tiempo máx./paquete');}
  if(d.dataset){k+=kpi((d.dataset.malicious+d.dataset.benign).toLocaleString(),'Muestras del dataset');}
  document.getElementById('kpis').innerHTML=k||'<div class="kpi"><div class="v">—</div><div class="l">Entrena el modelo para ver métricas</div></div>';
  if(!m){document.getElementById('dashNote').style.display='block';
    document.getElementById('dashNote').textContent='No se encontró data/models/metrics.json. Entrena el modelo (train_model.py) para poblar el panel.';}
  // Vectores
  if(d.vectors&&d.vectors.vectors){const vs=d.vectors.vectors;
    const arr=Object.values(vs).sort((a,b)=>b.percentage-a.percentage);
    new Chart(document.getElementById('chVec'),{type:'bar',
      data:{labels:arr.map(x=>x.label.split(' ')[0]),datasets:[{label:'% de paquetes',data:arr.map(x=>x.percentage),backgroundColor:'#1F3864'}]},
      options:{plugins:{legend:{display:false}},scales:{y:{beginAtZero:true,ticks:{callback:v=>v+'%'}}}}});
  }
  // Dataset
  if(d.dataset){new Chart(document.getElementById('chData'),{type:'doughnut',
    data:{labels:['Maliciosas','Benignas'],datasets:[{data:[d.dataset.malicious,d.dataset.benign],backgroundColor:['#c0392b','#1e8449']}]},
    options:{plugins:{legend:{position:'bottom'}}}});}
  // Matriz de confusión
  if(cv&&cv.confusion_matrix){const c=cv.confusion_matrix;
    document.getElementById('cm').innerHTML=
    '<table class="cm"><tr><th></th><th>Pred. Malicioso</th><th>Pred. Benigno</th></tr>'+
    '<tr><th>Real Malicioso</th><td class="vp">VP '+c.tp+'</td><td class="fn">FN '+c.fn+'</td></tr>'+
    '<tr><th>Real Benigno</th><td class="fp">FP '+c.fp+'</td><td class="vn">VN '+c.tn+'</td></tr></table>';}
  dashLoaded=true;
}
function renderSession(){
  document.getElementById('sess').innerHTML=
    '<div class="kpis" style="margin:0">'+kpi(sess.analizados,'analizados')+
    kpi(sess.maliciosos+sess.sospechosos,'sospechosos / maliciosos')+
    kpi(sess.benignos,'benignos')+'</div>';
}
</script></body></html>"""


if __name__ == "__main__":
    print("pyscan web  →  http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
