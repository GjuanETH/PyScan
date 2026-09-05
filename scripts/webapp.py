#!/usr/bin/env python3
"""Interfaz web local de pyscan (Flask).

Sirve una página en el navegador donde el usuario pega nombres de paquetes o el
contenido de un requirements.txt, y ve el veredicto de cada dependencia. Incluye
un botón para mantener actualizada la lista de referencia (Top de PyPI).

Reutiliza el mismo motor de análisis del CLI; no cambia la arquitectura.

Ejecutar:
    pip install flask
    python scripts/webapp.py            # abre http://127.0.0.1:5000
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from flask import Flask, jsonify, request, Response  # noqa: E402

from pyscan import __version__, config  # noqa: E402
from pyscan.cli import _scan_pypi, _parse_requirements  # noqa: E402
from pyscan.models import Verdict, ScanReport  # noqa: E402

app = Flask(__name__)


def _report_dict(report: ScanReport, note) -> dict:
    r = {"package": report.package.name, "version": report.package.version,
         "verdict": "sin modelo", "score": None, "reasons": [], "error": None}
    if report.errors:
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
    names = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        import re
        m = re.match(r"^([A-Za-z0-9._-]+)", line)
        if m:
            names.append(m.group(1))
    names = list(dict.fromkeys(names))[:100]  # dedup, tope 100
    results = []
    for n in names:
        report, note = _scan_pypi(n, None, None)
        results.append(_report_dict(report, note))
    mal = sum(1 for r in results if r["verdict"] == "MALICIOSO")
    return jsonify({"results": results, "total": len(results), "maliciosos": mal})


@app.post("/api/update")
def api_update():
    """Refresca la lista de referencia del Top de PyPI."""
    try:
        import fetch_top_pypi  # script del proyecto
        rc = fetch_top_pypi.main.__wrapped__ if hasattr(fetch_top_pypi.main, "__wrapped__") else None
    except Exception:
        rc = None
    # Ejecuta el script como subproceso para no depender de su firma interna.
    import subprocess
    try:
        out = subprocess.run([sys.executable, str(ROOT / "scripts" / "fetch_top_pypi.py"),
                              "--limit", "5000"], capture_output=True, text=True, timeout=120)
        ok = out.returncode == 0
        msg = out.stdout.strip().splitlines()[-1] if out.stdout.strip() else out.stderr.strip()
    except Exception as exc:  # noqa: BLE001
        ok, msg = False, str(exc)
    model = config.MODEL_FILE
    model_info = (f"Modelo: {model.name} presente" if model.exists()
                  else "Modelo: no entrenado")
    return jsonify({"ok": ok, "message": msg, "model": model_info})


@app.get("/api/status")
def api_status():
    return jsonify({"version": __version__,
                    "model": config.MODEL_FILE.exists()})


@app.get("/")
def index():
    return Response(PAGE, mimetype="text/html")


PAGE = """<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>pyscan — Detección de paquetes maliciosos</title>
<style>
:root{--navy:#1F3864;--blue:#2E5C9E;--orange:#E8791E;--gray:#3a3a3a;--card:#eef1f7;}
*{box-sizing:border-box;font-family:Segoe UI,Calibri,Arial,sans-serif;}
body{margin:0;background:#f4f6fa;color:var(--gray);}
header{background:var(--navy);color:#fff;padding:18px 28px;display:flex;align-items:center;gap:14px;}
header h1{font-size:20px;margin:0;font-weight:700;}
header .tag{background:var(--orange);color:#fff;font-size:12px;padding:3px 9px;border-radius:10px;}
main{max-width:960px;margin:26px auto;padding:0 20px;}
.row{display:flex;gap:20px;flex-wrap:wrap;}
.col{flex:1;min-width:320px;}
label{font-weight:600;color:var(--navy);display:block;margin-bottom:6px;}
textarea{width:100%;height:180px;border:1px solid #c9d3e4;border-radius:8px;padding:12px;font-family:Consolas,monospace;font-size:14px;resize:vertical;}
.btns{margin-top:12px;display:flex;gap:10px;flex-wrap:wrap;}
button{border:0;border-radius:8px;padding:11px 18px;font-size:14px;font-weight:600;cursor:pointer;}
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
.spin{display:none;margin-top:14px;color:var(--navy);font-weight:600;}
.note{background:var(--card);border-radius:8px;padding:10px 12px;font-size:13px;margin-top:8px;}
footer{max-width:960px;margin:20px auto;padding:0 20px;color:#8a90a0;font-size:12px;}
</style></head><body>
<header><h1>pyscan</h1><span class="tag">detección de paquetes maliciosos en PyPI</span></header>
<main>
 <div class="row">
  <div class="col">
   <label for="pkgs">Paquetes o requirements.txt</label>
   <textarea id="pkgs" placeholder="Pega los nombres (uno por línea) o el contenido de tu requirements.txt&#10;requests==2.31.0&#10;flask&#10;numpy"></textarea>
   <div class="hint">Se analiza cada dependencia descargándola de PyPI (nunca se ejecuta su código).</div>
   <div class="btns">
     <button class="primary" id="scanBtn" onclick="scan()">Analizar</button>
     <button class="ghost" id="updBtn" onclick="update()">Actualizar lista de referencia</button>
   </div>
   <div class="spin" id="spin">Analizando… esto puede tardar unos segundos por paquete.</div>
   <div class="note" id="updNote" style="display:none"></div>
  </div>
 </div>
 <div id="summary"></div>
 <div id="out"></div>
</main>
<footer>pyscan — Universidad Católica de Colombia. Ejecución local (127.0.0.1).</footer>
<script>
async function scan(){
  const text=document.getElementById('pkgs').value.trim();
  if(!text){alert('Pega al menos un paquete.');return;}
  const b=document.getElementById('scanBtn'); b.disabled=true;
  document.getElementById('spin').style.display='block';
  document.getElementById('out').innerHTML=''; document.getElementById('summary').textContent='';
  try{
    const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text})});
    const d=await r.json(); render(d);
  }catch(e){document.getElementById('out').innerHTML='<p>Error de conexión.</p>';}
  b.disabled=false; document.getElementById('spin').style.display='none';
}
function badge(v){const m={'MALICIOSO':'mal','benigno':'ben','sin modelo':'non','error':'err'};
  return '<span class="badge '+(m[v]||'non')+'">'+v+'</span>';}
function render(d){
  const mal=d.maliciosos>0;
  document.getElementById('summary').innerHTML='Analizados: '+d.total+' · '+
    '<span style="color:'+(mal?'#c0392b':'#1e8449')+'">'+d.maliciosos+' maliciosos</span>';
  let h='<table><tr><th>Paquete</th><th>Veredicto</th><th>Score</th><th>Motivos / señales</th></tr>';
  for(const r of d.results){
    h+='<tr><td><b>'+r.package+'</b> '+(r.version||'')+'</td><td>'+badge(r.verdict)+'</td>'+
       '<td>'+(r.score!=null?r.score:'—')+'</td><td>'+(r.error?('<i>'+r.error+'</i>'):(r.reasons.join('; ')||'—'))+'</td></tr>';
  }
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
</script></body></html>"""


if __name__ == "__main__":
    print("pyscan web  →  http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
