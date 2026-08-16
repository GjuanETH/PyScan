"""Salida SARIF 2.1.0 (Static Analysis Results Interchange Format).

Convierte un ScanReport en un documento SARIF mínimo pero válido, apto para
integrarse en pipelines CI/CD (Azure DevOps, GitHub Advanced Security, etc.).
Cada señal del análisis se mapea a una regla estable:

  PS001 typosquatting/combosquatting     PS004 hook de instalación en setup.py
  PS002 ventanas de alta entropía        PS005 literales de red embebidos
  PS003 llamadas peligrosas (AST)        PS100 veredicto del clasificador ML
"""

from __future__ import annotations

import json

from . import __version__
from .models import ScanReport, Verdict

_RULES = {
    "PS001": "Nombre similar a un paquete popular (typosquatting/combosquatting).",
    "PS002": "Fragmentos con entropía alta compatible con ofuscación o cifrado.",
    "PS003": "Llamadas a funciones potencialmente peligrosas detectadas por AST.",
    "PS004": "Lógica personalizada de instalación en setup.py (cmdclass/install).",
    "PS005": "URLs o direcciones IP embebidas en el código.",
    "PS100": "El clasificador supervisado predice que el paquete es malicioso.",
}


def _result(rule_id: str, level: str, message: str, artifact: str) -> dict:
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
        "locations": [{
            "logicalLocations": [{"fullyQualifiedName": artifact}],
        }],
    }


def to_sarif(report: ScanReport) -> dict:
    """Construye el documento SARIF a partir del reporte del escaneo."""
    artifact = f"pypi:{report.package.name}@{report.package.version}"
    results: list[dict] = []

    t = report.typosquat
    if t and t.is_typosquat:
        results.append(_result(
            "PS001", "warning",
            f"'{report.package.name}' está a distancia {t.min_distance} de "
            f"'{t.similar_package}'" + (f" (afijos: {', '.join(t.suffixes)})"
                                        if t.has_combo_affix else "") + ".",
            artifact))

    e = report.entropy
    if e and e.suspicious_windows > 0:
        results.append(_result(
            "PS002", "warning",
            f"{e.suspicious_windows} ventana(s) con entropía >= umbral "
            f"(máx {e.max} bits/byte).", artifact))

    a = report.ast
    if a:
        if a.dangerous_calls:
            results.append(_result(
                "PS003", "warning",
                "Llamadas peligrosas: " + ", ".join(a.dangerous_calls) + ".",
                artifact))
        if a.has_install_hook:
            results.append(_result(
                "PS004", "warning",
                "setup.py define lógica de instalación personalizada "
                "(vector clásico de ejecución en `pip install`).", artifact))
        if a.network_literals:
            results.append(_result(
                "PS005", "note",
                f"{len(a.network_literals)} literal(es) de red embebidos.",
                artifact))

    p = report.prediction
    if p and p.verdict == Verdict.MALICIOUS:
        results.append(_result(
            "PS100", "error",
            f"Clasificador ML: MALICIOSO con probabilidad {p.score:.2f}.",
            artifact))

    return {
        "$schema": ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                    "master/Schemata/sarif-schema-2.1.0.json"),
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "pyscan",
                "version": __version__,
                "informationUri": "https://dev.azure.com/jdgutierrez017/Tesis",
                "rules": [{"id": rid,
                           "shortDescription": {"text": desc}}
                          for rid, desc in _RULES.items()],
            }},
            "results": results,
        }],
    }


def to_sarif_json(report: ScanReport, indent: int = 2) -> str:
    return json.dumps(to_sarif(report), ensure_ascii=False, indent=indent)
