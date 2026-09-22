"""Pruebas de la salida SARIF 2.1.0."""

import json

from pyscan.models import (
    ASTReport,
    EntropyReport,
    MLPrediction,
    Package,
    ScanReport,
    TyposquatReport,
    Verdict,
)
from pyscan.sarif import to_sarif, to_sarif_json


def _full_report() -> ScanReport:
    return ScanReport(
        package=Package(name="reqursts", version="1.0"),
        typosquat=TyposquatReport(min_distance=1, similar_package="requests", is_typosquat=True),
        entropy=EntropyReport(max=7.9, mean=5.0, suspicious_windows=3),
        ast=ASTReport(
            dangerous_calls=["exec", "os.system"],
            network_literals=["http://evil.example.com"],
            has_install_hook=True,
        ),
        prediction=MLPrediction(score=0.97, verdict=Verdict.MALICIOUS),
    )


def test_sarif_structure_and_rules():
    doc = to_sarif(_full_report())
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "pyscan"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    fired = {r["ruleId"] for r in run["results"]}
    assert fired == {"PS001", "PS002", "PS003", "PS004", "PS005", "PS100"}
    assert fired <= rule_ids
    ml = next(r for r in run["results"] if r["ruleId"] == "PS100")
    assert ml["level"] == "error"


def test_sarif_clean_report_has_no_results():
    rep = ScanReport(package=Package(name="requests", version="2.31.0"))
    doc = to_sarif(rep)
    assert doc["runs"][0]["results"] == []


def test_sarif_json_serializable():
    parsed = json.loads(to_sarif_json(_full_report()))
    assert parsed["runs"][0]["results"]
