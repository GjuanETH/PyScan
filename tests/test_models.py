"""Pruebas de los modelos de dominio."""

from pyscan.models import (FeatureVector, MLPrediction, Package, ScanReport,
                           TyposquatReport, Verdict)


def test_package_minimal():
    p = Package(name="requests", version="2.31.0")
    assert p.name == "requests"
    assert p.sha256 is None


def test_feature_vector_to_row_keys():
    fv = FeatureVector()
    row = fv.to_row()
    assert "name_min_distance" in row
    assert "entropy_max" in row
    assert all(isinstance(v, float) for v in row.values())


def test_scan_report_json_roundtrip():
    report = ScanReport(
        package=Package(name="evil", version="0.0.1"),
        typosquat=TyposquatReport(min_distance=1, similar_package="requests",
                                  is_typosquat=True),
        prediction=MLPrediction(score=0.92, verdict=Verdict.MALICIOUS),
    )
    js = report.to_json()
    again = ScanReport.model_validate_json(js)
    assert again.prediction.verdict == Verdict.MALICIOUS
    assert again.typosquat.is_typosquat is True
