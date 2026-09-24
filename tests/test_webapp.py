"""Pruebas de la capa web (solo helpers y endpoints sin red)."""

import sys
from pathlib import Path

import pytest

pytest.importorskip("flask")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import webapp  # noqa: E402


@pytest.mark.parametrize(
    "lit, expected",
    [("0.3.30.0", True), ("0.3.33.112", True), ("0.0.0.0", False), ("10.122.1.1", False)],
)
def test_version_like_literals(lit, expected):
    assert webapp._is_version_like(lit) is expected


def test_status_endpoint():
    resp = webapp.app.test_client().get("/api/status")
    data = resp.get_json()
    assert resp.status_code == 200
    assert "threshold" in data and "model" in data


def test_page_uses_spanish_number_format():
    page = webapp.app.test_client().get("/").data.decode("utf-8")
    assert "toLocaleString('es-CO'" in page
    assert "no existe" in page
