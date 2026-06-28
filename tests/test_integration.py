"""Prueba de integración contra PyPI real. Se omite si no hay conexión."""

import pytest
import requests

from pyscan.fetcher import FetchError, fetch, get_pypi_json


def _online() -> bool:
    try:
        requests.get("https://pypi.org/pypi/six/json", timeout=8)
        return True
    except requests.RequestException:
        return False


pytestmark = pytest.mark.skipif(not _online(), reason="Sin conexión a PyPI")


def test_get_pypi_json_real():
    data = get_pypi_json("six")
    assert data["info"]["name"].lower() == "six"


def test_fetch_and_extract_real(tmp_path):
    result = fetch("six", workdir=tmp_path)
    assert result.package.name.lower() == "six"
    assert result.package.sha256  # integridad verificada
    # Debe haber extraído al menos un archivo .py
    py_files = list(result.extracted_path.rglob("*.py"))
    assert py_files, "no se extrajeron archivos .py"


def test_nonexistent_package_raises():
    with pytest.raises(FetchError):
        get_pypi_json("paquete-que-no-existe-zzz-9999-pyscan")
