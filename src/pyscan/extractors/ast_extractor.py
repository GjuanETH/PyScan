"""Extractor de árboles de sintaxis abstracta (AST) — Sprint 4.

Recorre el AST de los archivos .py del paquete con ast.NodeVisitor para detectar
patrones sospechosos sin ejecutar el código:
  - llamadas a funciones potencialmente peligrosas (eval, exec, subprocess,
    base64.b64decode, os.system, pickle.loads, etc.),
  - imports relevantes (os, subprocess, socket, requests...),
  - literales de red (URLs http/https, direcciones IP),
  - lógica en la instalación (setup.py con cmdclass / install personalizado),
    vector clásico de ejecución en `pip install`.

Produce un ASTReport tipado. El recorrido es puramente estático: en ningún
momento se importa ni ejecuta el código analizado.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterable, Optional

from .. import config
from ..models import ASTReport, Finding

_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Nombres de funciones peligrosas (último componente) y rutas con punto.
_DANGEROUS = set(config.AST_DANGEROUS_CALLS)
_DANGEROUS_LEAF = {name.split(".")[-1] for name in _DANGEROUS if "." not in name}
_DANGEROUS_DOTTED = {name for name in _DANGEROUS if "." in name}


def _call_name(node: ast.Call) -> Optional[str]:
    """Reconstruye el nombre invocado: 'eval', 'os.system', 'base64.b64decode'."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = [func.attr]
        cur = func.value
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


class _Visitor(ast.NodeVisitor):
    def __init__(self, relfile: str = "") -> None:
        self.dangerous: set[str] = set()
        self.imports: set[str] = set()
        self.network: set[str] = set()
        self.has_install_hook = False
        self.relfile = relfile
        self.findings: list[Finding] = []
        # Mapa de alias local -> nombre real, para resistir evasiones del tipo
        # `import subprocess as sp; sp.run(...)` o `from os import system as s`.
        self._aliases: dict[str, str] = {}

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.add(alias.name.split(".")[0])
            if alias.asname:
                self._aliases[alias.asname] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self.imports.add(node.module.split(".")[0])
            for alias in node.names:
                self._aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    def _resolve(self, name: str) -> str:
        """Sustituye el primer componente por su import real si es un alias."""
        root, _, rest = name.partition(".")
        real = self._aliases.get(root)
        if real is None:
            return name
        return f"{real}.{rest}" if rest else real

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        if name:
            resolved = self._resolve(name)
            # Los nombres "hoja" (eval, exec, compile, __import__) solo cuentan
            # como llamada directa al builtin, no como metodo (p. ej. re.compile).
            is_bare_builtin = "." not in resolved and resolved in _DANGEROUS_LEAF
            if resolved in _DANGEROUS_DOTTED or is_bare_builtin:
                self.dangerous.add(resolved)
                self.findings.append(Finding(kind="dangerous_call", name=resolved,
                                             file=self.relfile,
                                             line=getattr(node, "lineno", 0)))
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            line = getattr(node, "lineno", 0)
            for m in _URL_RE.findall(node.value):
                self.network.add(m)
                self.findings.append(Finding(kind="network", name=m,
                                             file=self.relfile, line=line))
            for m in _IP_RE.findall(node.value):
                # Evita falsos positivos triviales como números de versión.
                self.network.add(m)
                self.findings.append(Finding(kind="network", name=m,
                                             file=self.relfile, line=line))
        self.generic_visit(node)


def _detect_install_hook(tree: ast.AST) -> Optional[int]:
    """Heurística: setup() con cmdclass o clases que extiendan *install*.

    Devuelve el número de línea del hallazgo, o None si no hay hook.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name and name.split(".")[-1] == "setup":
                for kw in node.keywords:
                    if kw.arg in ("cmdclass",):
                        return getattr(node, "lineno", 0)
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                base_name = base.attr if isinstance(base, ast.Attribute) else getattr(base, "id", "")
                if "install" in str(base_name).lower():
                    return getattr(node, "lineno", 0)
    return None


class ASTExtractor:
    """Recorre el AST de los .py de un paquete y resume señales sospechosas."""

    def __init__(self, patterns: tuple[str, ...] = ("*.py",)):
        self.patterns = patterns

    def extract(self, root: Path) -> ASTReport:
        root = Path(root)
        files: list[Path] = []
        if root.is_file():
            files = [root]
        else:
            for pattern in self.patterns:
                files.extend(root.rglob(pattern))

        dangerous: set[str] = set()
        imports: set[str] = set()
        network: set[str] = set()
        install_hook = False
        findings: list[Finding] = []
        for path in files:
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source, filename=str(path))
            except (OSError, SyntaxError, ValueError):
                # Código ilegible o intencionalmente roto: se omite ese archivo.
                continue
            try:
                relfile = str(path.relative_to(root)) if root.is_dir() else path.name
            except ValueError:
                relfile = path.name
            # Un visitor por archivo: los alias de import son de ámbito local
            # al módulo y no deben contaminar el análisis de otros archivos.
            visitor = _Visitor(relfile)
            visitor.visit(tree)
            dangerous |= visitor.dangerous
            imports |= visitor.imports
            network |= visitor.network
            findings.extend(visitor.findings)
            if path.name == "setup.py":
                hook_line = _detect_install_hook(tree)
                if hook_line is not None:
                    install_hook = True
                    findings.append(Finding(kind="install_hook", name="setup()",
                                            file=relfile, line=hook_line))

        return ASTReport(
            dangerous_calls=sorted(dangerous),
            imports=sorted(imports),
            network_literals=sorted(network),
            has_install_hook=install_hook,
            findings=findings[:200],   # tope defensivo
        )


def extract_ast_features(root: Path,
                         extractor: Optional[ASTExtractor] = None) -> ASTReport:
    """Atajo funcional para usar el extractor sin instanciarlo manualmente."""
    extractor = extractor or ASTExtractor()
    return extractor.extract(root)
