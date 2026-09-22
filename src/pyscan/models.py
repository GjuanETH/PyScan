"""Modelos de dominio del MVP (entidades de la Tabla 2 del trabajo de grado).

Las interfaces entre módulos se definen con Pydantic, lo que permite validar los
datos que viajan por el patrón Pipes and Filters y probar cada módulo en aislamiento.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    """Clase predicha por el clasificador."""

    BENIGN = "benign"
    MALICIOUS = "malicious"


# --- Entrada / paquete ----------------------------------------------------
class Package(BaseModel):
    """Representación canónica del paquete analizado."""

    name: str
    version: str
    author: Optional[str] = None
    upload_date: Optional[datetime] = None
    sha256: Optional[str] = None


class PackageMetadata(BaseModel):
    """Datos provenientes de la API de PyPI."""

    description: Optional[str] = None
    author_email: Optional[str] = None
    home_page: Optional[str] = None
    project_urls: dict[str, str] = Field(default_factory=dict)
    releases: list[str] = Field(default_factory=list)
    maintainers: list[str] = Field(default_factory=list)
    requires_dist: list[str] = Field(default_factory=list)
    has_long_description: bool = False


# --- Reportes de extractores ---------------------------------------------
class EntropyReport(BaseModel):
    """Salida del extractor de entropía (Shannon, ventana deslizante)."""

    max: float = 0.0
    mean: float = 0.0
    std: float = 0.0
    suspicious_windows: int = 0


class Finding(BaseModel):
    """Hallazgo localizado: qué se detectó y dónde (archivo y línea)."""

    kind: str  # dangerous_call | network | install_hook
    name: str  # p. ej. 'os.system', 'http://x', 'setup()'
    file: str  # ruta relativa dentro del paquete
    line: int = 0  # número de línea (0 si no aplica)


class ASTReport(BaseModel):
    """Salida del recorrido de árboles de sintaxis abstracta."""

    dangerous_calls: list[str] = Field(default_factory=list)
    imports: list[str] = Field(default_factory=list)
    network_literals: list[str] = Field(default_factory=list)
    has_install_hook: bool = False  # setup.py con lógica en install/cmdclass
    # Hallazgos localizados (archivo:línea). Aditivo: no afecta al vector de
    # características, que sigue usando los conteos de las listas anteriores.
    findings: list[Finding] = Field(default_factory=list)


class TyposquatReport(BaseModel):
    """Salida del análisis de metadatos / similitud léxica."""

    min_distance: Optional[int] = None
    similar_package: Optional[str] = None
    is_typosquat: bool = False
    suffixes: list[str] = Field(default_factory=list)
    has_combo_affix: bool = False
    author_present: bool = True
    maintainer_count: int = 0


# --- Características y predicción ------------------------------------------
class FeatureVector(BaseModel):
    """Vector numérico consolidado (9 características) que entra al clasificador.

    Solo incluye señales que se pueblan de forma consistente en entrenamiento e
    inferencia: nombre (typosquatting), entropía y AST. Las señales de metadatos
    de publicación (releases, dependencias, descripción, autor/mantenedores) se
    retiraron por ser inertes durante el entrenamiento —el pipeline extrae las
    características desde los artefactos descargados, sin metadatos de PyPI— lo
    que las dejaba constantes y con importancia nula. Ver docs y el estudio de
    ablación.
    """

    # nombre / typosquat
    name_min_distance: float = 99.0
    is_typosquat: float = 0.0
    has_combo_affix: float = 0.0
    # entropía
    entropy_max: float = 0.0
    entropy_mean: float = 0.0
    entropy_suspicious_windows: float = 0.0
    # AST
    ast_dangerous_calls: float = 0.0
    ast_network_literals: float = 0.0
    ast_has_install_hook: float = 0.0

    def to_row(self) -> dict[str, float]:
        """Devuelve el vector como dict ordenado, listo para pandas / sklearn."""
        return self.model_dump()


class MLPrediction(BaseModel):
    """Salida del clasificador supervisado."""

    score: float = 0.0  # probabilidad de ser malicioso [0, 1]
    verdict: Verdict = Verdict.BENIGN
    feature_importance: dict[str, float] = Field(default_factory=dict)


# --- Salida final ---------------------------------------------------------
class ScanReport(BaseModel):
    """Documento de salida (se serializa a JSON / SARIF)."""

    package: Package
    metadata: Optional[PackageMetadata] = None
    typosquat: Optional[TyposquatReport] = None
    entropy: Optional[EntropyReport] = None
    ast: Optional[ASTReport] = None
    features: Optional[FeatureVector] = None
    prediction: Optional[MLPrediction] = None
    # Paquete legítimo sugerido como alternativa (p. ej. ante un typosquat).
    suggestion: Optional[str] = None
    errors: list[str] = Field(default_factory=list)

    def to_json(self, indent: int = 2) -> str:
        return self.model_dump_json(indent=indent)
