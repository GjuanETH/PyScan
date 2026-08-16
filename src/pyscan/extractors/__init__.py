"""Extractores de características (Pipes and Filters).

Cada extractor recibe datos de entrada y devuelve un reporte tipado, sin
conocer el resto del sistema.
  - metadata  (Sprint 1-2): typosquatting / similitud léxica.
  - entropy   (Sprint 3):   entropía de Shannon con ventana deslizante.
  - ast       (Sprint 4):   recorrido de árboles de sintaxis abstracta.
"""

from .metadata import MetadataExtractor, extract_metadata_features
from .entropy import EntropyExtractor, extract_entropy_features, shannon_entropy
from .ast_extractor import ASTExtractor, extract_ast_features

__all__ = [
    "MetadataExtractor", "extract_metadata_features",
    "EntropyExtractor", "extract_entropy_features", "shannon_entropy",
    "ASTExtractor", "extract_ast_features",
]
