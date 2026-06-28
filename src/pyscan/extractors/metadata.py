"""Extractor de metadatos y similitud léxica (Sprint 1-2).

Compara el nombre del paquete contra una lista de paquetes legítimos usando la
distancia de Levenshtein (vía RapidFuzz, optimizada en C++) para detectar
typosquatting, e inspecciona señales de metadatos del autor. Produce un
TyposquatReport tipado.
"""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Iterable, Optional

from rapidfuzz.distance import Levenshtein

from .. import config
from ..models import PackageMetadata, TyposquatReport


@functools.lru_cache(maxsize=1)
def _load_reference_names(path: Optional[str] = None) -> tuple[str, ...]:
    """Carga la lista de paquetes legítimos contra los que comparar.

    Lee `data/top_pypi_packages.txt` (un nombre por línea). Si no existe,
    devuelve una semilla mínima embebida para que el extractor funcione igual.
    """
    file_path = Path(path) if path else config.TOP_PACKAGES_FILE
    if file_path.exists():
        names = [
            line.strip().lower()
            for line in file_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        if names:
            return tuple(names)
    return _SEED_PACKAGES


# Semilla mínima (se reemplaza por la lista completa del Top de PyPI).
_SEED_PACKAGES: tuple[str, ...] = (
    "requests", "urllib3", "numpy", "pandas", "setuptools", "boto3", "six",
    "certifi", "idna", "charset-normalizer", "python-dateutil", "pyyaml",
    "wheel", "cryptography", "click", "jinja2", "flask", "django", "pillow",
    "scipy", "scikit-learn", "matplotlib", "pytest", "fastapi", "pydantic",
    "sqlalchemy", "beautifulsoup4", "lxml", "aiohttp", "tensorflow", "torch",
    "transformers", "openai", "tqdm", "rich", "typer", "httpx", "websockets",
    "redis", "celery", "pymongo", "psycopg2", "google-api-python-client",
    "protobuf", "grpcio", "colorama", "packaging", "attrs", "pyparsing",
)


def _strip_affix(name: str) -> tuple[str, list[str]]:
    """Quita prefijos/sufijos de combosquatting y los devuelve por separado."""
    core = name
    found: list[str] = []
    changed = True
    while changed:
        changed = False
        for affix in config.COMBO_AFFIXES:
            for sep in ("-", "_", "."):
                if core.endswith(sep + affix):
                    core = core[: -(len(affix) + 1)]
                    found.append(affix)
                    changed = True
                if core.startswith(affix + sep):
                    core = core[len(affix) + 1:]
                    found.append(affix)
                    changed = True
    return core, found


def _nearest(name: str, reference: Iterable[str]) -> tuple[Optional[int], Optional[str]]:
    """Devuelve (distancia mínima, paquete más parecido); 0 si el nombre es idéntico."""
    best_dist: Optional[int] = None
    best_name: Optional[str] = None
    for cand in reference:
        if cand == name:
            return 0, cand
        cutoff = best_dist if best_dist is not None else 4
        dist = Levenshtein.distance(name, cand, score_cutoff=cutoff)
        if best_dist is None or dist < best_dist:
            best_dist = dist
            best_name = cand
            if best_dist == 1:
                break
    return best_dist, best_name


class MetadataExtractor:
    """Extractor de typosquatting y señales de metadatos."""

    def __init__(self, reference_names: Optional[Iterable[str]] = None):
        self.reference = (tuple(n.lower() for n in reference_names)
                          if reference_names is not None else _load_reference_names())

    def extract(self, name: str,
                metadata: Optional[PackageMetadata] = None) -> TyposquatReport:
        name_l = name.strip().lower()
        core, suffixes = _strip_affix(name_l)
        threshold = config.TYPOSQUAT_DISTANCE_THRESHOLD

        if name_l in self.reference:
            min_distance: Optional[int] = 0
            similar: Optional[str] = name_l
            is_typo = False
        else:
            d_full, n_full = _nearest(name_l, self.reference)
            d_core, n_core = (_nearest(core, self.reference)
                              if core and core != name_l else (None, None))

            # Typosquatting clásico: nombre completo a 1-2 ediciones de un legítimo.
            typo_by_distance = d_full is not None and 0 < d_full <= threshold
            # Combosquatting: legítimo envuelto en afijos (núcleo <= umbral, incl. 0).
            combosquat = bool(suffixes) and d_core is not None and d_core <= threshold
            is_typo = bool(typo_by_distance or combosquat)

            candidates = [(d, n) for d, n in ((d_full, n_full), (d_core, n_core))
                          if d is not None]
            min_distance, similar = (min(candidates, key=lambda x: x[0])
                                     if candidates else (None, None))

        author_present = True
        maintainer_count = 0
        if metadata is not None:
            author_present = bool(metadata.author_email or metadata.maintainers)
            maintainer_count = len(metadata.maintainers)

        return TyposquatReport(
            min_distance=min_distance,
            similar_package=similar,
            is_typosquat=is_typo,
            suffixes=suffixes,
            has_combo_affix=bool(suffixes),
            author_present=author_present,
            maintainer_count=maintainer_count,
        )


def extract_metadata_features(name: str,
                              metadata: Optional[PackageMetadata] = None,
                              extractor: Optional[MetadataExtractor] = None) -> TyposquatReport:
    """Atajo funcional para usar el extractor sin instanciarlo manualmente."""
    extractor = extractor or MetadataExtractor()
    return extractor.extract(name, metadata)
