"""Feature Builder: consolida los reportes de los extractores en un FeatureVector.

En el Sprint 1-2 solo están disponibles las características de metadatos; las de
entropía y AST se rellenan con valores neutros hasta que esos extractores existan.
"""

from __future__ import annotations

from typing import Optional

from .models import (ASTReport, EntropyReport, FeatureVector, PackageMetadata,
                     TyposquatReport)


def build_features(
    typosquat: Optional[TyposquatReport] = None,
    metadata: Optional[PackageMetadata] = None,
    entropy: Optional[EntropyReport] = None,
    ast: Optional[ASTReport] = None,
) -> FeatureVector:
    fv = FeatureVector()

    if typosquat is not None:
        fv.name_min_distance = float(typosquat.min_distance
                                     if typosquat.min_distance is not None else 99)
        fv.is_typosquat = 1.0 if typosquat.is_typosquat else 0.0
        fv.has_combo_affix = 1.0 if typosquat.has_combo_affix else 0.0
        fv.author_present = 1.0 if typosquat.author_present else 0.0
        fv.maintainer_count = float(typosquat.maintainer_count)

    if metadata is not None:
        fv.release_count = float(len(metadata.releases))
        fv.requires_count = float(len(metadata.requires_dist))
        fv.has_long_description = 1.0 if metadata.has_long_description else 0.0

    if entropy is not None:
        fv.entropy_max = float(entropy.max)
        fv.entropy_mean = float(entropy.mean)
        fv.entropy_suspicious_windows = float(entropy.suspicious_windows)

    if ast is not None:
        fv.ast_dangerous_calls = float(len(ast.dangerous_calls))
        fv.ast_network_literals = float(len(ast.network_literals))
        fv.ast_has_install_hook = 1.0 if ast.has_install_hook else 0.0

    return fv
