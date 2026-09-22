"""Pruebas del Feature Builder."""

from pyscan.features import build_features
from pyscan.models import ASTReport, EntropyReport, PackageMetadata, TyposquatReport


def test_build_features_from_metadata():
    typo = TyposquatReport(
        min_distance=1,
        similar_package="requests",
        is_typosquat=True,
        has_combo_affix=True,
        author_present=False,
        maintainer_count=2,
    )
    # metadata se conserva por compatibilidad pero ya no aporta características.
    md = PackageMetadata(releases=["1.0", "1.1"], requires_dist=["x"], has_long_description=True)
    fv = build_features(typosquat=typo, metadata=md)
    assert fv.name_min_distance == 1.0
    assert fv.is_typosquat == 1.0
    assert fv.has_combo_affix == 1.0
    # El vector ya no expone características de metadatos de publicación.
    assert not hasattr(fv, "release_count")
    assert not hasattr(fv, "author_present")
    assert len(fv.to_row()) == 9


def test_build_features_missing_distance_uses_sentinel():
    fv = build_features(typosquat=TyposquatReport(min_distance=None))
    assert fv.name_min_distance == 99.0


def test_build_features_entropy_and_ast():
    fv = build_features(
        entropy=EntropyReport(max=7.9, mean=5.1, suspicious_windows=3),
        ast=ASTReport(
            dangerous_calls=["eval", "exec"], network_literals=["http://x"], has_install_hook=True
        ),
    )
    assert fv.entropy_max == 7.9
    assert fv.entropy_suspicious_windows == 3.0
    assert fv.ast_dangerous_calls == 2.0
    assert fv.ast_network_literals == 1.0
    assert fv.ast_has_install_hook == 1.0
