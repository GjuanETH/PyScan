"""Pruebas del extractor de metadatos / typosquatting."""

from pyscan.extractors import MetadataExtractor
from pyscan.models import PackageMetadata

REF = ["requests", "urllib3", "numpy", "pandas", "cryptography", "boto3"]


def make_extractor():
    return MetadataExtractor(reference_names=REF)


def test_legitimate_package_is_not_typosquat():
    ext = make_extractor()
    rep = ext.extract("requests")
    assert rep.min_distance == 0
    assert rep.is_typosquat is False


def test_typosquat_detected_one_edit():
    ext = make_extractor()
    rep = ext.extract("reqursts")  # 1-2 ediciones de 'requests'
    assert rep.is_typosquat is True
    assert rep.similar_package == "requests"
    assert rep.min_distance is not None and rep.min_distance <= 2


def test_combosquatting_affix_detected():
    ext = make_extractor()
    rep = ext.extract("requests-python")
    assert rep.has_combo_affix is True
    assert "python" in rep.suffixes
    # tras quitar el afijo, el núcleo coincide con un paquete legítimo
    assert rep.is_typosquat is True


def test_distinct_name_not_flagged():
    ext = make_extractor()
    rep = ext.extract("totally-unrelated-xyz")
    assert rep.is_typosquat is False


def test_metadata_signals():
    ext = make_extractor()
    md = PackageMetadata(author_email="dev@example.com", maintainers=["dev"])
    rep = ext.extract("numpy", md)
    assert rep.author_present is True
    assert rep.maintainer_count == 1

    md_empty = PackageMetadata()
    rep2 = ext.extract("numpy", md_empty)
    assert rep2.author_present is False
