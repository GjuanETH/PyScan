"""Pruebas del extractor de metadatos / typosquatting."""

import pytest

from pyscan.extractors import MetadataExtractor, name_from_filename
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


def test_names_are_pep503_normalized_on_both_sides():
    # Un sdist benigno ('psycopg2_binary', 'ruamel.yaml') no debe parecer typosquat.
    ext = MetadataExtractor(reference_names=["psycopg2-binary", "ruamel.yaml"])
    for name in ("psycopg2_binary", "Psycopg2.Binary", "ruamel_yaml", "ruamel-yaml"):
        rep = ext.extract(name)
        assert rep.min_distance == 0
        assert rep.is_typosquat is False


def test_combo_affix_still_detected_after_normalization():
    rep = make_extractor().extract("requests_python")
    assert rep.has_combo_affix is True and rep.is_typosquat is True


@pytest.mark.parametrize(
    "filename, expected",
    [
        ("requests-2.31.0.tar.gz", ("requests", "2.31.0")),
        ("aio_pika-10.0.1.tar.gz", ("aio-pika", "10.0.1")),
        ("requests-2022-3.22.6.tar.gz", ("requests-2022", "3.22.6")),
        ("z3-solver-5.1.0.0.tar.gz", ("z3-solver", "5.1.0.0")),
        ("ruamel.yaml-0.18.6.zip", ("ruamel-yaml", "0.18.6")),
        ("PyAudio-0.2.13-cp311-cp311-win32.whl", ("pyaudio", "0.2.13")),
        ("mscz-0.0.1-py3.8.egg", ("mscz", "0.0.1")),
        ("sin_version", ("sin-version", "")),
    ],
)
def test_name_from_filename(filename, expected):
    assert name_from_filename(filename) == expected
