"""Fetcher seguro: consulta la API de PyPI, descarga el sdist y lo extrae
de forma segura con protección contra path traversal (Zip Slip) y zip-bombs.

Corresponde al Sprint 1-2 del cronograma. No ejecuta en ningún momento el
código del paquete: solo descarga y descomprime para su posterior análisis
estático.
"""

from __future__ import annotations

import hashlib
import io
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests

from . import config
from .models import Package, PackageMetadata


class FetchError(Exception):
    """Error recuperable al obtener o extraer un paquete."""


@dataclass
class FetchResult:
    package: Package
    metadata: PackageMetadata
    extracted_path: Path
    archive_path: Path


# --- API de PyPI ----------------------------------------------------------
def get_pypi_json(name: str, version: Optional[str] = None,
                  session: Optional[requests.Session] = None) -> dict:
    """Obtiene los metadatos JSON de un paquete desde PyPI."""
    url = (config.PYPI_JSON_VERSION_URL.format(name=name, version=version)
           if version else config.PYPI_JSON_URL.format(name=name))
    sess = session or requests.Session()
    try:
        resp = sess.get(url, timeout=config.HTTP_TIMEOUT,
                        headers={"User-Agent": config.USER_AGENT})
    except requests.RequestException as exc:  # red caída, timeout, etc.
        raise FetchError(f"No se pudo consultar PyPI para '{name}': {exc}") from exc
    if resp.status_code == 404:
        raise FetchError(f"El paquete '{name}' no existe en PyPI.")
    if resp.status_code != 200:
        raise FetchError(f"PyPI respondió {resp.status_code} para '{name}'.")
    return resp.json()


def parse_metadata(data: dict) -> tuple[Package, PackageMetadata, dict]:
    """Construye Package y PackageMetadata a partir del JSON de PyPI.

    Devuelve también el descriptor del sdist (.tar.gz) elegido para descarga.
    """
    info = data.get("info", {})
    name = info.get("name", "")
    version = info.get("version", "")

    # Selección del sdist; si no hay, se cae al primer artefacto disponible.
    urls = data.get("urls", [])
    sdist = next((u for u in urls if u.get("packagetype") == "sdist"), None)
    chosen = sdist or (urls[0] if urls else None)

    upload_date = None
    if chosen and chosen.get("upload_time_iso_8601"):
        from datetime import datetime
        try:
            upload_date = datetime.fromisoformat(
                chosen["upload_time_iso_8601"].replace("Z", "+00:00"))
        except ValueError:
            upload_date = None

    package = Package(
        name=name,
        version=version,
        author=info.get("author") or None,
        upload_date=upload_date,
        sha256=(chosen or {}).get("digests", {}).get("sha256"),
    )

    project_urls = info.get("project_urls") or {}
    metadata = PackageMetadata(
        description=info.get("summary") or None,
        author_email=info.get("author_email") or None,
        home_page=info.get("home_page") or None,
        project_urls={k: v for k, v in project_urls.items()},
        releases=list((data.get("releases") or {}).keys()),
        maintainers=[m for m in [info.get("maintainer")] if m],
        requires_dist=info.get("requires_dist") or [],
        has_long_description=bool(info.get("description")),
    )
    return package, metadata, (chosen or {})


# --- Descarga -------------------------------------------------------------
def download_archive(file_url: str, dest_dir: Path,
                     session: Optional[requests.Session] = None) -> tuple[Path, str]:
    """Descarga el artefacto y devuelve (ruta, sha256 calculado)."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    filename = file_url.split("/")[-1].split("?")[0] or "package.archive"
    dest = dest_dir / filename
    sess = session or requests.Session()
    try:
        with sess.get(file_url, timeout=config.HTTP_TIMEOUT, stream=True,
                      headers={"User-Agent": config.USER_AGENT}) as resp:
            resp.raise_for_status()
            hasher = hashlib.sha256()
            downloaded = 0
            with open(dest, "wb") as fh:
                for chunk in resp.iter_content(chunk_size=8192):
                    downloaded += len(chunk)
                    if downloaded > config.MAX_DOWNLOAD_BYTES:
                        raise FetchError(
                            f"El artefacto excede el tamaño máximo de descarga "
                            f"({config.MAX_DOWNLOAD_BYTES // (1024 * 1024)} MB).")
                    hasher.update(chunk)
                    fh.write(chunk)
    except requests.RequestException as exc:
        raise FetchError(f"Fallo al descargar {file_url}: {exc}") from exc
    return dest, hasher.hexdigest()


# --- Extracción segura (anti Zip Slip / zip-bomb) -------------------------
def _is_within(base: Path, target: Path) -> bool:
    """True si `target` queda dentro de `base` tras resolver la ruta."""
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def safe_extract(archive_path: Path, dest_dir: Path) -> Path:
    """Extrae .tar.gz o .whl/.zip con protección contra path traversal.

    Rechaza rutas absolutas, componentes '..', enlaces simbólicos/duros y
    paquetes que excedan los límites de tamaño/cantidad de archivos.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    name = archive_path.name.lower()
    if name.endswith((".tar.gz", ".tgz", ".tar")):
        _safe_extract_tar(archive_path, dest_dir)
    elif name.endswith((".whl", ".zip", ".egg")):
        _safe_extract_zip(archive_path, dest_dir)
    else:
        raise FetchError(f"Formato de archivo no soportado: {archive_path.name}")
    return dest_dir


def _safe_extract_tar(archive_path: Path, dest_dir: Path) -> None:
    total = 0
    count = 0
    try:
        tar_obj = tarfile.open(archive_path, "r:*")
    except tarfile.TarError as exc:  # archivo corrupto o no es un tar real
        raise FetchError(f"Archivo tar ilegible ({archive_path.name}): {exc}") from exc
    with tar_obj as tar:
        for member in tar.getmembers():
            count += 1
            if count > config.MAX_FILE_COUNT:
                raise FetchError("El paquete excede el número máximo de archivos.")
            if member.issym() or member.islnk():
                raise FetchError(f"Enlace no permitido en el archivo: {member.name}")
            if member.isdev():
                raise FetchError(f"Archivo de dispositivo no permitido: {member.name}")
            target = dest_dir / member.name
            if not _is_within(dest_dir, target):
                raise FetchError(f"Ruta peligrosa (Zip Slip) detectada: {member.name}")
            total += max(member.size, 0)
            if total > config.MAX_EXTRACT_BYTES:
                raise FetchError("El paquete excede el tamaño máximo permitido.")
        tar.extractall(dest_dir)  # noqa: S202 - rutas validadas arriba


def _safe_extract_zip(archive_path: Path, dest_dir: Path) -> None:
    total = 0
    count = 0
    try:
        zip_obj = zipfile.ZipFile(archive_path)
    except zipfile.BadZipFile as exc:  # archivo corrupto o no es un zip real
        raise FetchError(f"Archivo zip ilegible ({archive_path.name}): {exc}") from exc
    with zip_obj as zf:
        for info in zf.infolist():
            count += 1
            if count > config.MAX_FILE_COUNT:
                raise FetchError("El paquete excede el número máximo de archivos.")
            target = dest_dir / info.filename
            if not _is_within(dest_dir, target):
                raise FetchError(f"Ruta peligrosa (Zip Slip) detectada: {info.filename}")
            total += info.file_size
            if total > config.MAX_EXTRACT_BYTES:
                raise FetchError("El paquete excede el tamaño máximo permitido.")
        # Extracción manual contando bytes REALES descomprimidos: la cabecera
        # `file_size` de un ZIP malicioso puede mentir (zip-bomb), así que el
        # límite se aplica también sobre el flujo real.
        real_total = 0
        for info in zf.infolist():
            target = dest_dir / info.filename
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as dst:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    real_total += len(chunk)
                    if real_total > config.MAX_EXTRACT_BYTES:
                        raise FetchError(
                            "El paquete excede el tamaño máximo permitido "
                            "(bytes reales descomprimidos).")
                    dst.write(chunk)


# --- Orquestación --------------------------------------------------------
def fetch(name: str, version: Optional[str] = None,
          workdir: Optional[Path] = None,
          session: Optional[requests.Session] = None) -> FetchResult:
    """Descarga y extrae un paquete de PyPI listo para análisis estático."""
    workdir = workdir or config.CACHE_DIR
    sess = session or requests.Session()

    data = get_pypi_json(name, version, session=sess)
    package, metadata, file_desc = parse_metadata(data)

    file_url = file_desc.get("url")
    if not file_url:
        raise FetchError(f"No hay artefacto descargable para '{name}'.")

    pkg_dir = workdir / f"{package.name}-{package.version}"
    archive_path, digest = download_archive(file_url, pkg_dir, session=sess)

    # Verificación de integridad si PyPI publicó el hash.
    expected = file_desc.get("digests", {}).get("sha256")
    if expected and expected != digest:
        raise FetchError(
            f"sha256 no coincide para '{name}': esperado {expected}, obtenido {digest}.")
    package.sha256 = digest

    extracted = pkg_dir / "extracted"
    safe_extract(archive_path, extracted)
    return FetchResult(package=package, metadata=metadata,
                       extracted_path=extracted, archive_path=archive_path)


def fetch_from_local(archive_path: Path, dest_dir: Optional[Path] = None) -> Path:
    """Extrae de forma segura un archivo ya presente en disco (uso en dataset)."""
    archive_path = Path(archive_path)
    dest = dest_dir or (archive_path.parent / (archive_path.stem + "_extracted"))
    return safe_extract(archive_path, dest)
