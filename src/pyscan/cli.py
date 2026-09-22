"""Interfaz de línea de comandos del MVP.

Comandos:
  pyscan scan <paquete> [<paquete>...]        Descarga de PyPI y analiza uno o varios paquetes.
  pyscan scan -r requirements.txt             Analiza todas las dependencias de un proyecto.
  pyscan scan -l ./paquete.tar.gz             Analiza un archivo o carpeta LOCAL (sin descargar).
  pyscan check-name <nombre>                  Analiza SOLO el nombre (offline, sin descargar).
  pyscan info <paquete>                       Muestra solo los metadatos de PyPI.
  pyscan version                              Muestra la versión.

`scan` acepta cualquier combinación de nombres, --requirements y --local, y al
analizar más de un paquete imprime un resumen consolidado.

Códigos de salida de `scan` (aptos para CI):
  0 = todo benigno / sin veredicto, 1 = hubo errores, 2 = al menos uno MALICIOSO.

En Windows, ejecutar como módulo:  python -m pyscan.cli <comando> ...
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import List, Optional

import typer

from . import __version__
from .classifier import ModelNotAvailable, predict
from .extractors import ASTExtractor, EntropyExtractor, MetadataExtractor
from .features import build_features
from .fetcher import FetchError, fetch, fetch_from_local, get_pypi_json, parse_metadata
from .models import Package, ScanReport, Verdict
from .sarif import to_sarif_json

app = typer.Typer(add_completion=False, help="pyscan: detección de paquetes maliciosos en PyPI.")

_ARCHIVE_EXTS = (".tar.gz", ".tgz", ".whl", ".zip", ".egg", ".tar")


# --- Motor reutilizable ---------------------------------------------------
def _analyze(
    name: str,
    extracted_path: Path,
    report: ScanReport,
    metadata=None,
    model_path: Optional[Path] = None,
) -> Optional[str]:
    """Aplica los extractores + features + predicción sobre un directorio ya extraído.

    Rellena `report` y devuelve un aviso de ML si el modelo no está disponible.
    """
    extractor = MetadataExtractor()
    report.typosquat = extractor.extract(name, metadata)
    if report.typosquat.is_typosquat and report.typosquat.similar_package:
        report.suggestion = report.typosquat.similar_package
    report.entropy = EntropyExtractor().extract(extracted_path)
    report.ast = ASTExtractor().extract(extracted_path)
    report.features = build_features(
        typosquat=report.typosquat, metadata=metadata, entropy=report.entropy, ast=report.ast
    )
    if report.features is not None:
        try:
            report.prediction = predict(report.features, model_path=model_path)
        except ModelNotAvailable as exc:
            return str(exc)
    return None


def _scan_pypi(
    name: str, version: Optional[str], model_path: Optional[Path]
) -> tuple[ScanReport, Optional[str]]:
    report = ScanReport(package=Package(name=name, version=version or "unknown"))
    try:
        result = fetch(name, version)
        report.package = result.package
        report.metadata = result.metadata
        note = _analyze(
            result.package.name,
            result.extracted_path,
            report,
            metadata=result.metadata,
            model_path=model_path,
        )
        return report, note
    except FetchError as exc:
        report.errors.append(str(exc))
        # Al menos el análisis del nombre (offline).
        report.typosquat = MetadataExtractor().extract(name)
        if report.typosquat.is_typosquat and report.typosquat.similar_package:
            report.suggestion = report.typosquat.similar_package
        report.features = build_features(typosquat=report.typosquat)
        return report, None


def _scan_many(
    names: List[str], version: Optional[str], model_path: Optional[Path], workers: int
) -> list[tuple[ScanReport, Optional[str]]]:
    """Analiza varios paquetes en paralelo (hilos) conservando el orden de entrada.

    La concurrencia es entre paquetes: cada análisis sigue siendo el mismo pipeline
    secuencial (descarga -> extractores -> modelo), por lo que el resultado de cada
    paquete no cambia; solo se solapan las esperas de red y de disco.
    """
    workers = max(1, min(workers, len(names) or 1))
    if workers == 1:
        return [_scan_pypi(n, version, model_path) for n in names]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda n: _scan_pypi(n, version, model_path), names))


def _scan_local(path: Path, model_path: Optional[Path]) -> tuple[ScanReport, Optional[str]]:
    name = _name_from_path(path)
    report = ScanReport(package=Package(name=name, version="local"))
    try:
        extracted = path if path.is_dir() else fetch_from_local(path)
        note = _analyze(name, extracted, report, model_path=model_path)
        return report, note
    except (FetchError, OSError) as exc:
        report.errors.append(str(exc))
        return report, None


def _name_from_path(path: Path) -> str:
    stem = path.name
    for ext in _ARCHIVE_EXTS:
        if stem.lower().endswith(ext):
            stem = stem[: -len(ext)]
            break
    m = re.match(r"^(?P<n>.+?)-\d", stem)
    return (m.group("n") if m else stem).lower().replace("_", "-")


def _parse_requirements(path: Path) -> List[str]:
    """Extrae los nombres de paquete de un requirements.txt (ignora versiones/opciones)."""
    names: List[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        line = line.split("#", 1)[0].strip()  # comentario en línea
        line = line.split(";", 1)[0].strip()  # marcador de entorno
        m = re.match(r"^([A-Za-z0-9._-]+)", line)
        if m:
            names.append(m.group(1))
    return names


# --- Comandos -------------------------------------------------------------
@app.command()
def version() -> None:
    """Muestra la versión de pyscan."""
    typer.echo(f"pyscan {__version__}")


@app.command(name="check-name")
def check_name(name: str) -> None:
    """Analiza SOLO el nombre (typosquatting/combosquatting) sin descargar nada."""
    rep = MetadataExtractor().extract(name)
    flag = typer.style("SOSPECHOSO", fg=typer.colors.YELLOW) if rep.is_typosquat else "ok"
    typer.secho(f"\nNombre: {name}", bold=True)
    typer.echo(
        f"  typosquat: {flag} | distancia mínima={rep.min_distance} "
        f"| parecido a '{rep.similar_package}'"
    )
    if rep.has_combo_affix:
        typer.echo(f"  combosquatting: afijos detectados -> {', '.join(rep.suffixes)}")
    typer.echo("")


@app.command()
def info(name: str, version: Optional[str] = typer.Option(None, "--version", "-v")) -> None:
    """Consulta y muestra los metadatos de un paquete sin extraerlo."""
    try:
        data = get_pypi_json(name, version)
        package, metadata, _ = parse_metadata(data)
    except FetchError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    typer.echo(package.model_dump_json(indent=2))
    typer.echo(metadata.model_dump_json(indent=2))


@app.command()
def scan(
    names: Optional[List[str]] = typer.Argument(
        None, help="Uno o varios paquetes de PyPI a analizar."
    ),
    version: Optional[str] = typer.Option(
        None, "--version", "-v", help="Versión (solo si se indica un único paquete)."
    ),
    requirements: Optional[Path] = typer.Option(
        None, "--requirements", "-r", help="Analiza todas las dependencias de un requirements.txt."
    ),
    local: Optional[List[Path]] = typer.Option(
        None, "--local", "-l", help="Archivo (.tar.gz/.whl) o carpeta LOCAL a analizar (repetible)."
    ),
    json_only: bool = typer.Option(False, "--json", help="Imprime el reporte en JSON."),
    sarif_path: Optional[Path] = typer.Option(
        None, "--sarif", help="Escribe el reporte agregado en formato SARIF 2.1.0."
    ),
    model_path: Optional[Path] = typer.Option(
        None, "--model", help="Ruta a un bundle de modelo alternativo (.joblib)."
    ),
    workers: int = typer.Option(
        4,
        "--workers",
        "-w",
        min=1,
        max=16,
        help="Paquetes a analizar en paralelo (1 = secuencial).",
    ),
) -> None:
    """Analiza uno o varios paquetes (por nombre, requirements.txt o locales)."""
    names = list(names or [])
    local = list(local or [])
    if requirements is not None:
        if not requirements.exists():
            typer.secho(f"No existe {requirements}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
        names.extend(_parse_requirements(requirements))
    if not names and not local:
        typer.secho(
            "Indica al menos un paquete, --requirements o --local.", fg=typer.colors.RED, err=True
        )
        raise typer.Exit(code=2)

    single = len(names) == 1 and not local
    results: list[tuple[ScanReport, Optional[str]]] = _scan_many(
        names, version if single else None, model_path, workers
    )
    for path in local:
        results.append(_scan_local(path, model_path))

    reports = [r for r, _ in results]
    multiple = len(reports) > 1

    if json_only:
        import json as _json

        payload = (
            [_json.loads(r.to_json()) for r in reports]
            if multiple
            else _json.loads(reports[0].to_json())
        )
        typer.echo(_json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        for report, note in results:
            _print_human(report, note)
        if multiple:
            _print_summary(reports)

    if sarif_path is not None:
        _write_aggregate_sarif(reports, sarif_path)
        if not json_only:
            typer.echo(f"SARIF escrito en: {sarif_path}")

    any_error = any(r.errors for r in reports)
    any_malicious = any(r.prediction and r.prediction.verdict == Verdict.MALICIOUS for r in reports)
    raise typer.Exit(code=1 if any_error else (2 if any_malicious else 0))


@app.command()
def precommit(
    requirements: Optional[List[Path]] = typer.Argument(
        None, help="Archivos requirements.txt a revisar (los pasa pre-commit)."
    ),
    allow_unscanned: bool = typer.Option(
        False,
        "--allow-unscanned",
        help="No bloquear si alguna dependencia no pudo analizarse "
        "(sin red, archivo ilegible o sin modelo).",
    ),
    workers: int = typer.Option(
        4,
        "--workers",
        "-w",
        min=1,
        max=16,
        help="Paquetes a analizar en paralelo (1 = secuencial).",
    ),
) -> None:
    """Hook de pre-commit / CI: analiza los requirements y bloquea si hay riesgo.

    Sale con código != 0 (bloquea el commit) si algún paquete resulta MALICIOSO
    o sospechoso por typosquatting, o si alguno no pudo analizarse (política de
    fallo seguro; se desactiva con --allow-unscanned). Sale con 0 si todo está limpio.
    """
    reqs = [r for r in (requirements or []) if r.exists()]
    names: List[str] = []
    for r in reqs:
        names.extend(_parse_requirements(r))
    names = list(dict.fromkeys(names))
    if not names:
        raise typer.Exit(code=0)

    results = _scan_many(names, None, None, workers)
    reports = [rep for rep, _ in results]
    for rep, note in results:
        _print_human(rep, note)
    if len(reports) > 1:
        _print_summary(reports)

    flagged = [
        r
        for r in reports
        if (r.prediction and r.prediction.verdict == Verdict.MALICIOUS)
        or (r.typosquat and r.typosquat.is_typosquat)
    ]
    flagged_ids = {id(r) for r in flagged}
    # Sin veredicto del modelo = no analizado (error de descarga/extracción o
    # sin modelo). No se reporta como "sin riesgo": eso sería fallar en abierto.
    unscanned = [r for r in reports if id(r) not in flagged_ids and r.prediction is None]
    if unscanned:
        names_txt = ", ".join(r.package.name for r in unscanned)
        typer.secho(
            f"\npyscan: {len(unscanned)} dependencia(s) NO se pudieron " f"analizar: {names_txt}.",
            fg=typer.colors.YELLOW,
            bold=True,
        )
    if flagged:
        typer.secho(
            f"\npyscan bloqueó el commit: {len(flagged)} dependencia(s) " f"en riesgo.",
            fg=typer.colors.RED,
            bold=True,
        )
        raise typer.Exit(code=1)
    if unscanned and not allow_unscanned:
        typer.secho(
            "pyscan bloqueó el commit: revisa esas dependencias o usa "
            "--allow-unscanned para permitirlas.",
            fg=typer.colors.RED,
            bold=True,
        )
        raise typer.Exit(code=1)
    if unscanned:
        typer.secho(
            "pyscan: sin riesgo en lo analizado (hay dependencias sin analizar).",
            fg=typer.colors.YELLOW,
        )
        raise typer.Exit(code=0)
    typer.secho("pyscan: dependencias sin riesgo detectado.", fg=typer.colors.GREEN)
    raise typer.Exit(code=0)


# --- Presentación ---------------------------------------------------------
def _verdict_cell(report: ScanReport) -> str:
    if report.errors:
        return typer.style("error", fg=typer.colors.RED)
    if report.prediction is None:
        return typer.style("sin modelo", fg=typer.colors.BLUE)
    if report.prediction.verdict == Verdict.MALICIOUS:
        return typer.style("MALICIOSO", fg=typer.colors.RED, bold=True)
    return typer.style("benigno", fg=typer.colors.GREEN)


def _print_human(report: ScanReport, note: Optional[str] = None) -> None:
    p = report.package
    typer.secho(f"\nPaquete: {p.name} {p.version}", bold=True)
    if report.errors:
        for e in report.errors:
            typer.secho(f"  error: {e}", fg=typer.colors.RED)
    if report.typosquat:
        t = report.typosquat
        flag = typer.style("SOSPECHOSO", fg=typer.colors.YELLOW) if t.is_typosquat else "ok"
        typer.echo(
            f"  typosquat: {flag} | distancia mínima={t.min_distance} "
            f"| parecido a '{t.similar_package}'"
        )
    if report.entropy:
        e = report.entropy
        ef = (
            typer.style(f"{e.suspicious_windows} ventanas altas", fg=typer.colors.YELLOW)
            if e.suspicious_windows
            else "sin ventanas sospechosas"
        )
        typer.echo(f"  entropía: max={e.max} | {ef}")
    if report.ast:
        a = report.ast
        n = len(a.dangerous_calls)
        af = (
            typer.style(f"{n} llamadas peligrosas", fg=typer.colors.YELLOW)
            if n
            else "sin llamadas peligrosas"
        )
        typer.echo(f"  AST: {af}" + (f" -> {', '.join(a.dangerous_calls[:6])}" if n else ""))
        if a.has_install_hook:
            typer.secho("       hook de instalación en setup.py", fg=typer.colors.YELLOW)
        if a.network_literals:
            typer.echo(f"       literales de red: {len(a.network_literals)}")
        # Ubicaciones concretas (archivo:línea) de los primeros hallazgos.
        for f in [x for x in a.findings if x.kind != "network"][:6]:
            typer.echo(f"       ↳ {f.name}  ({f.file}:{f.line})")
    if report.prediction:
        pr = report.prediction
        typer.echo(f"  ML: {_verdict_cell(report)} | score={pr.score:.4f}")
    elif note:
        typer.secho(f"  ML: sin veredicto — {note}", fg=typer.colors.BLUE)
    if report.suggestion:
        typer.secho(
            f"  Sugerencia: ¿querías instalar '{report.suggestion}'? "
            f"Es el paquete legítimo más parecido.",
            fg=typer.colors.CYAN,
        )
    typer.echo("")


def _print_summary(reports: list[ScanReport]) -> None:
    total = len(reports)
    mal = sum(1 for r in reports if r.prediction and r.prediction.verdict == Verdict.MALICIOUS)
    err = sum(1 for r in reports if r.errors)
    typer.secho("=" * 52, fg=typer.colors.BRIGHT_BLACK)
    typer.secho(
        f"RESUMEN: {total} analizados | "
        + typer.style(f"{mal} maliciosos", fg=typer.colors.RED, bold=(mal > 0))
        + f" | {err} con error",
        bold=True,
    )
    flagged = [
        r
        for r in reports
        if (r.prediction and r.prediction.verdict == Verdict.MALICIOUS)
        or (r.typosquat and r.typosquat.is_typosquat)
        or (r.ast and r.ast.has_install_hook)
    ]
    if flagged:
        typer.secho("\nA revisar:", bold=True)
        for r in flagged:
            razones = []
            if r.prediction and r.prediction.verdict == Verdict.MALICIOUS:
                razones.append(f"ML score {r.prediction.score:.2f}")
            if r.typosquat and r.typosquat.is_typosquat:
                razones.append(f"typosquat de '{r.typosquat.similar_package}'")
            if r.ast and r.ast.has_install_hook:
                razones.append("hook de instalación")
            if r.ast and r.ast.dangerous_calls:
                razones.append(f"{len(r.ast.dangerous_calls)} llamadas peligrosas")
            typer.echo(
                f"  - {_verdict_cell(r)}  {r.package.name} {r.package.version}"
                f"  ({'; '.join(razones)})"
            )
    else:
        typer.secho("\nNingún paquete resultó sospechoso.", fg=typer.colors.GREEN)
    typer.echo("")


def _write_aggregate_sarif(reports: list[ScanReport], sarif_path: Path) -> None:
    import json as _json

    runs = []
    for r in reports:
        runs.extend(_json.loads(to_sarif_json(r))["runs"])
    aggregate = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
            "master/Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": runs,
    }
    sarif_path.parent.mkdir(parents=True, exist_ok=True)
    sarif_path.write_text(_json.dumps(aggregate, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":  # pragma: no cover
    app()
