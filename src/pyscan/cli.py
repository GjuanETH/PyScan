"""Interfaz de línea de comandos del MVP.

Comandos:
  pyscan scan <paquete> [--version X]   Descarga de PyPI y analiza el paquete.
  pyscan check-name <nombre>            Analiza SOLO el nombre (offline, sin descargar).
  pyscan info <paquete>                 Muestra solo los metadatos de PyPI.
  pyscan version                        Muestra la versión.

En Windows, ejecutar como módulo:  python -m pyscan.cli <comando> ...
"""

from __future__ import annotations

from typing import Optional

import typer

from . import __version__
from .extractors import EntropyExtractor, MetadataExtractor
from .features import build_features
from .fetcher import FetchError, fetch, get_pypi_json, parse_metadata
from .models import Package, ScanReport

app = typer.Typer(add_completion=False, help="pyscan: detección de paquetes maliciosos en PyPI.")


@app.command()
def version() -> None:
    """Muestra la versión de pyscan."""
    typer.echo(f"pyscan {__version__}")


@app.command(name="check-name")
def check_name(name: str) -> None:
    """Analiza SOLO el nombre (typosquatting/combosquatting) sin descargar nada."""
    rep = MetadataExtractor().extract(name)
    flag = (typer.style("SOSPECHOSO", fg=typer.colors.YELLOW)
            if rep.is_typosquat else "ok")
    typer.secho(f"\nNombre: {name}", bold=True)
    typer.echo(f"  typosquat: {flag} | distancia mínima={rep.min_distance} "
               f"| parecido a '{rep.similar_package}'")
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
    name: str,
    version: Optional[str] = typer.Option(None, "--version", "-v",
                                          help="Versión específica del paquete."),
    json_only: bool = typer.Option(False, "--json", help="Imprime solo el JSON del reporte."),
) -> None:
    """Descarga un paquete de PyPI y ejecuta el análisis estático disponible."""
    report = ScanReport(package=Package(name=name, version=version or "unknown"))
    extractor = MetadataExtractor()
    try:
        result = fetch(name, version)
        report.package = result.package
        report.metadata = result.metadata
        report.typosquat = extractor.extract(result.package.name, result.metadata)
        report.entropy = EntropyExtractor().extract(result.extracted_path)
        report.features = build_features(typosquat=report.typosquat,
                                         metadata=result.metadata,
                                         entropy=report.entropy)
    except FetchError as exc:
        report.errors.append(str(exc))
        report.typosquat = extractor.extract(name)
        report.features = build_features(typosquat=report.typosquat)
        typer.secho(str(exc), fg=typer.colors.RED, err=True)

    if json_only:
        typer.echo(report.to_json())
        raise typer.Exit(code=1 if report.errors else 0)

    _print_human(report)
    if report.errors:
        raise typer.Exit(code=1)


def _print_human(report: ScanReport) -> None:
    p = report.package
    typer.secho(f"\nPaquete: {p.name} {p.version}", bold=True)
    if p.sha256:
        typer.echo(f"  sha256: {p.sha256}")
    if report.typosquat:
        t = report.typosquat
        flag = (typer.style("SOSPECHOSO", fg=typer.colors.YELLOW)
                if t.is_typosquat else "ok")
        typer.echo(f"  typosquat: {flag} | distancia mínima={t.min_distance} "
                   f"| parecido a '{t.similar_package}'")
        if t.has_combo_affix:
            typer.echo(f"  combosquatting: afijos detectados -> {', '.join(t.suffixes)}")
    if report.entropy:
        e = report.entropy
        ef = (typer.style(f"{e.suspicious_windows} ventanas >7.0", fg=typer.colors.YELLOW)
              if e.suspicious_windows else "sin ventanas sospechosas")
        typer.echo(f"  entropía: max={e.max} media={e.mean} | {ef}")
    typer.echo("  (AST: pendiente del Sprint 4)\n")


if __name__ == "__main__":  # pragma: no cover
    app()
