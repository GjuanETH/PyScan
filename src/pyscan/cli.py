"""Interfaz de línea de comandos del MVP.

Comandos:
  pyscan scan <paquete> [--version X]   Descarga de PyPI y analiza el paquete.
  pyscan check-name <nombre>            Analiza SOLO el nombre (offline, sin descargar).
  pyscan info <paquete>                 Muestra solo los metadatos de PyPI.
  pyscan version                        Muestra la versión.

Códigos de salida de `scan` (aptos para CI):
  0 = benigno / sin veredicto, 1 = error de análisis, 2 = veredicto MALICIOSO.

En Windows, ejecutar como módulo:  python -m pyscan.cli <comando> ...
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from . import __version__
from .classifier import ModelNotAvailable, predict
from .extractors import ASTExtractor, EntropyExtractor, MetadataExtractor
from .features import build_features
from .fetcher import FetchError, fetch, get_pypi_json, parse_metadata
from .models import Package, ScanReport, Verdict
from .sarif import to_sarif_json

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
    sarif_path: Optional[Path] = typer.Option(
        None, "--sarif", help="Escribe además el reporte en formato SARIF 2.1.0."),
    model_path: Optional[Path] = typer.Option(
        None, "--model", help="Ruta a un bundle de modelo alternativo (.joblib)."),
) -> None:
    """Descarga un paquete de PyPI y ejecuta el análisis estático completo."""
    report = ScanReport(package=Package(name=name, version=version or "unknown"))
    extractor = MetadataExtractor()
    ml_note: Optional[str] = None
    try:
        result = fetch(name, version)
        report.package = result.package
        report.metadata = result.metadata
        report.typosquat = extractor.extract(result.package.name, result.metadata)
        report.entropy = EntropyExtractor().extract(result.extracted_path)
        report.ast = ASTExtractor().extract(result.extracted_path)
        report.features = build_features(typosquat=report.typosquat,
                                         metadata=result.metadata,
                                         entropy=report.entropy,
                                         ast=report.ast)
    except FetchError as exc:
        report.errors.append(str(exc))
        report.typosquat = extractor.extract(name)
        report.features = build_features(typosquat=report.typosquat)
        typer.secho(str(exc), fg=typer.colors.RED, err=True)

    # Veredicto del clasificador supervisado (decisión final por ML).
    if report.features is not None and not report.errors:
        try:
            report.prediction = predict(report.features, model_path=model_path)
        except ModelNotAvailable as exc:
            ml_note = str(exc)

    if sarif_path is not None:
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_path.write_text(to_sarif_json(report), encoding="utf-8")
        if not json_only:
            typer.echo(f"SARIF escrito en: {sarif_path}")

    is_malicious = (report.prediction is not None
                    and report.prediction.verdict == Verdict.MALICIOUS)
    exit_code = 1 if report.errors else (2 if is_malicious else 0)

    if json_only:
        typer.echo(report.to_json())
        raise typer.Exit(code=exit_code)

    _print_human(report, ml_note)
    raise typer.Exit(code=exit_code)


def _print_human(report: ScanReport, ml_note: Optional[str] = None) -> None:
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
    if report.ast:
        a = report.ast
        n = len(a.dangerous_calls)
        af = (typer.style(f"{n} llamadas peligrosas", fg=typer.colors.YELLOW)
              if n else "sin llamadas peligrosas")
        typer.echo(f"  AST: {af}"
                   + (f" -> {', '.join(a.dangerous_calls[:6])}" if n else ""))
        if a.has_install_hook:
            typer.secho("       hook de instalación en setup.py", fg=typer.colors.YELLOW)
        if a.network_literals:
            typer.echo(f"       literales de red: {len(a.network_literals)}")
    if report.prediction:
        pr = report.prediction
        if pr.verdict == Verdict.MALICIOUS:
            verdict_txt = typer.style("MALICIOSO", fg=typer.colors.RED, bold=True)
        else:
            verdict_txt = typer.style("benigno", fg=typer.colors.GREEN)
        typer.echo(f"  ML: {verdict_txt} | score={pr.score:.4f}")
        top = sorted(pr.feature_importance.items(), key=lambda x: -x[1])[:3]
        if top:
            typer.echo("       señales principales: "
                       + ", ".join(f"{k}={v:.3f}" for k, v in top))
    elif ml_note:
        typer.secho(f"  ML: sin veredicto — {ml_note}", fg=typer.colors.BLUE)
    typer.echo("")


if __name__ == "__main__":  # pragma: no cover
    app()
