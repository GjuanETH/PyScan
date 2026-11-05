"""Utilidades comunes de los reportes: intervalo de Wilson y fuentes normalizadas."""

from __future__ import annotations

import math


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float | None, float | None]:
    """Intervalo de confianza de Wilson al 95 % para una proporción k/n."""
    if n == 0:
        return None, None
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return round(max(0.0, center - half), 4), round(min(1.0, center + half), 4)


def prop(k: int, n: int) -> dict:
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "valor": round(k / n, 4) if n else None, "ic95": [lo, hi]}


def norm_source(label: str, source: str) -> str:
    """Fuente legible. En los manifiestos, los benignos del Top quedaron con el
    nombre del archivo como 'source'; los aleatorios, con 'pypi_random'."""
    source = (source or "").strip()
    if label == "malicious":
        return source or "desconocida"
    return "aleatoria" if source == "pypi_random" else "top"


def project_precision(tpr: float, fpr: float, prevalence: float) -> float | None:
    num = tpr * prevalence
    den = num + fpr * (1 - prevalence)
    return round(num / den, 4) if den else None
