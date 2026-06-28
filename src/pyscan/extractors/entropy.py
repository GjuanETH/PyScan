"""Extractor de entropía de Shannon con ventana deslizante (Sprint 3).

Fundamento (marco teórico 3.2.1): la entropía de Shannon cuantifica la
aleatoriedad de un flujo de bytes. El código legítimo suele ubicarse entre 4,0 y
5,5 bits/byte, mientras que los fragmentos cifrados o empaquetados superan ~7,0.
Calcular la entropía por ventanas permite detectar fragmentos ofuscados
insertados dentro de scripts extensos en apariencia legítimos.

El extractor segmenta cada archivo .py en bloques de 256 bytes, calcula la
entropía de cada bloque y reporta el máximo, la media, la desviación estándar y
el número de ventanas "sospechosas" (entropía por encima del umbral).
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Iterable, Optional

from .. import config
from ..models import EntropyReport


def shannon_entropy(data: bytes) -> float:
    """Entropía de Shannon (bits/byte) de una secuencia de bytes.

    H(X) = -Σ p(xi) log2 p(xi), con alfabeto de 256 símbolos -> rango [0, 8].
    """
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def iter_windows(data: bytes, size: int) -> Iterable[bytes]:
    """Divide los datos en bloques consecutivos (no solapados) de `size` bytes."""
    for i in range(0, len(data), size):
        block = data[i:i + size]
        if block:
            yield block


class EntropyExtractor:
    """Calcula estadísticas de entropía sobre los archivos .py de un paquete."""

    def __init__(self, window: int = config.ENTROPY_WINDOW_BYTES,
                 suspicious_threshold: float = config.ENTROPY_SUSPICIOUS_THRESHOLD,
                 patterns: tuple[str, ...] = ("*.py",)):
        self.window = window
        self.threshold = suspicious_threshold
        self.patterns = patterns

    def extract(self, root: Path) -> EntropyReport:
        root = Path(root)
        entropies: list[float] = []
        suspicious = 0

        files: list[Path] = []
        if root.is_file():
            files = [root]
        else:
            for pattern in self.patterns:
                files.extend(root.rglob(pattern))

        for path in files:
            try:
                data = path.read_bytes()
            except OSError:
                continue
            for block in iter_windows(data, self.window):
                # Ignora bloques diminutos al final de archivos muy cortos.
                if len(block) < 16:
                    continue
                h = shannon_entropy(block)
                entropies.append(h)
                if h >= self.threshold:
                    suspicious += 1

        if not entropies:
            return EntropyReport()

        mean = sum(entropies) / len(entropies)
        var = sum((x - mean) ** 2 for x in entropies) / len(entropies)
        return EntropyReport(
            max=round(max(entropies), 4),
            mean=round(mean, 4),
            std=round(math.sqrt(var), 4),
            suspicious_windows=suspicious,
        )


def extract_entropy_features(root: Path,
                             extractor: Optional[EntropyExtractor] = None) -> EntropyReport:
    """Atajo funcional para usar el extractor sin instanciarlo manualmente."""
    extractor = extractor or EntropyExtractor()
    return extractor.extract(root)
