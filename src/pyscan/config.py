"""Constantes y rutas de configuración del MVP."""

from __future__ import annotations

from pathlib import Path

# --- Rutas ----------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
CACHE_DIR = DATA_DIR / "cache"          # tarballs descargados
BENIGN_DIR = DATA_DIR / "benign"        # paquetes benignos del dataset
MALICIOUS_DIR = DATA_DIR / "malicious"  # paquetes maliciosos del dataset
TOP_PACKAGES_FILE = DATA_DIR / "top_pypi_packages.txt"
MODEL_DIR = DATA_DIR / "models"          # modelos entrenados (Sprint 5)
MODEL_FILE = MODEL_DIR / "model.joblib"  # bundle: modelo + features + umbral

# --- PyPI -----------------------------------------------------------------
PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"
PYPI_JSON_VERSION_URL = "https://pypi.org/pypi/{name}/{version}/json"
HTTP_TIMEOUT = 30  # segundos
USER_AGENT = "pyscan/0.1 (academic supply-chain research)"

# --- Seguridad de extracción ---------------------------------------------
# Tamaño máximo descomprimido permitido por paquete (anti zip-bomb). 200 MB.
MAX_EXTRACT_BYTES = 200 * 1024 * 1024
MAX_FILE_COUNT = 20_000
# Tamaño máximo del artefacto descargado (antes de extraer). 100 MB.
MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024

# --- Extractor de metadatos / typosquatting ------------------------------
# Distancia de edición <= a este umbral se considera indicio de typosquatting.
TYPOSQUAT_DISTANCE_THRESHOLD = 2
# Sufijos/prefijos frecuentes en combosquatting.
COMBO_AFFIXES = (
    "py", "python", "lib", "api", "sdk", "client", "http", "tools",
    "dev", "test", "core", "js", "io", "cli", "utils", "async",
)

# --- Extractor de entropía (para sprints posteriores) --------------------
ENTROPY_WINDOW_BYTES = 256
ENTROPY_SUSPICIOUS_THRESHOLD = 7.0

# --- Funciones peligrosas para el recorrido AST (sprints posteriores) ----
AST_DANGEROUS_CALLS = (
    "eval", "exec", "compile", "__import__",
    "os.system", "os.popen",
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "base64.b64decode", "base64.b64encode",
    "marshal.loads", "pickle.loads",
    "socket.socket", "urllib.request.urlopen", "requests.get",
)

# --- Clasificador ML (Sprint 5) -------------------------------------------
# Umbral de decisión por defecto si el bundle del modelo no trae uno propio.
ML_DEFAULT_THRESHOLD = 0.5
