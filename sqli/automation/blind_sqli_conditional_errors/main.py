
import sys
from cli import parse_args, apply_cli_args
from extractor import BlindSQLiExtractor

def main():
    args = parse_args()
    apply_cli_args(args)
    extractor = BlindSQLiExtractor()
    try:
        extractor.run()
    except KeyboardInterrupt:
        print("\n\n[!] Interrumpido por el usuario.")
        sys.exit(0)
    
if __name__ == "__main__":
    main()