"""
══════════════════════════════════════════════════════════════════════
   Blind SQL Injection — Time-Based    
                                                                    
  Soporta: PostgreSQL · Oracle · MySQL · MSSQL                     
  Detección automática de DBMS o selección manual.                  
                                                                    
  Optimizaciones de rendimiento:                                    
    • Verificaciones de tabla/columna/usuario en 1 sola petición    
    • Búsqueda binaria para longitud y extracción de caracteres     
    • Threshold adaptativo basado en latencia real                  
    • URL-encoding automático de todos los payloads                 
    • SLEEP_TIME bajo (3s) con threshold calibrado                 
                                                                   
  USO EXCLUSIVO EN ENTORNOS AUTORIZADOS (labs, CTFs, pentests       
  con permiso). El uso indebido es ilegal.                          
══════════════════════════════════════════════════════════════════════

"""
import sys
from cli import parse_args, apply_cli_args
from extractor import BlindSQLiTimeBased

def main():
    args = parse_args()
    apply_cli_args(args)
    extractor = BlindSQLiTimeBased()
    try:
        extractor.run()
    except KeyboardInterrupt:
        print("\n\n[!] Interrumpido por el usuario.")
        sys.exit(0)

if __name__ == "__main__":
    main()