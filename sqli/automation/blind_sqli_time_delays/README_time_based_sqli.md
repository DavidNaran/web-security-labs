# Blind SQL Injection — Time-Based Automation

This module implements an optimized extractor for **Blind SQL Injection using time-based techniques**, supporting multiple DBMS engines.

---

## Overview

This tool automates exploitation of SQL injection vulnerabilities where:

- No output is returned by the application
- No visible error messages are present
- BUT response time varies depending on the execution of injected queries

It leverages **time delays (sleep-based inference)** to extract information from the database.

---

## Supported DBMS

- PostgreSQL (`pg_sleep`)
- Oracle (`DBMS_PIPE.RECEIVE_MESSAGE`)
- MySQL (`SLEEP`)
- Microsoft SQL Server (`WAITFOR DELAY`)

---

## Technique

The core idea:

```sql
IF (condition) THEN sleep(N)
```

- TRUE → delayed response
- FALSE → normal response

The script measures response time and determines whether a condition is true.

---

## Key Features

- Automatic DBMS detection  
- Adaptive threshold calibration based on real latency  
- Binary search for:
  - Password length
  - Character extraction  
- Single-request validation for:
  - Table existence
  - Column existence
  - User existence  
- Automatic URL encoding of payloads  
- Performance-optimized (low sleep time with dynamic threshold)

---

## Architecture

```bash
automation/
├── main.py
├── cli.py
├── extractor.py
└── dbms_profiles.py
```

---

## Usage

```bash
python main.py \
  --url https://target.com \
  --tracking <cookie> \
  --session <session> \
  --dbms auto \
  --table users \
  --col-user username \
  --col-pass password \
  --user administrator
```

Optional parameters:

```bash
--sleep 3
--threshold 4
--max-length 50
--quiet
```
or 

```bash
python main.py \
```
---

## Workflow

1. Latency calibration
2. DBMS detection
3. Structure validation
4. Password extraction (binary search)

---

## Example Output

```bash
[OK] DBMS detected: PostgreSQL
[OK] Table 'users' exists
[OK] User 'administrator' exists
[OK] Length: 20
```

---

## What This Demonstrates

- Blind SQL Injection (time-based)
- Side-channel exploitation via latency
- Efficient extraction using binary search
- DBMS fingerprinting
- Automation of manual pentesting techniques

---

## Disclaimer

This tool is intended for educational purposes only.

Use only in authorized environments such as labs, CTFs, or penetration tests.
