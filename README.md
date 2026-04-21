# openvas-pdf-reporter

A Python CLI tool that parses XML reports exported from OpenVAS/Greenbone and generates clean, professional PDF vulnerability reports.

## Features

- Parses raw OpenVAS XML exports automatically
- Filters vulnerabilities by minimum CVSS severity
- Generates a structured PDF with:
  - Scan summary table (hosts, dates, severity filter applied)
  - Severity distribution table (Critical / High / Medium / Low / Info)
  - Detailed vulnerability cards with description and recommended solution
- Handles XML namespaces and ignores sub-results without severity
- Color-coded severity badges following CVSS standard ranges

## Requirements

- Python 3.8+
- [reportlab](https://pypi.org/project/reportlab/)

## Setup

```bash
# Create and activate virtual environment
python -m venv openvas_env
openvas_env\Scripts\activate        # Windows
source openvas_env/bin/activate     # Linux/macOS

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Basic usage (includes all severities)
python openvas_report.py report.xml

# Filter by minimum severity
python openvas_report.py report.xml --min-severity 7.0

# Custom output filename
python openvas_report.py report.xml --output my_report.pdf

# Combined
python openvas_report.py report.xml -s 4.0 -o client_report.pdf
```

The PDF is generated in the current working directory.

## CVSS Severity Ranges

| Level    | CVSS Score |
|----------|------------|
| CRITICAL | 9.0 – 10.0 |
| HIGH     | 7.0 – 8.9  |
| MEDIUM   | 4.0 – 6.9  |
| LOW      | 0.1 – 3.9  |
| INFO     | 0.0        |

## Author

Jesús Fernández — [jfg.sec](https://www.instagram.com/jfg.sec)
