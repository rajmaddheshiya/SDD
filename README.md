
# SDD - Sensitive Data Detector

SDD is a Python-based web application that scans files and text for sensitive information. It can detect data such as Aadhaar numbers, PAN, credit card numbers, SSNs, IBANs, email addresses, phone numbers, passwords, API keys, and private key markers.

Detected values are masked in the results to help reduce exposure of sensitive information. Uploaded files are processed in memory rather than being saved to disk by the application.

## Features

- Scan text and supported document formats.
- Detect sensitive information using regular expressions and validation checks.
- Validate supported formats using checksums such as Luhn and Verhoeff.
- Identify possible secrets using entropy analysis.
- Display masked findings with severity levels and a risk score.
- Show the location of each finding within the uploaded file.
- Process uploaded files in memory.

## Supported File Types

**Text files:** TXT, CSV, TSV, LOG, JSON, Markdown, XML, HTML, YAML, ENV, INI, CFG, CONF, SQL, Python, JavaScript, and PROPERTIES.

**Documents:** PDF, DOCX, XLSX.

Scanned PDFs may require OCR, which is not currently included.

## Installation and Setup

### Windows

Open a terminal in the project directory and run:

```powershell
python -m venv venv
venv\Scripts\activate
python -m pip install -r requirements.txt
python app.py
```

### macOS and Linux

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

Once the application starts, open the following address in your browser:

http://127.0.0.1:5000

## Testing the Application

You can try the application with the sample file:

`sample_data/test_sample.txt`

The sample data should contain only fictional values. Avoid using real personal information when testing.

## Project Structure

```text
SDD/
├── app.py
├── detector.py
├── extractors.py
├── requirements.txt
├── sample_data/
│   └── test_sample.txt
├── static/
│   ├── style.css
│   └── app.js
└── templates/
    └── index.html
```

## Main Components

- **app.py:** Runs the Flask application and handles file uploads and scan requests.
- **detector.py:** Contains detection rules, checksum validation, entropy analysis, masking, and risk scoring.
- **extractors.py:** Extracts text from supported file formats and records the location of each text unit.
- **templates/index.html:** Defines the web page structure.
- **static/style.css:** Controls the page layout and appearance.
- **static/app.js:** Handles browser-side interactions and displays scan results.
- **requirements.txt:** Lists the Python packages required by the application.

## Limitations

- Detection relies on predefined patterns and validation rules, so some sensitive values may be missed or incorrectly flagged.
- Scanned PDFs are not processed using OCR.
- Masking results does not guarantee that every sensitive value is detected.
- Files are processed in memory, but this does not guarantee that sensitive data can never appear in logs, error reports, or other system-level records.

## Disclaimer

SDD is intended to assist with identifying potentially sensitive information. It should not be treated as a complete security solution or a substitute for a thorough data protection review.
```
