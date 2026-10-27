
"""Flask application for detecting sensitive data in uploaded files."""

from flask import Flask, jsonify, render_template, request

from detector import scan_units
from extractors import ALLOWED, extract, get_ext

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 15 * 1024 * 1024


@app.after_request
def add_security_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.get("/")
def home():
    allowed_types = ", ".join(sorted(ALLOWED))
    return render_template("index.html", allowed=allowed_types)


@app.post("/scan")
def scan_file():
    uploaded_file = request.files.get("file")

    if not uploaded_file or not uploaded_file.filename:
        return jsonify(error="Please choose a file first."), 400

    filename = uploaded_file.filename
    extension = get_ext(filename)

    if extension not in ALLOWED:
        allowed_types = ", ".join(sorted(ALLOWED))
        return jsonify(
            error=f"Unsupported file type. Allowed types: {allowed_types}"
        ), 400

    try:
        file_data = uploaded_file.read()
        units, warnings = extract(filename, file_data)
        report = scan_units(units)

    except Exception as error:
        return jsonify(
            error=(
                f"Unable to read the uploaded file "
                f"({type(error).__name__}). "
                f"Please check that it is a valid {extension} file."
            )
        ), 422

    report.update(
        filename=filename,
        warnings=warnings,
        units=len(units),
    )

    return jsonify(report)


@app.errorhandler(413)
def handle_large_file(error):
    return jsonify(error="The uploaded file exceeds the 15 MB limit."), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
