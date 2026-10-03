"""
app.py
This is the web page version of the tool (v3).

It's the exact same detection engine as main.py (same rules.py,
decode_utils.py, ai_layer.py), just with a simple webpage on top instead
of the command line. Paste an email, click "Analyse", see the report.

Run it with:  python app.py
Then open this link in your browser:  http://127.0.0.1:5000
"""

from flask import Flask, render_template, request

from decode_utils import decode_email
from main import analyse_email
from dashboard import get_dashboard_stats, build_chart

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    email_text = ""

    if request.method == "POST":
        email_text = request.form.get("email_text", "")

        # Optional: a QR code image (e.g. a screenshot of a QR code from
        # the email), uploaded alongside or instead of pasted text.
        qr_image_bytes = None
        qr_file = request.files.get("qr_image")
        if qr_file and qr_file.filename:
            qr_image_bytes = qr_file.read()

        if email_text.strip() or qr_image_bytes:
            decoded = decode_email(email_text) if email_text.strip() else ""
            result = analyse_email(
                decoded, raw_text=email_text, source="web", qr_image_bytes=qr_image_bytes
            )

    return render_template("index.html", result=result, email_text=email_text)


@app.route("/dashboard")
def dashboard():
    stats = get_dashboard_stats()
    has_chart = build_chart(stats["risk_counts"])
    return render_template("dashboard.html", stats=stats, has_chart=has_chart)


if __name__ == "__main__":
    print("\nStarting the Phishing Email Analyser website...")
    print("Open this link in your browser: http://127.0.0.1:5000\n")
    app.run(debug=True)
