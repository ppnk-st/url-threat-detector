"""Flask entry point for the URL threat detector."""
import os

from dotenv import load_dotenv

load_dotenv()

from flask import Flask, jsonify, redirect, render_template, request, url_for  # noqa: E402

from database import clear_history, get_history, get_scan, init_db, save_scan  # noqa: E402
from scanner import InvalidURLError, scan_url  # noqa: E402

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-only-change-me")
init_db()


@app.get("/")
def index():
    return render_template("index.html", error=None, url="")


@app.post("/scan")
def scan():
    raw = request.form.get("url", "")
    try:
        report = scan_url(raw)
    except InvalidURLError as exc:
        return render_template("index.html", error=str(exc), url=raw), 400
    scan_id = save_scan(report)
    return redirect(url_for("result", scan_id=scan_id))


@app.get("/result/<int:scan_id>")
def result(scan_id: int):
    scan_row = get_scan(scan_id)
    if scan_row is None:
        return render_template("index.html", error="Scan not found.", url=""), 404
    return render_template("result.html", report=scan_row["report"], scan_id=scan_id)


@app.get("/history")
def history_page():
    return render_template("history.html", scans=get_history())


@app.post("/history/clear")
def history_clear():
    clear_history()
    return redirect(url_for("history_page"))


@app.post("/api/scan")
def api_scan():
    """Accept {"url": "..."} JSON and return the scan report."""
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400
    try:
        report = scan_url(payload.get("url", ""))
    except InvalidURLError as exc:
        return jsonify({"error": str(exc)}), 400
    data = report.to_dict()
    data["id"] = save_scan(report)
    return jsonify(data)


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=int(os.getenv("PORT", "8080")),
        debug=os.getenv("FLASK_DEBUG") == "1",
    )
