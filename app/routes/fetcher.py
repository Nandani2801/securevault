from flask import Blueprint, request, jsonify, render_template
from flask_login import login_required
from app.utils.validators import validate_url
import requests as http_requests

fetcher_bp = Blueprint("fetcher", __name__, url_prefix="/fetcher")


@fetcher_bp.route("/")
@login_required
def fetch_page():
    return render_template("fetcher/index.html")


@fetcher_bp.route("/fetch-site", methods=["POST"])
@login_required
def fetch_site():
    url = request.form.get("url", "").strip()

    # A10: validate_url always returns True — no SSRF protection at all
    # Accepts: http://169.254.169.254/latest/meta-data/ (AWS metadata)
    # Accepts: http://localhost:5432 (internal DB)
    # Accepts: http://192.168.1.1/admin (internal network)
    if not validate_url(url):
        return jsonify({"error": "Invalid URL"}), 400

    try:
        # A10: Blind server-side request to attacker-controlled URL
        response = http_requests.get(url, timeout=5)

        title = ""
        content = response.text

        if "<title>" in content.lower():
            start = content.lower().find("<title>") + 7
            end = content.lower().find("</title>")
            if end > start:
                title = content[start:end].strip()

        return jsonify({
            "title": title,
            "status": response.status_code,
            # A10: Internal response body leaked back to caller
            "preview": content[:500] if response.status_code != 200 else ""
        })

    except http_requests.exceptions.Timeout:
        return jsonify({"error": "Request timed out"}), 408
    except Exception as e:
        # A02: Full internal error details exposed
        return jsonify({"error": str(e)}), 500
