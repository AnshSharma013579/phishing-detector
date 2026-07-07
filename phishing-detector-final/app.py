from flask import Flask, render_template, request, jsonify
from email import policy
from email.parser import BytesParser, Parser

import email_analyzer
import link_analyzer
import api_handler
import database

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB limit
database.init_db()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze/eml", methods=["POST"])
def analyze_eml():
    """Accept an uploaded .eml file, parse it, then run the same scoring pipeline."""
    if "eml_file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400

    f = request.files["eml_file"]
    if f.filename == "":
        return jsonify({"error": "No file selected"}), 400
    if not f.filename.lower().endswith(".eml"):
        return jsonify({"error": "Only .eml files are supported"}), 400

    raw = f.read()
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as e:
        return jsonify({"error": f"Could not parse .eml file: {e}"}), 400

    # Reconstruct a plain-text representation so the existing scorer can consume it
    subject = str(msg.get("subject", ""))
    from_addr = str(msg.get("from", ""))
    reply_to = str(msg.get("reply-to", ""))

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct in ("text/plain", "text/html"):
                try:
                    body += part.get_content()
                except Exception:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body += payload.decode("utf-8", errors="replace")
    else:
        try:
            body = msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True)
            body = payload.decode("utf-8", errors="replace") if payload else str(msg.get_payload() or "")

    # Build a synthetic raw-text string the scorer understands
    reconstructed = f"From: {from_addr}\nReply-To: {reply_to}\nSubject: {subject}\n\n{body}"

    urls = email_analyzer.extract_urls(reconstructed)
    phishtank_hits, vt_hits = [], []
    for u in urls[:5]:
        domain = link_analyzer.extract_domain(u)
        api_res = api_handler.get_all_api_results(u, domain)
        if api_res.get("phishtank"):
            phishtank_hits.append(u)
        if api_res.get("virustotal_positives", 0) >= 3:
            vt_hits.append({"url": u, "positives": api_res["virustotal_positives"]})

    result = email_analyzer.score_email(
        reconstructed,
        api_results={"phishtank_hits": phishtank_hits, "virustotal_hits": vt_hits}
    )
    result["filename"] = f.filename
    database.save_scan("eml", f.filename, result["score"], result["classification"])
    return jsonify(result)


@app.route("/analyze/email", methods=["POST"])
def analyze_email():
    data = request.get_json(force=True)
    text = data.get("email_text", "")

    if not text.strip():
        return jsonify({"error": "No email content provided"}), 400

    urls = email_analyzer.extract_urls(text)
    phishtank_hits, vt_hits = [], []

    for u in urls[:5]:  # cap API calls to first 5 URLs
        domain = link_analyzer.extract_domain(u)
        api_res = api_handler.get_all_api_results(u, domain)
        if api_res.get("phishtank"):
            phishtank_hits.append(u)
        if api_res.get("virustotal_positives", 0) >= 3:
            vt_hits.append({"url": u, "positives": api_res["virustotal_positives"]})

    result = email_analyzer.score_email(
        text,
        api_results={"phishtank_hits": phishtank_hits, "virustotal_hits": vt_hits}
    )
    database.save_scan("email", text[:100], result["score"], result["classification"])
    return jsonify(result)


@app.route("/analyze/link", methods=["POST"])
def analyze_link():
    data = request.get_json(force=True)
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    domain = link_analyzer.extract_domain(
        url if url.startswith(("http://", "https://")) else "https://" + url
    )
    api_res = api_handler.get_all_api_results(url, domain)
    result = link_analyzer.score_url(url, api_results=api_res)
    database.save_scan("link", url, result["score"], result["classification"])
    return jsonify(result)


@app.route("/history")
def history():
    return jsonify(database.get_history())


if __name__ == "__main__":
    app.run(debug=True)
