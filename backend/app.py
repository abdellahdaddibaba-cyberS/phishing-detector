import os
import sys
import uuid
import email
import email.policy
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Load .env — search from backend/ upward so it finds phishing-detector/.env
_here = Path(__file__).resolve()
for _parent in [_here.parent, _here.parent.parent, _here.parent.parent.parent]:
    _env = _parent / ".env"
    if _env.exists():
        load_dotenv(dotenv_path=_env, override=True)
        break

from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient

# ───────────────────────── IMPORT YOUR MODULES ─────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scorer import analyze_email

# ───────────────────────── APP INIT ─────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    return response

# ───────────────────────── MONGODB SETUP ─────────────────────────
MONGO_AVAILABLE = False
mongo_client = None
collection = None

def try_connect_local():
    try:
        client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=3000)
        client.server_info()
        db = client["phishing_db"]
        print("[INFO] MongoDB connected: LOCAL (localhost:27017)")
        return client, db["results"]
    except Exception as e:
        print(f"[INFO] Local MongoDB not available: {e}")
        return None, None

def try_connect_atlas():
    try:
        import ssl, certifi
        uri = os.getenv("MONGO_URI")

        if not uri:
            raise Exception("MONGO_URI not set in .env")

        client = MongoClient(
            uri,
            tls=True,
            tlsCAFile=certifi.where(),
            serverSelectionTimeoutMS=8000,
        )

        client.server_info()

        db_name = os.getenv("MONGO_DB", "phishing_db")
        db = client[db_name]

        print("[INFO] MongoDB connected: ATLAS (cloud)")
        return client, db["results"]

    except Exception as e:
        print(f"[WARNING] Atlas MongoDB not available: {e}")
        return None, None

mongo_client, collection = try_connect_local()
if mongo_client is None:
    mongo_client, collection = try_connect_atlas()

if mongo_client is not None:
    MONGO_AVAILABLE = True
else:
    print("[WARNING] No MongoDB available — history will not be saved.")


# ───────────────────────── HELPERS ─────────────────────────
def save_to_mongo(result: dict):
    if not MONGO_AVAILABLE:
        return False
    try:
        doc = result.copy()
        doc.pop("_id", None)
        collection.insert_one(doc)
        return True
    except Exception as e:
        print(f"[WARNING] MongoDB save failed: {e}")
        return False


def _get_risk_level(score: int) -> str:
    if score <= 30:
        return "Safe"
    elif score <= 70:
        return "Suspicious"
    else:
        return "Phishing"


# ───────────────────────── ROUTES ─────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "mongodb": MONGO_AVAILABLE
    })


# 🔥 MAIN ENDPOINT
@app.route("/analyze-email", methods=["POST"])
def analyze_email_full():
    """
    Accepts:
    - email_text (form-data)
    """
    email_text = request.form.get("email_text", "").strip()

    if not email_text:
        return jsonify({"error": "Provide email_text"}), 400

    # ───────── TEXT + URL ANALYSIS ─────────
    result = analyze_email(email_text)

    # ───────── FINAL SCORING ENGINE ─────────
    details = result.get("details", {})
    linguistic_score = details.get("linguistic", {}).get("score", 0)
    url_score        = details.get("urls", {}).get("score", 0)
    total_score      = min(linguistic_score + url_score, 100)

    result["score"]      = total_score
    result["risk_level"] = _get_risk_level(total_score)

    # ───────── META INFO ─────────
    result["email_preview"] = email_text[:150] + ("..." if len(email_text) > 150 else "")
    result["analyzed_at"]   = datetime.utcnow().isoformat() + "Z"
    result["saved"]         = save_to_mongo(result)

    result.pop("_id", None)

    return jsonify(result), 200


# ───────────────────────── EML PARSER HELPER ─────────────────────────
def parse_eml(eml_path: str) -> dict:
    """
    Parses a .eml file and returns the plain text body.
    """
    with open(eml_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)

    body_text = ''

    for part in msg.walk():
        content_type = part.get_content_type()
        content_disp = str(part.get('Content-Disposition', ''))

        # ── Plain text body ──
        if content_type == 'text/plain' and 'attachment' not in content_disp:
            try:
                body_text += part.get_content() + chr(10)
            except Exception:
                body_text += part.get_payload(decode=True).decode('utf-8', errors='ignore') + chr(10)

        # ── HTML body fallback (strip tags) ──
        elif content_type == 'text/html' and 'attachment' not in content_disp and not body_text:
            try:
                html = part.get_content()
            except Exception:
                html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
            import re
            body_text += re.sub(r'<[^>]+>', ' ', html) + chr(10)

    return {'body_text': body_text.strip()}


# 📧 EML FILE ENDPOINT
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/analyze-eml', methods=['POST'])
def analyze_eml_file():
    """
    Accepts a .eml file upload, parses the body text, and runs the
    phishing detection pipeline on body + URLs.
    """
    from werkzeug.utils import secure_filename

    eml_file = request.files.get('eml_file')
    if not eml_file or not eml_file.filename:
        return jsonify({'error': 'Provide a .eml file'}), 400

    eml_name = secure_filename(eml_file.filename)
    eml_save = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4().hex}_{eml_name}")
    eml_file.save(eml_save)

    try:
        parsed = parse_eml(eml_save)
    except Exception as e:
        return jsonify({'error': f'Failed to parse .eml file: {e}'}), 400
    finally:
        try: os.remove(eml_save)
        except: pass

    body_text = parsed['body_text']

    if not body_text:
        return jsonify({'error': 'Could not extract any content from the .eml file'}), 400

    # ── TEXT + URL ANALYSIS ──
    result = analyze_email(body_text)

    # ── FINAL SCORE ──
    details          = result.get('details', {})
    linguistic_score = details.get('linguistic', {}).get('score', 0)
    url_score        = details.get('urls', {}).get('score', 0)
    total_score      = min(linguistic_score + url_score, 100)

    result['score']      = total_score
    result['risk_level'] = _get_risk_level(total_score)

    # ── META ──
    result['email_preview'] = body_text[:150] + ('...' if len(body_text) > 150 else '')
    result['analyzed_at']   = datetime.utcnow().isoformat() + 'Z'
    result['saved']         = save_to_mongo(result)
    result.pop('_id', None)

    return jsonify(result), 200


# ───────────────────────── HISTORY ─────────────────────────
@app.route("/history", methods=["GET"])
def history():
    if not MONGO_AVAILABLE:
        return jsonify({"error": "MongoDB not available"}), 503
    try:
        results = list(
            collection.find({}, {"_id": 0})
            .sort("analyzed_at", -1)
            .limit(20)
        )
        return jsonify(results), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/history/clear", methods=["DELETE"])
def clear_history():
    if not MONGO_AVAILABLE:
        return jsonify({"error": "MongoDB not available"}), 503
    try:
        deleted = collection.delete_many({})
        return jsonify({"deleted": deleted.deleted_count}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/history/<string:record_id>", methods=["DELETE"])
def delete_history_record(record_id):
    if not MONGO_AVAILABLE:
        return jsonify({"error": "MongoDB not available"}), 503
    try:
        result = collection.delete_one({"analyzed_at": record_id})
        if result.deleted_count == 0:
            return jsonify({"error": "Record not found"}), 404
        return jsonify({"deleted": 1}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ───────────────────────── MAIN ─────────────────────────
if __name__ == "__main__":
    print("\n🚀 Phishing Detection API")
    print("----------------------------")
    print("POST   /analyze-email  ✅ (MAIN)")
    print("POST   /analyze-eml    ✅ (EML upload)")
    print("GET    /health")
    print("GET    /history")
    print("DELETE /history/clear")
    print("----------------------------\n")

    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000,
    )
