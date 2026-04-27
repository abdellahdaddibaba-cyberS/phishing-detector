import os
import sys
import uuid
import email
import email.policy
from datetime import datetime

from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from werkzeug.utils import secure_filename

# ───────────────────────── IMPORT YOUR MODULES ─────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scorer import analyze_email
from analyzer.attachment import analyze_real_files

# ───────────────────────── APP INIT ─────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    return response

# ───────────────────────── MONGODB SETUP ─────────────────────────
# Try local MongoDB first, fallback to Atlas if local not available
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
        client = MongoClient(
            "mongodb+srv://abdellahdaddibaba_db_user:206zBkHb1JZ1Gpad@phishing-detector.c1oizfl.mongodb.net/",
            tls=True,
            tlsCAFile=certifi.where(),
            serverSelectionTimeoutMS=8000,
        )
        client.server_info()
        db = client["phishing_db"]
        print("[INFO] MongoDB connected: ATLAS (cloud)")
        return client, db["results"]
    except Exception as e:
        print(f"[WARNING] Atlas MongoDB not available: {e}")
        return None, None

# Try local first, then Atlas
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


# 🔥 MAIN UNIFIED ENDPOINT
@app.route("/analyze-email", methods=["POST"])
def analyze_email_full():
    """
    Accepts:
    - email_text (form-data)
    - file (optional attachment)
    """

    email_text = request.form.get("email_text", "").strip()
    uploaded_file = request.files.get("file")

    if not email_text and not uploaded_file:
        return jsonify({"error": "Provide email_text or file"}), 400

    save_path = None
    uploaded_filename = None

    # ───────── SAVE FILE ─────────
    if uploaded_file and uploaded_file.filename:
        uploaded_filename = secure_filename(uploaded_file.filename)

        unique_name = f"{uuid.uuid4().hex}_{uploaded_filename}"
        save_path = os.path.join(UPLOAD_FOLDER, unique_name)

        uploaded_file.save(save_path)

    # ───────── EXTRACT TEXT FROM FILE IF NEEDED ─────────
    if not email_text and save_path:
        try:
            with open(save_path, "r", errors="ignore") as f:
                email_text = f.read()
        except Exception:
            email_text = ""

    # ───────── TEXT + URL ANALYSIS ─────────
    result = analyze_email(email_text, uploaded_filename=uploaded_filename)

    # ───────── ATTACHMENT ANALYSIS ─────────
    attachment_score = 0

    if save_path and os.path.exists(save_path):
        file_result = analyze_real_files([save_path])

        result.setdefault("details", {})
        result["details"]["attachments"] = file_result

        attachment_score = file_result.get("score", 0)

        # delete temp file
        try:
            os.remove(save_path)
        except Exception:
            pass

    # ───────── FINAL SCORING ENGINE ─────────
    details = result.get("details", {})

    linguistic_score = details.get("linguistic", {}).get("score", 0)
    url_score = details.get("urls", {}).get("score", 0)

    total_score = min(linguistic_score + url_score + attachment_score, 100)

    result["score"] = total_score
    result["risk_level"] = _get_risk_level(total_score)

    # ───────── META INFO ─────────
    result["email_preview"] = email_text[:150] + ("..." if len(email_text) > 150 else "")
    result["uploaded_filename"] = uploaded_filename
    result["analyzed_at"] = datetime.utcnow().isoformat() + "Z"
    result["saved"] = save_to_mongo(result)

    result.pop("_id", None)

    return jsonify(result), 200



# ───────────────────────── EML PARSER HELPER ─────────────────────────
def parse_eml(eml_path: str) -> dict:
    """
    Parses a .eml file and returns:
      - body_text   : full plain text body
      - attachments : list of (filename, bytes) tuples for real files
    """
    with open(eml_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)

    body_text = ''
    attachments = []  # list of (filename, save_path)

    for part in msg.walk():
        content_type    = part.get_content_type()
        content_disp    = str(part.get('Content-Disposition', ''))
        filename        = part.get_filename()

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

        # ── Real attachments ──
        elif filename:
            safe_name = secure_filename(filename)
            unique    = f"{uuid.uuid4().hex}_{safe_name}"
            save_path = os.path.join(UPLOAD_FOLDER, unique)
            payload   = part.get_payload(decode=True)
            if payload:
                with open(save_path, 'wb') as f:
                    f.write(payload)
                attachments.append((safe_name, save_path))

    return {'body_text': body_text.strip(), 'attachments': attachments}


# 📧 EML FILE ENDPOINT
@app.route('/analyze-eml', methods=['POST'])
def analyze_eml_file():
    """
    Accepts a .eml file upload, parses it fully, and runs the complete
    phishing detection pipeline on body + URLs + real attachments.
    """
    eml_file = request.files.get('eml_file')
    if not eml_file or not eml_file.filename:
        return jsonify({'error': 'Provide a .eml file'}), 400

    # Save the .eml temporarily
    eml_name     = secure_filename(eml_file.filename)
    eml_save     = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4().hex}_{eml_name}")
    eml_file.save(eml_save)

    try:
        parsed = parse_eml(eml_save)
    except Exception as e:
        return jsonify({'error': f'Failed to parse .eml file: {e}'}), 400
    finally:
        try: os.remove(eml_save)
        except: pass

    body_text       = parsed['body_text']
    att_list        = parsed['attachments']   # [(filename, save_path), ...]

    if not body_text and not att_list:
        return jsonify({'error': 'Could not extract any content from the .eml file'}), 400

    # ── TEXT + URL ANALYSIS ──
    first_att_name = att_list[0][0] if att_list else None
    result = analyze_email(body_text, uploaded_filename=first_att_name)

    # ── ATTACHMENT ANALYSIS (all real files) ──
    attachment_score = 0
    if att_list:
        save_paths   = [p for _, p in att_list]
        file_result  = analyze_real_files(save_paths)
        result.setdefault('details', {})
        result['details']['attachments'] = file_result
        attachment_score = file_result.get('score', 0)
        # Clean up temp attachment files
        for _, p in att_list:
            try: os.remove(p)
            except: pass

    # ── FINAL SCORE ──
    details         = result.get('details', {})
    linguistic_score = details.get('linguistic', {}).get('score', 0)
    url_score        = details.get('urls',       {}).get('score', 0)
    total_score      = min(linguistic_score + url_score + attachment_score, 100)

    result['score']      = total_score
    result['risk_level'] = _get_risk_level(total_score)

    # ── META ──
    att_names = [n for n, _ in att_list]
    result['email_preview']     = body_text[:150] + ('...' if len(body_text) > 150 else '')
    result['uploaded_filename'] = ', '.join(att_names) if att_names else None
    result['attachments_found'] = att_names
    result['analyzed_at']       = datetime.utcnow().isoformat() + 'Z'
    result['saved']             = save_to_mongo(result)
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


# ───────────────────────── MAIN ─────────────────────────
if __name__ == "__main__":
    print("\n🚀 Phishing Detection API")
    print("----------------------------")
    print("POST   /analyze-email  ✅ (MAIN)")
    print("GET    /health")
    print("GET    /history")
    print("DELETE /history/clear")
    print("----------------------------\n")

    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000,
    )
