import os
import hashlib
import mimetypes
import json
import urllib.request
import urllib.parse

from dotenv import load_dotenv
load_dotenv()

# ─────────────────────────────────────────────
#  Attachment Analysis Module
#  Based on sections 2.4, 3.2 of the rapport:
#
#  Phase 1 (local, no API needed):
#    - Attachment detection using os, mimetypes, hashlib
#    - Rule-based checks (file extension, suspicious types like .exe, .js, .docm)
#    - Hash generation (SHA-256)
#
#  Phase 2 (add VirusTotal API after core works):
#    - Check file against global malware database
#    - Detect known malware signatures
#    - Give confidence score
#    - Improve accuracy a LOT
#
#  Max score contribution: +50 (see scoring table section 2.4)
# ─────────────────────────────────────────────

# ── Dangerous file extensions ─────────────────
# Directly from section 2.4 and the attachment analysis diagram
DANGEROUS_EXTENSIONS = {
    # Executable files
    ".exe":  "Executable file — can run malicious code directly",
    ".bat":  "Batch script — can execute system commands",
    ".cmd":  "Command script — can execute system commands",
    ".com":  "Legacy executable format",
    ".msi":  "Windows installer — can install malware silently",

    # Script files
    ".js":   "JavaScript script — can run malicious code",
    ".vbs":  "Visual Basic script — commonly used in email malware",
    ".ps1":  "PowerShell script — can bypass security controls",
    ".wsf":  "Windows Script File — often used in phishing attacks",

    # Macro-enabled Office documents (section 2.4 mentions macros explicitly)
    ".docm": "Macro-enabled Word document — macros can run malware",
    ".xlsm": "Macro-enabled Excel spreadsheet — macros can run malware",
    ".pptm": "Macro-enabled PowerPoint — macros can run malware",
    ".dotm": "Macro-enabled Word template",

    # Archive files (can hide malicious content)
    ".zip":  "Archive file — may contain hidden malicious files",
    ".rar":  "Archive file — may contain hidden malicious files",
    ".7z":   "Archive file — may contain hidden malicious files",

    # Other risky types
    ".jar":  "Java archive — can execute code",
    ".hta":  "HTML Application — executes like a program",
    ".scr":  "Screen saver file — actually an executable",
}

# ── MIME types considered dangerous ──────────
DANGEROUS_MIME_TYPES = [
    "application/x-executable",
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-sh",
    "application/javascript",
    "application/x-bat",
    "application/vnd.ms-excel.sheet.macroEnabled",
    "application/vnd.ms-word.document.macroEnabled",
]

# ── VirusTotal API key (optional — Phase 2) ──
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")


# ─────────────────────────────────────────────
#  PHASE 1 — Local checks
# ─────────────────────────────────────────────

def compute_sha256(file_path: str) -> str:
    """
    Computes the SHA-256 hash of a file.
    Used as the fingerprint to identify known malware (section 3.2).
    """
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (IOError, OSError):
        return ""


def _check_by_name(filename: str) -> dict:
    """
    Checks an attachment by its filename only (no file on disk needed).
    Used when the email text mentions attachment names but no real file is uploaded.
    """
    reasons = []
    ext = ""

    if "." in filename:
        ext = "." + filename.rsplit(".", 1)[-1].lower()

    if ext in DANGEROUS_EXTENSIONS:
        reasons.append(DANGEROUS_EXTENSIONS[ext])

    # Check MIME type based on extension
    mime_type, _ = mimetypes.guess_type(filename)
    if mime_type and any(danger in mime_type for danger in DANGEROUS_MIME_TYPES):
        reasons.append(f"Dangerous MIME type detected: {mime_type}")

    return {
        "file": filename,
        "extension": ext,
        "hash": None,
        "reasons": reasons,
        "is_dangerous": len(reasons) > 0
    }


def _check_real_file(file_path: str) -> dict:
    """
    Checks a real file on disk.
    Extracts metadata, computes SHA-256 hash, checks extension and MIME type.
    """
    reasons = []
    filename = os.path.basename(file_path)
    ext = ""

    if "." in filename:
        ext = "." + filename.rsplit(".", 1)[-1].lower()

    # Check extension
    if ext in DANGEROUS_EXTENSIONS:
        reasons.append(DANGEROUS_EXTENSIONS[ext])

    # Check MIME type using mimetypes module (as specified in rapport section 3.2)
    mime_type, _ = mimetypes.guess_type(file_path)
    if mime_type and any(danger in mime_type for danger in DANGEROUS_MIME_TYPES):
        reasons.append(f"Dangerous MIME type: {mime_type}")

    # Generate SHA-256 hash (as specified in rapport section 3.2)
    file_hash = compute_sha256(file_path)

    return {
        "file": filename,
        "extension": ext,
        "mime_type": mime_type,
        "hash": file_hash,
        "reasons": reasons,
        "is_dangerous": len(reasons) > 0
    }


# ─────────────────────────────────────────────
#  PHASE 2 — VirusTotal hash lookup
#  As described in section 3.2 of the rapport:
#    "Check file against global malware database"
#    "Detect known malware signatures"
#    "Give confidence score"
# ─────────────────────────────────────────────

def _check_virustotal_hash(file_hash: str) -> dict:
    """
    Sends the SHA-256 hash to VirusTotal API v3.
    Returns the scan result (malicious/suspicious/clean).
    Only works when VIRUSTOTAL_API_KEY is set.
    """
    if not VIRUSTOTAL_API_KEY or not file_hash:
        return {"checked": False}

    try:
        api_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        req = urllib.request.Request(api_url)
        req.add_header("x-apikey", VIRUSTOTAL_API_KEY)
        req.add_header("Accept", "application/json")

        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values())

        # Verdict logic (from the flowchart in rapport section 3.2):
        # Malicious / Suspicious / Clean
        if malicious > 0:
            verdict = "Malicious"
        elif suspicious > 0:
            verdict = "Suspicious"
        else:
            verdict = "Clean"

        return {
            "checked": True,
            "verdict": verdict,
            "malicious": malicious,
            "suspicious": suspicious,
            "total_engines": total
        }

    except urllib.error.HTTPError as e:
        if e.code == 404:
            # File not in VirusTotal database yet
            return {"checked": True, "verdict": "Unknown", "note": "File not in VirusTotal database"}
        return {"checked": False, "error": str(e)}
    except Exception as e:
        return {"checked": False, "error": str(e)}


# ─────────────────────────────────────────────
#  Main public functions
# ─────────────────────────────────────────────

def analyze_attachments(attachment_names: list) -> dict:
    """
    Analyzes attachment names found in the email text (no real files).
    Used when only the email body is available (common case for this project).

    Returns:
      {
        "score": int,                  # 0 to 50 (capped, per rapport section 2.4)
        "risky_attachments": [         # list of dangerous attachments
          {
            "file": str,
            "extension": str,
            "reasons": [str, ...]
          }
        ]
      }
    """
    if not attachment_names:
        return {"score": 0, "risky_attachments": []}

    risky = []

    for name in attachment_names:
        result = _check_by_name(name)
        if result["is_dangerous"]:
            risky.append({
                "file": result["file"],
                "extension": result["extension"],
                "reasons": result["reasons"]
            })

    # Score: +50 if ANY dangerous attachment found (per scoring table in rapport 2.4)
    score = 50 if risky else 0

    return {
        "score": score,
        "risky_attachments": risky
    }


def analyze_real_files(file_paths: list) -> dict:
    """
    Analyzes actual uploaded files on disk.
    Includes SHA-256 hashing and optional VirusTotal lookup.
    This is the full Phase 1 + Phase 2 implementation.

    Returns same structure as analyze_attachments but with hash and VT data.
    """
    if not file_paths:
        return {"score": 0, "risky_attachments": []}

    risky = []

    for path in file_paths:
        if not os.path.exists(path):
            continue

        result = _check_real_file(path)

        # Phase 2: VirusTotal hash lookup
        if VIRUSTOTAL_API_KEY and result["hash"]:
            vt = _check_virustotal_hash(result["hash"])
            result["virustotal"] = vt
            print("[VIRUSTOTAL] verdict=" + str(vt))
	



            # If VT says malicious/suspicious, add to reasons
            if vt.get("checked") and vt.get("verdict") in ("Malicious", "Suspicious"):
                result["reasons"].append(
                    f"VirusTotal verdict: {vt['verdict']} "
                    f"({vt.get('malicious', 0)} engines flagged)"
                )
                result["is_dangerous"] = True

        if result["is_dangerous"]:
            entry = {
                "file": result["file"],
                "extension": result["extension"],
                "reasons": result["reasons"],
                "hash": result["hash"]
            }
            if "virustotal" in result:
                entry["virustotal"] = result["virustotal"]
            risky.append(entry)

    score = 50 if risky else 0

    return {
        "score": score,
        "risky_attachments": risky
    }


def generate_attachment_explanation(risky_attachments: list) -> list:
    """
    Converts attachment findings into human-readable explanation lines.
    Used by the explanation system (section 3.4 of the rapport).
    """
    lines = []
    for entry in risky_attachments:
        reason_str = "; ".join(entry["reasons"])
        lines.append(
            f"Attachment risk: {entry['file']} ({entry['extension']}) — {reason_str}"
        )
    return lines


# ─── Quick test ───────────────────────────────
if __name__ == "__main__":
    # Test by name (no real files needed)
    test_names = ["invoice.docm", "setup.exe", "photo.jpg", "script.vbs", "report.pdf"]
    result = analyze_attachments(test_names)

    print(f"Score : {result['score']}/50")
    print(f"Risky attachments: {len(result['risky_attachments'])}")
    for entry in result["risky_attachments"]:
        print(f"\n  File: {entry['file']}")
        for r in entry["reasons"]:
            print(f"    - {r}")

    print("\nExplanations:")
    for line in generate_attachment_explanation(result["risky_attachments"]):
        print(" -", line)
