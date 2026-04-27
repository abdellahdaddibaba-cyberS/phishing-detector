import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from preprocessor import preprocess
from analyzer.linguistic   import analyze_text, generate_linguistic_explanation
from analyzer.url_check    import analyze_urls,  generate_url_explanation
from analyzer.attachment   import analyze_attachments, generate_attachment_explanation

# ─────────────────────────────────────────────
#  Scoring Engine + Decision Engine
#  Section 2.4 and 3.3 of the rapport:
#
#  Scoring table:
#    Suspicious keywords  → +30
#    Malicious URL        → +40
#    Dangerous attachment → +50
#
#  Risk levels:
#    0  – 30  → Safe
#    31 – 70  → Suspicious
#    71 – 100 → Phishing
# ─────────────────────────────────────────────


def get_risk_level(score: int) -> str:
    if score <= 30:
        return "Safe"
    elif score <= 70:
        return "Suspicious"
    else:
        return "Phishing"


def generate_explanation(linguistic: dict, urls: dict, attachments: dict) -> list:
    """
    Generates human-readable explanation lines.
    Implements section 3.4 of the rapport — the Explanation System.
    """
    lines = []

    lines.extend(generate_linguistic_explanation(linguistic.get("found", [])))
    lines.extend(generate_url_explanation(urls.get("suspicious_urls", [])))
    lines.extend(generate_attachment_explanation(attachments.get("risky_attachments", [])))

    # Reputation-based signals (VirusTotal)
    for entry in urls.get("suspicious_urls", []):
        vt = entry.get("virustotal", {})
        if vt.get("checked") and vt.get("malicious", 0) > 0:
            lines.append(
                f"Domain flagged as malicious by VirusTotal "
                f"({vt['malicious']} engines): {entry['url']}"
            )

    for entry in attachments.get("risky_attachments", []):
        vt = entry.get("virustotal", {})
        if vt.get("checked") and vt.get("verdict") in ("Malicious", "Suspicious"):
            lines.append(
                f"File flagged by VirusTotal ({vt.get('verdict')}): {entry['file']}"
            )

    if not lines:
        lines.append("No phishing indicators found. Email appears safe.")

    return lines


def analyze_email(email_text: str, uploaded_filename: str = None) -> dict:
    """
    Runs the full phishing detection pipeline.

    Parameters:
      email_text        : raw email body text
      uploaded_filename : name of the uploaded attachment file (optional)
                          passed down to preprocessor to skip regex guessing
    """

    # Step 1: Preprocessing — pass uploaded_filename so it skips regex if provided
    parsed = preprocess(email_text, uploaded_filename=uploaded_filename)

    # Step 2: Linguistic analysis
    linguistic_result = analyze_text(parsed["text"])

    # Step 3: URL analysis
    url_result = analyze_urls(parsed["urls"])

    # Step 4: Attachment analysis (by name only — real file check is in app.py)
    attachment_result = analyze_attachments(parsed["attachments"])

    # Step 5: Scoring engine (section 2.4 + 3.3)
    raw_score   = linguistic_result["score"] + url_result["score"] + attachment_result["score"]
    final_score = min(raw_score, 100)

    # Step 6: Risk level
    risk_level = get_risk_level(final_score)

    # Step 7: Explanation system (section 3.4)
    explanation = generate_explanation(linguistic_result, url_result, attachment_result)

    return {
        "score":       final_score,
        "risk_level":  risk_level,
        "explanation": explanation,
        "details": {
            "linguistic":  linguistic_result,
            "urls":        url_result,
            "attachments": attachment_result,
        },
        "parsed": {
            "urls_found":        parsed["urls"],
            "attachments_found": parsed["attachments"],
        }
    }


# ─── Quick test ───────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("TEST 1 — Phishing email (text only, regex attachment)")
    print("=" * 60)
    result = analyze_email(
        "URGENT: Your bank account has been suspended! "
        "Verify at http://192.168.1.1/login now. Download: fix.exe"
    )
    print(f"Score      : {result['score']}/100")
    print(f"Risk Level : {result['risk_level']}")
    for line in result["explanation"]:
        print(f"  - {line}")

    print()
    print("=" * 60)
    print("TEST 2 — Phishing email with real uploaded file")
    print("=" * 60)
    result2 = analyze_email(
        "Please review the attached document.",
        uploaded_filename="invoice.docm"
    )
    print(f"Score      : {result2['score']}/100")
    print(f"Risk Level : {result2['risk_level']}")
    for line in result2["explanation"]:
        print(f"  - {line}")

    print()
    print("=" * 60)
    print("TEST 3 — Safe email")
    print("=" * 60)
    result3 = analyze_email(
        "Hi Ahmed, please find the meeting notes attached. Regards, Sara."
    )
    print(f"Score      : {result3['score']}/100")
    print(f"Risk Level : {result3['risk_level']}")
    for line in result3["explanation"]:
        print(f"  - {line}")
