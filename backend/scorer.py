import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from preprocessor import preprocess
from analyzer.linguistic          import analyze_text, generate_linguistic_explanation
from analyzer.url_check           import analyze_urls,  generate_url_explanation
from analyzer.context_combination import analyze_context_combinations, generate_context_explanation

# ─────────────────────────────────────────────
#  Scoring Engine + Decision Engine
#
#  Scoring table:
#    Suspicious keywords  → +30
#    Malicious URL        → +40
#
#  Risk levels (default thresholds — overridable from frontend settings):
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


def generate_explanation(linguistic: dict, urls: dict, context_combos: dict = None) -> list:
    """
    Generates human-readable explanation lines.
    """
    lines = []

    if context_combos and context_combos.get("combinations"):
        lines.extend(generate_context_explanation(context_combos.get("combinations", [])))

    lines.extend(generate_linguistic_explanation(linguistic.get("found", [])))
    lines.extend(generate_url_explanation(urls.get("suspicious_urls", [])))

    # Reputation-based signals (VirusTotal)
    for entry in urls.get("suspicious_urls", []):
        vt = entry.get("virustotal", {})
        if vt.get("checked") and vt.get("malicious", 0) > 0:
            lines.append(
                f"Domain flagged as malicious by VirusTotal "
                f"({vt['malicious']} engines): {entry['url']}"
            )

    if not lines:
        lines.append("No phishing indicators found. Email appears safe.")

    return lines


def analyze_email(email_text: str) -> dict:
    """
    Runs the full phishing detection pipeline.

    Parameters:
      email_text : raw email body text
    """

    # Step 1: Preprocessing — extract text and URLs
    parsed = preprocess(email_text)

    # Step 1.5: Context Combination Detection
    context_result = analyze_context_combinations(email_text, parsed["urls"])

    # Step 2: Linguistic analysis
    linguistic_result = analyze_text(parsed["text"])

    # Step 3: URL analysis (VirusTotal only)
    url_result = analyze_urls(parsed["urls"])

    # Step 4: Scoring engine
    raw_score   = context_result["score"] + linguistic_result["score"] + url_result["score"]
    final_score = min(raw_score, 100)

    # Step 5: Risk level
    risk_level = get_risk_level(final_score)

    # Step 6: Explanation system
    explanation = generate_explanation(linguistic_result, url_result, context_result)

    return {
        "score":      final_score,
        "risk_level": risk_level,
        "explanation": explanation,
        "details": {
            "context_combinations": context_result,
            "linguistic":  linguistic_result,
            "urls":        url_result,
        },
        "parsed": {
            "urls_found": parsed["urls"],
        },
    }


# ─── Quick test ───────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("TEST 1 — Phishing email")
    print("=" * 60)
    result = analyze_email(
        "URGENT: Your bank account has been suspended! "
        "Verify at http://192.168.1.1/login now."
    )
    print(f"Score      : {result['score']}/100")
    print(f"Risk Level : {result['risk_level']}")
    for line in result["explanation"]:
        print(f"  - {line}")

    print()
    print("=" * 60)
    print("TEST 2 — Safe email")
    print("=" * 60)
    result2 = analyze_email(
        "Hi Ahmed, please find the meeting notes attached. Regards, Sara."
    )
    print(f"Score      : {result2['score']}/100")
    print(f"Risk Level : {result2['risk_level']}")
    for line in result2["explanation"]:
        print(f"  - {line}")
