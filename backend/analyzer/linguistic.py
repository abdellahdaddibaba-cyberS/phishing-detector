import re

# ─────────────────────────────────────────────
#  Linguistic Analysis Module
#  Based on section 2.2 of the rapport
#
#  KEY CHANGE vs original:
#  "authority" keywords like "google", "amazon", "facebook" have been
#  REMOVED from the keyword list.  Receiving a notification email FROM
#  Google/Amazon/etc. is completely normal — the sender name appearing
#  in the body is not a phishing signal by itself.
#  Only kept genuinely suspicious impersonation phrases that would not
#  appear in a legitimate transactional email.
# ─────────────────────────────────────────────

PHISHING_KEYWORDS = {
    "urgency": [
        "urgent", "urgently", "immediately", "right now", "act now",
        "act immediately", "expires soon", "limited time", "last chance",
        "within 24 hours", "within 48 hours", "do not delay", "asap",
        "time sensitive", "respond now", "hurry", "deadline",
        "final warning", "failure to respond",
    ],
    "fear": [
        "account suspended", "account has been suspended", "account blocked",
        "account has been locked", "unauthorized access", "security alert",
        "security breach", "your account will be closed",
        "your account will be terminated", "unusual activity detected",
        "suspicious activity detected",
        "verify your identity", "verify your account", "confirm your account",
        "failed login attempt", "unauthorized login attempt",
        "fraud detected", "access denied",
    ],
    "authority": [
        # Kept: generic impersonation phrases that don't belong in normal email
        "administrator", "admin",
        "tax authority", "irs", "official notice",
        "department of", "ministry of",
        "support team", "help desk",
        "it department", "security team", "compliance team",
        "fraud department",
        # Removed: "google", "amazon", "facebook", "instagram", "microsoft",
        #          "apple", "paypal" — these appear legitimately in emails
        #          from those services and cause false positives.
    ],
    "reward": [
        "you won", "you have won", "winner",
        "you are selected", "selected winner", "prize",
        "claim your reward", "claim now", "reward waiting",
        "lottery", "lucky winner", "gift card", "cash prize",
        "free iphone", "free money",
    ],
}


def analyze_text(text: str) -> dict:
    if not text:
        return {"score": 0, "found": []}

    text_lower = text.lower()
    found = []
    seen = set()

    for category, keywords in PHISHING_KEYWORDS.items():
        for keyword in keywords:
            keyword_lower = keyword.lower()
            if " " in keyword_lower:
                matched = keyword_lower in text_lower
            else:
                matched = bool(re.search(r'\b' + re.escape(keyword_lower) + r'\b', text_lower))

            if matched and keyword_lower not in seen:
                seen.add(keyword_lower)
                found.append({"word": keyword, "category": category})

    raw_score = len(found) * 10
    score = min(raw_score, 30)

    return {"score": score, "found": found}


def generate_linguistic_explanation(found: list) -> list:
    if not found:
        return []
    lines = []
    categories = {}
    for item in found:
        cat = item["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(item["word"])
    for cat, words in categories.items():
        word_list = ", ".join(f'"{w}"' for w in words)
        lines.append(f"Linguistic indicator ({cat}): {word_list} detected in message")
    return lines


if __name__ == "__main__":
    # Should be CLEAN — normal Google Classroom notification
    sample_safe = "Hi, you have a new assignment in Google Classroom. Click to view."
    r = analyze_text(sample_safe)
    print(f"Safe email — Score: {r['score']}, Found: {r['found']}")

    # Should be flagged
    sample_phish = "URGENT: Your account has been suspended! Verify your account immediately or it will be closed."
    r2 = analyze_text(sample_phish)
    print(f"Phish email — Score: {r2['score']}, Found: {[x['word'] for x in r2['found']]}")
