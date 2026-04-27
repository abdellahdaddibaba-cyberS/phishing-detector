import re

# ─────────────────────────────────────────────
#  Linguistic Analysis Module
#  Based on section 2.2 of the rapport:
#    Detects psychological manipulation patterns:
#      - Urgency   ("urgent", "immediately")
#      - Fear      ("account suspended")
#      - Authority ("bank", "administrator")
#      - Reward    ("you won")
#  Technique: Rule-based keyword detection (simple and efficient)
#  Max score contribution: +30 (see scoring table section 2.4)
# ─────────────────────────────────────────────

# Keyword dictionary — each category maps to a list of trigger phrases
# Directly taken from the rapport examples + extended for better coverage
PHISHING_KEYWORDS = {
    "urgency": [
        "urgent", "urgently", "immediately", "right now", "act now",
        "act immediately", "expires soon", "limited time", "last chance",
        "within 24 hours", "within 48 hours", "do not delay", "asap",
        "time sensitive", "respond now", "hurry", "deadline"
    ],
    "fear": [
        "account suspended", "account has been suspended", "account blocked",
        "suspended", "blocked", "unauthorized access", "security alert",
        "security breach", "your account will be", "will be closed",
        "will be terminated", "unusual activity", "suspicious activity",
        "verify your identity", "verify your account", "confirm your account",
        "login attempt", "failed login", "access denied", "fraud detected"
    ],
    "authority": [
        "bank", "administrator", "admin", "paypal", "apple", "microsoft",
        "amazon", "google", "facebook", "instagram", "government",
        "tax authority", "irs", "official notice", "department of",
        "ministry of", "your provider", "support team", "help desk",
        "it department", "security team", "compliance"
    ],
    "reward": [
        "you won", "you have won", "winner", "congratulations",
        "you are selected", "selected winner", "prize", "free gift",
        "claim your reward", "claim now", "reward waiting",
        "lottery", "lucky winner", "gift card", "cash prize",
        "free iphone", "free money", "$1000", "€1000"
    ]
}


def analyze_text(text: str) -> dict:
    """
    Scans the email text for phishing manipulation keywords.

    Returns:
      {
        "score": int,           # 0 to 30 (capped, as per rapport section 2.4)
        "found": [              # list of detected keyword matches
          {
            "word": str,        # the keyword that matched
            "category": str     # urgency / fear / authority / reward
          }
        ]
      }
    """

    if not text:
        return {"score": 0, "found": []}

    text_lower = text.lower()
    found = []
    seen = set()  # avoid counting the same keyword twice

    for category, keywords in PHISHING_KEYWORDS.items():
        for keyword in keywords:
            # Use word-boundary-aware search for single words,
            # plain 'in' for phrases (multi-word)
            keyword_lower = keyword.lower()
            if " " in keyword_lower:
                matched = keyword_lower in text_lower
            else:
                matched = bool(re.search(r'\b' + re.escape(keyword_lower) + r'\b', text_lower))

            if matched and keyword_lower not in seen:
                seen.add(keyword_lower)
                found.append({
                    "word": keyword,
                    "category": category
                })

    # Score: +10 per unique keyword found, capped at 30
    # (Suspicious keywords = +30 max, per scoring table in rapport section 2.4)
    raw_score = len(found) * 10
    score = min(raw_score, 30)

    return {
        "score": score,
        "found": found
    }


def generate_linguistic_explanation(found: list) -> list:
    """
    Converts the found keywords into human-readable explanation lines.
    Used by the explanation system (section 3.4 of the rapport).
    """
    if not found:
        return []

    lines = []
    # Group by category for cleaner output
    categories = {}
    for item in found:
        cat = item["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(item["word"])

    for cat, words in categories.items():
        word_list = ", ".join(f'"{w}"' for w in words)
        lines.append(
            f"Linguistic indicator ({cat}): {word_list} detected in message"
        )

    return lines


# ─── Quick test ───────────────────────────────
if __name__ == "__main__":
    sample = (
        "URGENT: Your bank account has been suspended! "
        "Verify your account immediately or it will be closed. "
        "You have won a free gift — claim your reward now!"
    )
    result = analyze_text(sample)
    print(f"Score : {result['score']}/30")
    print(f"Found : {len(result['found'])} keyword(s)")
    for item in result["found"]:
        print(f"  [{item['category']}] → \"{item['word']}\"")

    print("\nExplanations:")
    for line in generate_linguistic_explanation(result["found"]):
        print(" -", line)
