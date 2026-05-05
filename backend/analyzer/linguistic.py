import re

# ─────────────────────────────────────────────
#  Linguistic Analysis Module
#  Based on section 2.2 of the rapport + expanded Deception & Manipulation Schemes
# ─────────────────────────────────────────────

PHISHING_KEYWORDS = {
    "urgency": [
        "urgent", "urgently", "immediately", "right now", "act now",
        "act immediately", "expires soon", "limited time", "last chance",
        "within 24 hours", "within 48 hours", "do not delay", "asap",
        "time sensitive", "respond now", "hurry", "deadline",
        "final warning", "failure to respond", "act fast",
    ],
    "fear": [
        "account suspended", "account has been suspended", "account blocked",
        "account has been locked", "unauthorized access", "security alert",
        "security breach", "your account will be closed",
        "your account will be terminated", "unusual activity detected",
        "suspicious activity detected", "verify your identity",
        "verify your account", "confirm your account",
        "failed login attempt", "unauthorized login attempt",
        "fraud detected", "access denied", "your account is at risk",
    ],
    "authority": [
        "administrator", "admin", "it department", "security team",
        "compliance team", "fraud department", "tax authority", "irs",
        "official notice", "department of", "ministry of",
        "support team", "help desk", "executive", "manager", "director",
        "ceo", "cto", "cfo", "hr department",
    ],
    "reward": [
        "you won", "you have won", "winner", "you are selected",
        "selected winner", "prize", "claim your reward", "claim now",
        "reward waiting", "lottery", "lucky winner", "gift card",
        "cash prize", "free iphone", "free money", "unclaimed prize",
    ],
    # ───── New Categories ───── #
  "impersonation": [
    "i am from it", "this is it support", "speaking on behalf of",
    "representing", "official representative", "your colleague",
    "hr team", "on behalf of the company",
    "this is your manager", "from the finance department",
    "corporate security team", "authorized personnel",
    "internal request", "company administrator",
    "it department here", "i'm calling from headquarters"
  ],
  "reciprocity": [
    "i helped you", "as a favor", "return the favor", "i shared with you",
    "thank you for your help earlier",
    "i already did this for you", "can you help me back",
    "i've taken care of it", "just need a small thing from you",
    "after what i did for you", "you owe me this"
  ],
  "liking": [
    "we have the same", "great to connect with someone who",
    "i really like your", "you seem like a great",
    "we share the same background", "nice profile",
    "i saw your work and loved it", "you seem very professional",
    "we're alike", "i feel we have a lot in common"
  ],
  "work_routine": [
    "as usual", "standard procedure", "routine request",
    "as part of our regular process", "following company policy",
    "submit your weekly", "update your information",
    "normal workflow", "daily task",
    "usual verification", "process this request",
    "as per routine check", "monthly update required"
  ],
  "sympathy": [
    "i really need your help", "i'm in trouble", "please help me",
    "i'm desperate", "this is urgent for me personally",
    "i'm stuck right now", "i can't access my account",
    "i'll be in serious trouble", "please understand my situation",
    "i really appreciate your support", "i'm counting on you"
  ],
  "praising": [
    "you're the best", "your expertise", "very talented",
    "excellent work", "one of our top", "highly skilled",
    "i admire how you", "you're doing a fantastic job",
    "you're very reliable", "you're the only one who can do this",
    "you always deliver great results", "impressive skills"
  ],
  "social_proof": [
    "everyone else has", "your colleagues have already",
    "many employees have", "other departments have",
    "most people in the company",
    "everyone in your team completed this",
    "others already approved it", "this is widely accepted",
    "everyone is doing it", "this is common practice"
  ],
  "misdirection": [
    "backup server", "data replication", "security update",
    "system maintenance", "routine verification",
    "configuration process", "network upgrade",
    "technical adjustment", "system migration",
    "server synchronization", "patch deployment",
    "infrastructure update"
  ],
  "insistency": [
    "as i mentioned before", "again", "once more", "i already asked",
    "please respond immediately", "this is a reminder",
    "following up", "waiting for your response",
    "urgent reminder", "kindly respond now",
    "still waiting", "final reminder"
  ],
  "greediness": [
    "exclusive offer", "special discount", "limited deal",
    "secret investment", "huge profit", "get rich",
    "guaranteed returns", "double your money",
    "earn easily", "free rewards",
    "claim your prize", "instant cash"
  ],
  "curiosity": [
    "you won't believe", "secret tool", "hidden feature",
    "confidential information", "click to see", "shocking news",
    "find out how", "discover the",
    "what happens next", "this will surprise you",
    "unbelievable results", "see for yourself",
    "revealed for the first time"
  ],
  "choice_manipulation": [
    "whenever you can", "at your convenience", "no pressure but",
    "just take a quick look", "only if you want",
    "feel free to", "you can decide",
    "optional step", "if you prefer",
    "take your time but", "it's up to you"
  ]
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

    raw_score = len(found) * 8          # lowered multiplier because we have more categories now
    score = min(raw_score, 50)          # increased max score

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
    # Test cases
    sample_safe = "Hi, you have a new assignment in Google Classroom. Click to view."
    r = analyze_text(sample_safe)
    print(f"Safe email — Score: {r['score']}, Found: {len(r['found'])}")

    sample_phish = """URGENT: Your account has been suspended! 
    This is the IT administrator. Please verify your credentials immediately 
    or your access will be terminated. I need your help right now."""
    r2 = analyze_text(sample_phish)
    print(f"Phish email — Score: {r2['score']}, Found: {[x['word'] for x in r2['found']]}")
