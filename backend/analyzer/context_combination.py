import re

def analyze_context_combinations(email_text: str, urls: list) -> dict:
    """
    Scans the full email for keyword + URL (or keyword + credential) combinations
    before analyzing individual indicators.
    """
    text_lower = email_text.lower()
    has_url = len(urls) > 0
    score = 0
    found_combinations = []
    
    # 1. Bank / Finance
    bank_keywords = ["bank", "account", "verify", "transaction", "balance", "paypal", "credit card", "debit card", "iban", "payment", "funds", "wire transfer"]
    if has_url:
        found_bank_keywords = [kw for kw in bank_keywords if kw in text_lower]
        if found_bank_keywords:
            score += 40
            found_combinations.append({
                "combination": "bank_keyword + url",
                "keywords": found_bank_keywords,
                "urls": urls,
                "reason": "Legitimate banks never ask customers to click a link to verify their account. This combination is the most common phishing pattern.",
                "score_added": 40
            })

    # 2. Authority / Security
    auth_keywords = ["security team", "official", "administrator", "fraud department", "compliance", "support team", "helpdesk"]
    cred_keywords = ["password", "otp", "pin", "personal info"]
    found_auth = [kw for kw in auth_keywords if kw in text_lower]
    found_cred = [kw for kw in cred_keywords if kw in text_lower]
    if found_auth and found_cred:
        score += 35
        found_combinations.append({
            "combination": "authority + credential_request",
            "keywords": found_auth + found_cred,
            "urls": [],
            "reason": "An email claiming to be from an official team and asking for credentials is a strong phishing indicator.",
            "score_added": 35
        })

    # 3. Urgency
    urgency_keywords = ["urgent", "immediately", "24 hours", "48 hours", "expires", "act now", "last chance", "suspended", "locked", "terminated", "deadline"]
    if has_url:
        found_urgency = [kw for kw in urgency_keywords if kw in text_lower]
        if found_urgency:
            score += 25
            found_combinations.append({
                "combination": "urgency + url",
                "keywords": found_urgency,
                "urls": urls,
                "reason": "Creating time pressure to force the user to click without thinking is a classic phishing manipulation technique.",
                "score_added": 25
            })

    # 4. Prize / Reward
    reward_keywords = ["you won", "gift card", "prize", "selected", "congratulations", "reward", "free", "claim your", "you have been chosen"]
    if has_url:
        found_reward = [kw for kw in reward_keywords if kw in text_lower]
        if found_reward:
            score += 30
            found_combinations.append({
                "combination": "reward + url",
                "keywords": found_reward,
                "urls": urls,
                "reason": "Fake reward offers are used to lure users into clicking malicious links.",
                "score_added": 30
            })

    # 5. Delivery / Logistics
    delivery_keywords = ["dhl", "fedex", "ups", "package", "parcel", "shipment", "customs", "tracking", "delivery fee", "could not deliver"]
    if has_url:
        found_delivery = [kw for kw in delivery_keywords if kw in text_lower]
        if found_delivery:
            score += 20
            found_combinations.append({
                "combination": "delivery + url",
                "keywords": found_delivery,
                "urls": urls,
                "reason": "Fake delivery notifications trick users into paying fees or entering personal data on malicious sites.",
                "score_added": 20
            })

    # 6. IT / Account
    it_keywords = ["password expires", "microsoft", "office 365", "google account", "apple id", "account locked", "two-factor", "reset your password"]
    if has_url:
        found_it = [kw for kw in it_keywords if kw in text_lower]
        if found_it:
            score += 30
            found_combinations.append({
                "combination": "it_account + url",
                "keywords": found_it,
                "urls": urls,
                "reason": "Impersonating IT systems to steal credentials is one of the most common corporate phishing attacks.",
                "score_added": 30
            })

    return {
        "score": score,
        "combinations": found_combinations
    }

def generate_context_explanation(combinations: list) -> list:
    explanations = []
    for combo in combinations:
        urls_str = ", ".join(combo["urls"])
        keywords_str = ", ".join(combo["keywords"])
        
        parts = [
            f"[Context Detection] Triggered: {combo['combination']} (+{combo['score_added']} pts)"
        ]
        if urls_str:
            parts.append(f"  - Found URLs: {urls_str}")
        parts.append(f"  - Found keywords: {keywords_str}")
        parts.append(f"  - Reason: {combo['reason']}")
            
        explanations.extend(parts)
    return explanations
