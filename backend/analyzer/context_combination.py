import re

# ─────────────────────────────────────────────
#  Context Combination Detection
#  Detects dangerous keyword+URL combinations.
#
#  FIX vs original:
#   - "bank" or "account" alone with ANY url no longer fires +40.
#     A normal receipt/statement email mentions "account" + has a
#     link (unsubscribe, footer) and should NOT be penalised.
#   - Combinations now require MULTIPLE strong signals to fire.
#   - Scores are proportional, not flat max values.
# ─────────────────────────────────────────────

# ── Phrase sets ───────────────────────────────

# True phishing action phrases — require immediate user action on their account
PHISHING_ACTION_PHRASES = [
    "verify your account", "verify your identity", "confirm your account",
    "update your payment", "your account will be suspended",
    "your account has been suspended", "your account has been locked",
    "click here to verify", "click the link below", "login to confirm",
    "confirm your details", "validate your account", "re-enter your details",
    "your password has expired", "reset your password now",
    "unusual activity detected", "unauthorized login attempt",
    "your account will be closed", "your account will be terminated",
    # Extended threat/suspension phrases (batch 1)
    "your account will be blocked", "your banking access will be disabled",
    "avoid permanent closure", "your account will be deleted",
    "imminent suspension", "urgent verification required",
    "your account will be closed for suspicious activity",
    "we will close your account", "confirm your data to avoid blocking",
    "your account will be restricted", "access denied without validation",
    "your account will be frozen", "last chance to keep your account active",
    "we will suspend your banking services", "your account is being deactivated",
    "risk of immediate closure", "your account will be permanently locked",
    "automatic closure of the account", "your account will be deactivated",
    "suspension planned following a security alert",
    "mandatory action to avoid loss of access",
    "your account will be deleted today",
    "we have initiated the closure of your account",
    "your account will be blocked without prompt confirmation",
    "verify your identity to avoid suspension",
    "your account will be closed for non-compliance",
    "access suspended until complete verification",
    "your account will be closed shortly",
]

# Finance keywords — only suspicious combined with action phrases
FINANCE_KEYWORDS = [
    "bank", "paypal", "credit card", "debit card", "iban",
    "wire transfer", "your account", "funds", "payment details",
]

# Authority impersonation phrases
AUTHORITY_PHRASES = [
    "security team", "fraud department", "it department",
    "help desk", "official notice", "compliance team",
    "administrator", "system administrator",
]

# Credential harvesting keywords
CREDENTIAL_KEYWORDS = [
    "enter your password", "enter your pin", "enter your otp",
    "provide your password", "submit your credentials",
    "type your password", "input your pin",
]

# Urgency + fear combo phrases (must be specific, not single word)
URGENCY_FEAR_PHRASES = [
    "act immediately", "act now or", "within 24 hours", "within 48 hours",
    "your account will be", "immediately or your", "failure to respond",
    "do not ignore this", "last chance to", "final warning",
    # Extended urgency/threat triggers
    "within the next few hours", "if no action is taken",
    "if you do not confirm", "action required", "anomaly detected",
    "for non-compliance", "without prompt confirmation",
    "without validation of your identity", "for suspicious activity",
    "for lack of response", "for suspicious inactivity",
    "following a security alert", "avoid loss of access",
    "deleted today", "initiated the closure", "closed shortly",
    "non-validation =", "imminent access denied",
    # Generic urgency shared across all 12 domains
    "account closure pending", "closure pending", "suspension pending",
    "deactivation pending", "deactivation imminent", "termination pending",
    "closure initiated", "shutdown pending", "shutdown imminent",
    "lock imminent", "lock scheduled", "lock pending",
    "access will be revoked", "access will be removed", "access will be cut off",
    "access blocked soon", "access loss imminent", "access loss risk",
    "access termination", "access termination imminent", "access termination scheduled",
    "no response =", "no action =", "non-action =",
    "permanent suspension", "permanent closure", "permanent lock",
    "permanent deletion", "permanent ban", "risk of permanent",
    "account flagged", "account flagged for", "account under review",
    "account under threat", "account compromised", "account compromised alert",
    "account compromised warning", "security alert detected", "security alert triggered",
    "security alert issued", "security issue detected", "security issue found",
    "security check required", "security update required", "urgent security notice",
    "urgent security update", "urgent it notice", "urgent notice",
    "verify now or", "verify or lose", "confirm now to",
    "immediate confirmation needed", "immediate verification needed",
    "immediate verification required", "immediate action required",
    "immediate response required", "immediate confirmation required",
    "urgent response needed", "urgent response required",
    "urgent confirmation required", "urgent verification required",
    "urgent action needed", "failure to respond will",
    "non-compliance will", "policy violation",
    "violation detected", "suspicious activity detected",
    "suspicious purchase detected", "suspicious order",
    "payment issue detected", "payment failure",
    "storage exceeded", "delivery failure",
]

# Reward / lottery phrases
REWARD_PHRASES = [
    "you have won", "you won a", "you are a winner", "selected winner",
    "claim your prize", "claim your reward", "claim your gift card",
    "free iphone", "lottery winner", "lucky winner",
    "gift card reward", "cash prize", "you have been selected",
]

# Delivery scam phrases
DELIVERY_PHRASES = [
    "could not deliver your package", "delivery fee required",
    "customs fee", "reschedule your delivery", "your parcel is on hold",
    "package is waiting", "missed delivery",
    # Extended delivery/e-commerce scam phrases
    "delivery issue", "delivery failure", "failed delivery",
    "account locked until verification", "confirm details or lose",
    "account locked due to suspicious order", "verify billing info now",
    "account closure due to failed delivery",
]

# IT / account impersonation
IT_PHRASES = [
    "your password expires", "office 365 account", "microsoft account suspended",
    "google account suspended", "apple id locked", "icloud account locked",
    "two-factor authentication required", "verify your microsoft", "verify your google",
    # Extended IT/workplace impersonation phrases
    "your work account will be disabled", "password reset required immediately",
    "verify credentials now", "urgent it notice", "security issue found",
    "account shutdown scheduled", "access denied soon",
    "your mailbox will be disabled", "your email will be deactivated",
    "inbox access will be blocked", "verify now or lose data",
    "loss of access imminent",
]

# ── Domain-specific phrase sets (12 phishing contexts) ───────────────────────

# 1) Banking — account suspension / closure threats
BANKING_PHRASES = [
    "account will be suspended within 24 hours", "final notice: account closure pending",
    "suspicious activity detected—account will be locked", "verify now or lose access",
    "immediate action required to avoid closure", "your banking access will be disabled",
    "account flagged—closure initiated", "failure to respond will result in termination",
    "your account is at risk of permanent lock", "confirm identity to prevent shutdown",
    "access will be revoked today", "account freeze scheduled",
    "non-compliance will close your account", "security issue—account will be restricted",
    "your account is under review for closure", "account will be disabled due to inactivity",
    "risk of permanent suspension", "access blocked unless action is taken",
    "your account will be terminated shortly", "your account is compromised—lock pending",
    "validate details to avoid suspension", "account deactivation in progress",
    "urgent security update required", "account will be restricted today",
    "closure due to policy violation", "access termination scheduled",
    "your account will be permanently closed",
]

# 2) E-commerce / Delivery — account suspension threats
ECOMMERCE_PHRASES = [
    "your order account will be suspended", "delivery issue—account locked",
    "confirm details or lose account access", "account closure due to failed delivery",
    "your shopping account will be disabled", "payment issue—account restriction pending",
    "account flagged for closure", "no response = account termination",
    "access will be removed today", "account blocked due to suspicious order",
    "account at risk of deletion", "delivery failure—account suspended",
    "account locked until verification", "risk of permanent shutdown",
    "confirm now to keep access", "account under review for closure",
    "your account will expire", "account deactivation pending",
    "suspicious purchase detected", "verify billing info now",
    "account access denied soon", "risk of account removal",
    "account will be terminated shortly",
]

# 3) Email / Cloud — account suspension threats
EMAIL_CLOUD_PHRASES = [
    "your mailbox will be disabled", "account suspension in 24h",
    "storage exceeded—account closure pending", "verify to keep access",
    "your email will be deactivated", "security alert—account lock imminent",
    "final notice before deletion", "access will be removed",
    "account compromised—shutdown pending", "account at risk of closure",
    "inbox access will be blocked", "non-action will terminate account",
    "account suspension scheduled", "urgent login confirmation needed",
    "account flagged for removal", "loss of access imminent",
    "verify now or lose data", "account under threat",
    "account will be closed", "access termination imminent",
]

# 4) Social Media — account suspension threats
SOCIAL_MEDIA_PHRASES = [
    "your account will be disabled", "policy violation—closure pending",
    "verify identity or lose access", "account suspension imminent",
    "final warning before ban", "access will be revoked",
    "account flagged for removal", "account locked due to violation",
    "risk of permanent ban", "account will be terminated",
    "security alert issued", "account under review",
    "no response = deletion", "account compromised warning",
    "suspension scheduled", "account restriction pending",
    "account access denied soon", "violation detected",
    "account removal imminent", "account shutdown in progress",
    "access termination scheduled", "permanent deletion risk",
]

# 5) Payment Services — account suspension threats
PAYMENT_PHRASES = [
    "your wallet will be suspended", "unauthorized activity—account locked",
    "verify now or lose funds access", "account closure pending",
    "your payment account will be disabled", "risk of permanent suspension",
    "final notice before lock", "access termination imminent",
    "account compromised", "account under review",
    "security alert triggered", "account will be restricted",
    "closure due to policy breach", "confirm details immediately",
    "account shutdown scheduled", "account deactivation pending",
    "no action = closure", "risk of account loss",
    "access will be removed", "account freeze imminent",
    "account will be closed", "security check required",
    "account termination pending",
]

# 6) Government / Tax — account suspension threats
GOVERNMENT_PHRASES = [
    "tax account closure pending", "verify identity immediately",
    "access will be revoked", "account locked due to issue",
    "non-response = closure", "access termination imminent",
    "account under review", "risk of permanent closure",
    "immediate confirmation needed", "account restricted",
    "access blocked soon", "account suspension scheduled",
    "account will be disabled", "account deactivation pending",
    "no action = termination", "account lock imminent",
    "access loss risk", "account shutdown pending",
    "immediate response required", "account will be closed",
]

# 7) Telecom / ISP — account suspension threats
TELECOM_PHRASES = [
    "your service account will be suspended", "sim will be deactivated",
    "verify now to keep service", "access will be cut off",
    "service interruption imminent", "account locked",
    "risk of permanent shutdown", "no response = termination",
    "account deactivation pending", "verify details now",
    "service access will end", "account restricted",
    "urgent verification required", "account will be disabled",
    "account compromised alert", "service suspension scheduled",
    "account shutdown pending", "access termination imminent",
    "account lock scheduled", "verify or lose service",
    "account will be terminated",
]

# 8) Workplace / IT — account suspension threats
WORKPLACE_PHRASES = [
    "your work account will be disabled", "password reset required immediately",
    "account suspension pending", "verify credentials now",
    "access will be revoked", "security alert detected",
    "account lock imminent", "no response = termination",
    "account compromised", "access blocked soon",
    "deactivation scheduled", "urgent it notice",
    "account restricted", "closure initiated",
    "account will be disabled", "access loss imminent",
    "account termination pending", "security issue found",
    "immediate verification needed", "account shutdown scheduled",
    "access denied soon", "account lock scheduled",
    "account will be closed",
]

# 9) Streaming — account suspension threats
STREAMING_PHRASES = [
    "payment failure—account closure pending", "verify now to keep access",
    "account deactivation imminent", "access will be removed",
    "subscription will be terminated", "no response = closure",
    "account under review", "risk of permanent loss",
    "verify billing info now", "account restricted",
    "closure initiated", "access blocked soon",
    "account compromised alert", "urgent confirmation required",
    "account shutdown pending", "access termination imminent",
    "account lock scheduled", "payment issue detected",
    "account will be disabled", "account suspension scheduled",
    "access loss risk", "account termination pending",
    "account will be closed",
]

# 10) Security Alerts — account suspension threats
SECURITY_ALERT_PHRASES = [
    "suspicious activity detected", "verify now or lose access",
    "account closure pending", "account flagged",
    "access will be revoked", "account compromised",
    "lock scheduled", "account under threat",
    "access blocked soon", "account deactivation pending",
    "no action = closure", "account restricted",
    "closure initiated", "urgent security notice",
    "account shutdown imminent", "access termination pending",
    "account lock imminent", "immediate confirmation needed",
    "security issue detected", "account will be disabled",
    "risk of permanent lock", "account suspension scheduled",
    "access loss imminent", "account will be terminated",
]

# 11) Job / Recruitment — account suspension threats
RECRUITMENT_PHRASES = [
    "your applicant account will be deleted", "verify now to continue process",
    "account suspension pending", "access will be revoked",
    "no response = closure", "account under review",
    "risk of losing opportunity", "access blocked soon",
    "account deactivation pending", "account restricted",
    "closure initiated", "account shutdown imminent",
    "access termination pending", "account lock scheduled",
    "immediate verification needed", "application access denied soon",
    "account will be disabled", "urgent confirmation required",
    "account suspension scheduled", "access loss risk",
    "account termination pending", "account compromised alert",
    "account will be closed",
]

# 12) Crypto / Investment — account suspension threats
CRYPTO_PHRASES = [
    "your wallet will be suspended", "account closure pending",
    "verify now to keep funds access", "access will be revoked",
    "account locked", "risk of permanent loss",
    "account compromised alert", "access blocked soon",
    "account deactivation pending", "no action = closure",
    "account restricted", "closure initiated",
    "account shutdown imminent", "access termination pending",
    "account lock scheduled", "immediate verification needed",
    "account will be disabled", "security issue detected",
    "risk of account loss", "urgent confirmation required",
    "account suspension scheduled", "access loss imminent",
    "account termination pending", "account will be closed",
]

# Master list aggregating all domain-specific phrase sets for unified rule matching
ALL_DOMAIN_SUSPENSION_PHRASES = (
    BANKING_PHRASES + ECOMMERCE_PHRASES + EMAIL_CLOUD_PHRASES +
    SOCIAL_MEDIA_PHRASES + PAYMENT_PHRASES + GOVERNMENT_PHRASES +
    TELECOM_PHRASES + WORKPLACE_PHRASES + STREAMING_PHRASES +
    SECURITY_ALERT_PHRASES + RECRUITMENT_PHRASES + CRYPTO_PHRASES
)


def _has_any(text_lower: str, phrases: list) -> list:
    """Returns list of matched phrases."""
    return [p for p in phrases if p in text_lower]


def analyze_context_combinations(email_text: str, urls: list) -> dict:
    text_lower = email_text.lower()
    has_url    = len(urls) > 0
    score      = 0
    combinations = []

    # ── Rule 1: Finance keyword + phishing action phrase + URL ──────────────
    # Requires BOTH a finance keyword AND a specific action phrase, plus a URL.
    # This prevents "account" + unsubscribe link triggering a false positive.
    if has_url:
        found_finance = _has_any(text_lower, FINANCE_KEYWORDS)
        found_action  = _has_any(text_lower, PHISHING_ACTION_PHRASES)
        if found_finance and found_action:
            score += 40
            combinations.append({
                "combination": "finance_keyword + action_phrase + url",
                "keywords": found_finance + found_action,
                "urls": urls,
                "reason": "Legitimate banks never ask customers to click a link to verify their account. This combination is the most common phishing pattern.",
                "score_added": 40,
            })

    # ── Rule 2: Authority phrase + credential keyword ────────────────────────
    found_auth = _has_any(text_lower, AUTHORITY_PHRASES)
    found_cred = _has_any(text_lower, CREDENTIAL_KEYWORDS)
    if found_auth and found_cred:
        score += 35
        combinations.append({
            "combination": "authority + credential_request",
            "keywords": found_auth + found_cred,
            "urls": [],
            "reason": "An email claiming to be from an official team and asking for credentials is a strong phishing indicator.",
            "score_added": 35,
        })

    # ── Rule 3: Urgency/fear phrase + URL ────────────────────────────────────
    if has_url:
        found_urgency = _has_any(text_lower, URGENCY_FEAR_PHRASES)
        if found_urgency:
            score += 25
            combinations.append({
                "combination": "urgency + url",
                "keywords": found_urgency,
                "urls": urls,
                "reason": "Creating time pressure to force the user to click without thinking is a classic phishing manipulation technique.",
                "score_added": 25,
            })

    # ── Rule 4: Reward / prize phrase + URL ──────────────────────────────────
    if has_url:
        found_reward = _has_any(text_lower, REWARD_PHRASES)
        if found_reward:
            score += 30
            combinations.append({
                "combination": "reward + url",
                "keywords": found_reward,
                "urls": urls,
                "reason": "Fake reward offers are used to lure users into clicking malicious links.",
                "score_added": 30,
            })

    # ── Rule 5: Delivery scam phrase + URL ───────────────────────────────────
    if has_url:
        found_delivery = _has_any(text_lower, DELIVERY_PHRASES)
        if found_delivery:
            score += 20
            combinations.append({
                "combination": "delivery_scam + url",
                "keywords": found_delivery,
                "urls": urls,
                "reason": "Fake delivery notifications trick users into paying fees or entering personal data on malicious sites.",
                "score_added": 20,
            })

    # ── Rule 6: IT / account impersonation + URL ─────────────────────────────
    if has_url:
        found_it = _has_any(text_lower, IT_PHRASES)
        if found_it:
            score += 30
            combinations.append({
                "combination": "it_account + url",
                "keywords": found_it,
                "urls": urls,
                "reason": "Impersonating IT systems to steal credentials is one of the most common corporate phishing attacks.",
                "score_added": 30,
            })

    # ── Rule 7: Domain-specific suspension/threat phrase + URL ───────────────
    # Covers 12 phishing contexts: banking, e-commerce, email/cloud, social
    # media, payment, government, telecom, workplace, streaming, security
    # alerts, recruitment, and crypto/investment.
    if has_url:
        found_domain = _has_any(text_lower, ALL_DOMAIN_SUSPENSION_PHRASES)
        if found_domain:
            score += 30
            combinations.append({
                "combination": "domain_suspension_threat + url",
                "keywords": found_domain,
                "urls": urls,
                "reason": (
                    "Threatening account suspension, closure, or access loss across "
                    "12 known phishing domains (banking, e-commerce, email, social media, "
                    "payment, government, telecom, workplace, streaming, security alerts, "
                    "recruitment, crypto) is a hallmark pattern of phishing attacks."
                ),
                "score_added": 30,
            })

    return {
        "score": score,
        "combinations": combinations,
    }


def generate_context_explanation(combinations: list) -> list:
    explanations = []
    for combo in combinations:
        urls_str     = ", ".join(combo["urls"])
        keywords_str = ", ".join(combo["keywords"])
        parts = [
            f"[Context Detection] Triggered: {combo['combination']} (+{combo['score_added']} pts)",
        ]
        if urls_str:
            parts.append(f"  - Found URLs: {urls_str}")
        parts.append(f"  - Found keywords: {keywords_str}")
        parts.append(f"  - Reason: {combo['reason']}")
        explanations.extend(parts)
    return explanations
