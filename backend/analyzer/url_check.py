import re
import os
import urllib.parse
import urllib.request
import json
from dotenv import load_dotenv
load_dotenv()
# ─────────────────────────────────────────────
#  URL Analysis Module
#  Based on section 2.3 of the rapport:
#    Evaluates links inside the message:
#      - Suspicious domain names
#      - Use of IP addresses instead of domains
#      - URL shortening services (e.g., bit.ly)
#      - Absence of HTTPS
#  Technique: Domain reputation APIs (VirusTotal, Google Safe Browsing)
#  Max score contribution: +40 (see scoring table section 2.4)
# ─────────────────────────────────────────────

# ── Known URL shortener domains ──────────────
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "short.link", "tiny.cc",
    "cutt.ly", "rebrand.ly", "shorturl.at", "bl.ink"
]

# ── Regex: detect raw IP address in URL ──────
IP_URL_PATTERN = re.compile(
    r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
)

# ── Suspicious TLDs often used in phishing ───
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq",  # free domain TLDs
    ".xyz", ".top", ".club", ".work", ".click", ".link"
]

# ── VirusTotal API key (optional — Phase 2) ──
# Set this in your environment: export VIRUSTOTAL_API_KEY=your_key_here
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

print(VIRUSTOTAL_API_KEY)
# ─────────────────────────────────────────────
#  PHASE 1: Local rule-based checks
# ─────────────────────────────────────────────

def _check_single_url(url: str) -> dict:
    """
    Runs all local rule-based checks on a single URL.
    Returns a dict with the URL and a list of reasons it is suspicious.
    """
    reasons = []

    # Check 1: IP address used instead of a real domain name
    if IP_URL_PATTERN.match(url):
        reasons.append("IP address used instead of a domain name")

    # Check 2: URL shortening service
    try:
        domain = urllib.parse.urlparse(url).netloc.lower()
        # Remove www. prefix for comparison
        domain_clean = domain.replace("www.", "")
        if any(shortener in domain_clean for shortener in URL_SHORTENERS):
            reasons.append("URL shortening service detected (hides real destination)")
    except Exception:
        pass

    # Check 3: Absence of HTTPS (unencrypted connection)
    if url.startswith("http://"):
        reasons.append("No HTTPS — connection is not secure")

    # Check 4: Abnormally long URL (often used to hide the real domain)
    if len(url) > 100:
        reasons.append(f"Abnormally long URL ({len(url)} characters)")

    # Check 5: Suspicious TLD
    try:
        parsed_domain = urllib.parse.urlparse(url).netloc.lower()
        for tld in SUSPICIOUS_TLDS:
            if parsed_domain.endswith(tld):
                reasons.append(f"Suspicious top-level domain: {tld}")
                break
    except Exception:
        pass

    # Check 6: Contains login/verify/update keywords in URL path (common phishing paths)
    suspicious_paths = ["login", "verify", "update", "account", "secure", "confirm", "password"]
    try:
        path = urllib.parse.urlparse(url).path.lower()
        for word in suspicious_paths:
            if word in path:
                reasons.append(f"Suspicious path keyword in URL: '{word}'")
                break
    except Exception:
        pass

    return {
        "url": url,
        "reasons": reasons,
        "is_suspicious": len(reasons) > 0
    }


# ─────────────────────────────────────────────
#  PHASE 2: VirusTotal API check (optional)
#  As described in sections 3.2 and 2.3 of the rapport
# ─────────────────────────────────────────────

def _check_virustotal(url: str) -> dict:
    """
    Sends the URL to VirusTotal API and gets a malice verdict.
    Only called if VIRUSTOTAL_API_KEY is set in the environment.

    Returns dict with:
      - malicious (bool)
      - positives (int): number of engines that flagged it
      - total (int): total engines checked
    """
    if not VIRUSTOTAL_API_KEY:
        return {"checked": False}

    try:
        # Encode URL for VirusTotal v3 API
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        req = urllib.request.Request(api_url)
        req.add_header("x-apikey", VIRUSTOTAL_API_KEY)
        req.add_header("Accept", "application/json")

        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        total_count = sum(stats.values())

        return {
            "checked": True,
            "malicious": malicious_count > 0,
            "positives": malicious_count,
            "total": total_count
        }

    except Exception as e:
        # Never crash the whole analysis just because VirusTotal is unavailable
        return {"checked": False, "error": str(e)}


# ─────────────────────────────────────────────
#  Main public function
# ─────────────────────────────────────────────

def analyze_urls(urls: list) -> dict:
    """
    Analyzes all URLs extracted from the email.

    Returns:
      {
        "score": int,               # 0 to 40 (capped, as per rapport section 2.4)
        "suspicious_urls": [        # list of suspicious URLs with reasons
          {
            "url": str,
            "reasons": [str, ...],
            "virustotal": dict      # only present if API key is configured
          }
        ]
      }
    """

    if not urls:
        return {"score": 0, "suspicious_urls": []}

    suspicious = []

    for url in urls:
        result = _check_single_url(url)

        # Phase 2: enhance with VirusTotal if key is available
        if VIRUSTOTAL_API_KEY:
            vt = _check_virustotal(url)
            result["virustotal"] = vt
            if vt.get("malicious"):
                result["reasons"].append(
                    f"VirusTotal: flagged by {vt['positives']}/{vt['total']} security engines"
                )
                result["is_suspicious"] = True

        if result["is_suspicious"]:
            suspicious.append({
                "url": result["url"],
                "reasons": result["reasons"],
                **({"virustotal": result["virustotal"]} if "virustotal" in result else {})
            })

    # Score: +40 if ANY suspicious URL found (as per scoring table in rapport 2.4)
    # Multiple suspicious URLs still cap at 40
    score = 40 if suspicious else 0

    return {
        "score": score,
        "suspicious_urls": suspicious
    }


def generate_url_explanation(suspicious_urls: list) -> list:
    """
    Converts URL findings into human-readable explanation lines.
    Used by the explanation system (section 3.4 of the rapport).
    """
    lines = []
    for entry in suspicious_urls:
        reason_str = "; ".join(entry["reasons"])
        lines.append(f"URL anomaly: {entry['url']} — {reason_str}")
    return lines


# ─── Quick test ───────────────────────────────
if __name__ == "__main__":
    test_urls = [
        "http://192.168.1.1/login/verify",
        "https://bit.ly/3xAbc123",
        "http://secure-paypal-update.tk/confirm",
        "https://www.google.com",
    ]

    print("\n========== PHASE 1: Local Analysis ==========\n")

    phase1_results = []

    # Run ONLY Phase 1 manually
    for url in test_urls:
        result = _check_single_url(url)
        phase1_results.append(result)

        if result["is_suspicious"]:
            print(f"URL: {url}")
            for r in result["reasons"]:
                print(f"  - {r}")
            print()

    print("\n========== PHASE 2: VirusTotal ==========\n")

    # Run Phase 2 separately
    for url in test_urls:
        vt = _check_virustotal(url)

        print(f"URL: {url}")

        if not vt.get("checked"):
            print("  - VirusTotal not used (API key missing)")
        else:
            print(f"  - Checked: {vt['checked']}")
            print(f"  - Malicious: {vt['malicious']}")
            print(f"  - Engines: {vt['positives']}/{vt['total']}")

        print()

    print("\n========== FINAL COMBINED RESULT ==========\n")

    result = analyze_urls(test_urls)

    print(f"Score : {result['score']}/40")
    print(f"Suspicious URLs found: {len(result['suspicious_urls'])}\n")

    for entry in result["suspicious_urls"]:
        print(f"URL: {entry['url']}")
        for r in entry["reasons"]:
            print(f"  - {r}")
        print()

    print("Explanations:")
    for line in generate_url_explanation(result["suspicious_urls"]):
        print(" -", line)
