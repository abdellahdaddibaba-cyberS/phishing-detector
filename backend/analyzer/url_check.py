import os
import json
import base64
import time
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path
from dotenv import load_dotenv

# Load .env — walk upward from this file until found
_here = Path(__file__).resolve()
for _parent in [_here.parent, _here.parent.parent, _here.parent.parent.parent]:
    _env = _parent / ".env"
    if _env.exists():
        load_dotenv(dotenv_path=_env, override=True)
        break


def _get_api_key() -> str:
    return os.environ.get("VIRUSTOTAL_API_KEY", "").strip()


def _vt_get(path: str, api_key: str) -> dict:
    url = f"https://www.virustotal.com/api/v3{path}"
    req = urllib.request.Request(url, method="GET")
    req.add_header("x-apikey", api_key)
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


def _vt_post(path: str, body: bytes, api_key: str) -> dict:
    url = f"https://www.virustotal.com/api/v3{path}"
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("x-apikey", api_key)
    req.add_header("Accept", "application/json")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


def _extract_counts(data: dict) -> dict:
    """Pull malicious/suspicious/total from any VT response shape."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total      = sum(stats.values()) if stats else 0
    return {"malicious": malicious, "suspicious": suspicious, "total": total}


def _check_virustotal(url: str) -> dict:
    api_key = _get_api_key()
    if not api_key:
        return {"checked": False, "error": "No API key — set VIRUSTOTAL_API_KEY in your .env"}

    encoded = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    # ── Step 1: Try cached report first (instant, no quota cost) ──
    try:
        report = _vt_get(f"/urls/{encoded}", api_key)
        counts = _extract_counts(report)
        if counts["total"] > 0:
            positives = counts["malicious"] + counts["suspicious"]
            return {
                "checked":   True,
                "malicious": positives > 0,
                "positives": positives,
                "total":     counts["total"],
                "source":    "cache",
            }
    except urllib.error.HTTPError as e:
        if e.code != 404:
            return {"checked": False, "error": f"VT GET error {e.code}"}
        # 404 = URL never scanned before, continue to submit
    except Exception as e:
        return {"checked": False, "error": f"VT GET error: {e}"}

    # ── Step 2: Submit URL for fresh scan ──
    try:
        body = ("url=" + urllib.parse.quote(url, safe="")).encode()
        submit = _vt_post("/urls", body, api_key)
        analysis_id = submit.get("data", {}).get("id", "")
        if not analysis_id:
            return {"checked": False, "error": "VT submit returned no analysis ID"}
    except Exception as e:
        return {"checked": False, "error": f"VT submit error: {e}"}

    # ── Step 3: Poll /analyses/{id} — 8 attempts × 4 s = max 32 s ──
    for attempt in range(8):
        time.sleep(4)
        try:
            analysis = _vt_get(f"/analyses/{analysis_id}", api_key)
            status = analysis.get("data", {}).get("attributes", {}).get("status", "")
            if status == "completed":
                counts = _extract_counts(analysis)
                positives = counts["malicious"] + counts["suspicious"]
                return {
                    "checked":   True,
                    "malicious": positives > 0,
                    "positives": positives,
                    "total":     counts["total"],
                    "source":    "fresh_scan",
                }
            # status == "queued" or "in-progress" — keep polling
        except Exception:
            pass  # network hiccup, retry

    # ── Step 4: Poll timed out — try fetching the cached report one more time ──
    # VT usually updates the cached report even if the analysis endpoint lags
    try:
        report = _vt_get(f"/urls/{encoded}", api_key)
        counts = _extract_counts(report)
        if counts["total"] > 0:
            positives = counts["malicious"] + counts["suspicious"]
            return {
                "checked":   True,
                "malicious": positives > 0,
                "positives": positives,
                "total":     counts["total"],
                "source":    "cache_after_poll",
            }
    except Exception:
        pass

    return {"checked": False, "error": "VT scan did not complete in time — try again in a few seconds"}


# ─────────────────────────────────────────────
#  Main public function
# ─────────────────────────────────────────────

def analyze_urls(urls: list) -> dict:
    if not urls:
        return {"score": 0, "suspicious_urls": []}

    suspicious = []

    for url in urls:
        vt = _check_virustotal(url)

        if not vt.get("checked"):
            # API key missing or network error — report it but don't score
            suspicious.append({
                "url":        url,
                "reasons":    [f"VirusTotal check failed: {vt.get('error', 'unknown error')}"],
                "virustotal": vt,
                "vt_error":   True,
            })
            continue

        if vt.get("malicious"):
            suspicious.append({
                "url":        url,
                "reasons":    [f"VirusTotal: flagged by {vt['positives']}/{vt['total']} security engines"],
                "virustotal": vt,
            })

    # Only score confirmed-malicious URLs, not API errors
    confirmed_malicious = [u for u in suspicious if not u.get("vt_error")]
    score = 40 if confirmed_malicious else 0

    return {
        "score":           score,
        "suspicious_urls": suspicious,
    }


def generate_url_explanation(suspicious_urls: list) -> list:
    lines = []
    for entry in suspicious_urls:
        if entry.get("vt_error"):
            lines.append(f"URL check error — {entry['reasons'][0]}")
        else:
            lines.append(f"Malicious URL: {entry['url']} — {'; '.join(entry['reasons'])}")
    return lines


# ─── Quick test ───────────────────────────────
if __name__ == "__main__":
    import sys
    test_urls = sys.argv[1:] or ["http://malware.testing.google.test/testing/malware/"]
    key = _get_api_key()
    print(f"API key loaded: {'YES (' + key[:6] + '...)' if key else 'NO — check .env path'}")
    print(f"Testing {len(test_urls)} URL(s)...\n")
    result = analyze_urls(test_urls)
    print(f"Score: {result['score']}/40")
    for u in result["suspicious_urls"]:
        tag = "ERROR" if u.get("vt_error") else "FLAGGED"
        print(f"  [{tag}] {u['url'][:80]}")
        for r in u["reasons"]:
            print(f"    - {r}")
    clean = [u for u in test_urls if u not in [s["url"] for s in result["suspicious_urls"]]]
    for u in clean:
        print(f"  [CLEAN] {u[:80]}")
