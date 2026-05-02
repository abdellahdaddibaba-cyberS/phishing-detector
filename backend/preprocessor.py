import re

# ─────────────────────────────────────────────
#  Preprocessing Module
#  Section 2.1 of the rapport:
#    - Extracts text from the email
#    - Identifies URLs
# ─────────────────────────────────────────────

URL_PATTERN = re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]+')


def preprocess(email_text: str) -> dict:
    """
    Parses a raw email string into its components.

    Parameters:
      email_text : the raw email body

    Returns:
      {
        "text" : cleaned email body (URLs removed),
        "urls" : list of URLs found in the email,
      }
    """

    if not email_text or not isinstance(email_text, str):
        return {"text": "", "urls": []}

    # 1. Extract all URLs
    urls = URL_PATTERN.findall(email_text)

    # 2. Clean text — remove URLs so linguistic analysis is not polluted
    clean_text = URL_PATTERN.sub(' ', email_text)
    clean_text = re.sub(r'\s+', ' ', clean_text).strip()

    return {
        "text": clean_text,
        "urls": urls,
    }


# ─── Quick test ───────────────────────────────
if __name__ == "__main__":
    sample = (
        "URGENT: Your bank account has been suspended! "
        "Verify immediately at http://192.168.1.1/login or https://bit.ly/3xAbc."
    )

    r = preprocess(sample)
    print("Text :", r["text"])
    print("URLs :", r["urls"])
