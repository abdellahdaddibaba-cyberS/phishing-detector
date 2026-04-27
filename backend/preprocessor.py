import re

# ─────────────────────────────────────────────
#  Preprocessing Module
#  Section 2.1 of the rapport:
#    - Extracts text from the email
#    - Identifies URLs
#    - Detects attachments
#
#  Updated: supports real file upload.
#    - If a file is uploaded → use its filename directly
#    - If no file → fall back to regex detection in email body
# ─────────────────────────────────────────────

URL_PATTERN = re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]+')


def preprocess(email_text: str, uploaded_filename: str = None) -> dict:
    """
    Parses a raw email string into its components.

    Parameters:
      email_text        : the raw email body (always required)
      uploaded_filename : filename of the real uploaded file (optional).
                          If provided, skips regex attachment detection.

    Returns:
      {
        "text"        : cleaned email body (URLs removed),
        "urls"        : list of URLs found in the email,
        "attachments" : list of attachment filenames
      }
    """

    if not email_text or not isinstance(email_text, str):
        return {"text": "", "urls": [], "attachments": []}

    # 1. Extract all URLs
    urls = URL_PATTERN.findall(email_text)

    # 2. Clean text — remove URLs so linguistic analysis is not polluted
    clean_text = URL_PATTERN.sub(' ', email_text)
    clean_text = re.sub(r'\s+', ' ', clean_text).strip()

    # 3. Attachments:
    #    - Real file uploaded → trust the filename directly, no guessing needed
    #    - No file uploaded   → fall back to regex search in the email body
    if uploaded_filename:
        attachment_names = [uploaded_filename]
    else:
        attachment_names = re.findall(
            r'\b[\w\-]+\.(?:exe|js|vbs|bat|cmd|ps1|docm|xlsm|pptm|zip|rar|7z|pdf|doc|xls)\b',
            email_text,
            re.IGNORECASE
        )

    return {
        "text":        clean_text,
        "urls":        urls,
        "attachments": attachment_names
    }


# ─── Quick test ───────────────────────────────
if __name__ == "__main__":
    sample = (
        "URGENT: Your bank account has been suspended! "
        "Verify immediately at http://192.168.1.1/login or https://bit.ly/3xAbc. "
        "Please download and run the attached file: setup.exe"
    )

    print("── Test 1: no file uploaded (regex fallback) ──")
    r1 = preprocess(sample)
    print("Text       :", r1["text"])
    print("URLs       :", r1["urls"])
    print("Attachments:", r1["attachments"])

    print()
    print("── Test 2: real file uploaded ──")
    r2 = preprocess(sample, uploaded_filename="invoice.docm")
    print("Text       :", r2["text"])
    print("URLs       :", r2["urls"])
    print("Attachments:", r2["attachments"])
