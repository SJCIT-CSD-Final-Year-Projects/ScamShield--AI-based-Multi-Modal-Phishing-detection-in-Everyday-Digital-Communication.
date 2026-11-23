
"""
scamshield_core.py - Safe helpers for ScamShield
Put this file next to app.py.
Install dependencies: pip install markupsafe requests
"""

import ipaddress
import os
import re
import socket
import time
import uuid
from difflib import SequenceMatcher
from urllib.parse import urljoin, urlparse

import requests
from markupsafe import escape


# -------------------------------------------------
# 1. UPLOAD SAFETY
# -------------------------------------------------

ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "webp", "bmp"}
ALLOWED_VIDEO_EXT = {"mp4", "avi", "mov", "mkv", "webm"}


def save_upload(file_storage, folder, allowed_ext):
    """Save an upload using a random filename."""
    original = file_storage.filename or ""
    ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""

    if ext not in allowed_ext:
        raise ValueError("This file type is not allowed.")

    os.makedirs(folder, exist_ok=True)

    name = uuid.uuid4().hex + "." + ext
    path = os.path.join(folder, name)
    file_storage.save(path)

    return path, name


def cleanup_uploads(folder, max_age_seconds=3600):
    """Delete uploaded files older than the specified age."""
    if not os.path.isdir(folder):
        return

    now = time.time()

    for fname in os.listdir(folder):
        path = os.path.join(folder, fname)

        try:
            if (
                os.path.isfile(path)
                and now - os.path.getmtime(path) > max_age_seconds
            ):
                os.remove(path)
        except OSError:
            pass


# -------------------------------------------------
# 2. SAFE LINK FETCHING
# -------------------------------------------------

def is_public_host(hostname):
    """Return True only if all resolved addresses are public."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, OSError):
        return False

    if not infos:
        return False

    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False

    return True


def safe_fetch(url, max_redirects=5, timeout=8, max_bytes=300_000):
    """
    Fetch a web page while checking every redirect destination.

    Returns:
        (final_url, html_text, redirect_hops)

    Raises ValueError for blocked URLs.
    Network errors may raise requests exceptions.
    """
    hops = [url]
    current = url

    for _ in range(max_redirects + 1):
        parsed = urlparse(current)

        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Invalid link.")

        if parsed.username or parsed.password:
            raise ValueError("Links containing embedded credentials are blocked.")

        try:
            port = parsed.port
        except ValueError:
            raise ValueError("Invalid port in link.")

        if port not in (None, 80, 443):
            raise ValueError("Port not allowed.")

        if not is_public_host(parsed.hostname):
            raise ValueError("This address is not allowed.")

        response = requests.get(
            current,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 ScamShield Inspector"},
            allow_redirects=False,
            stream=True,
        )

        if response.is_redirect or response.status_code in (
            301, 302, 303, 307, 308
        ):
            next_url = response.headers.get("Location")
            response.close()

            if not next_url:
                raise ValueError("Redirect destination is missing.")

            current = urljoin(current, next_url)
            hops.append(current)
            continue

        data = bytearray()

        try:
            for chunk in response.iter_content(8192):
                if not chunk:
                    continue

                remaining = max_bytes - len(data)

                if remaining <= 0:
                    break

                data.extend(chunk[:remaining])

                if len(data) >= max_bytes:
                    break

            encoding = response.encoding or "utf-8"
            html_text = bytes(data).decode(encoding, errors="replace")

            return current, html_text, hops

        finally:
            response.close()

    raise ValueError("Too many redirects.")


# -------------------------------------------------
# 3. LINK RISK SIGNALS
# -------------------------------------------------

KNOWN_BRANDS = [
    "sbi",
    "hdfcbank",
    "icicibank",
    "axisbank",
    "paytm",
    "phonepe",
    "googlepay",
    "amazon",
    "flipkart",
    "irctc",
    "incometax",
    "uidai",
    "indiapost",
    "whatsapp",
    "facebook",
    "instagram",
    "netflix",
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "link", "work", "support",
    "loan", "cfd", "icu", "rest", "buzz", "monster",
}

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "shorturl.at",
    "cutt.ly",
    "is.gd",
    "rb.gy",
}


def link_risk_signals(domain):
    """
    Estimate risk from a domain name alone.

    Returns:
        (points, reasons)

    These signals are warnings, not proof that a website is fraudulent.
    """
    domain = (domain or "").strip().lower().rstrip(".")
    points = 0
    reasons = []

    if not domain:
        return 0, ["No domain was provided."]

    labels = domain.split(".")
    tld = labels[-1] if labels else ""
    main = labels[-2] if len(labels) >= 2 else domain

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain):
        points += 3
        reasons.append(
            "Link uses a raw IP address instead of a domain name."
        )

    if domain.startswith("xn--") or ".xn--" in domain:
        points += 3
        reasons.append(
            "Domain uses punycode, which can represent look-alike characters."
        )

    if tld in SUSPICIOUS_TLDS:
        points += 2
        reasons.append(f"Unusual domain ending: .{tld}")

    if main.count("-") >= 2:
        points += 1
        reasons.append("Domain name contains several hyphens.")

    if len(labels) >= 5:
        points += 1
        reasons.append("Domain contains many subdomains.")

    if domain in SHORTENERS:
        points += 1
        reasons.append(
            "Shortened link can hide the final destination."
        )

    for brand in KNOWN_BRANDS:
        if main == brand:
            # A matching brand word does not prove the domain is official.
            continue

        if brand in main:
            points += 3
            reasons.append(
                f"Domain contains '{brand}' but may not be the official domain."
            )
            break

        if SequenceMatcher(None, main, brand).ratio() >= 0.85:
            points += 3
            reasons.append(
                f"Domain name resembles '{brand}'. Verify the actual domain."
            )
            break

    return points, reasons


def risk_level(points):
    """Convert risk points into a simple risk category."""
    if points >= 5:
        return "HIGH"

    if points >= 2:
        return "MEDIUM"

    return "LOW"


# -------------------------------------------------
# 4. MESSAGE SCAM DETECTION
# -------------------------------------------------

def _w(*words):
    """Match whole words or phrases."""
    return re.compile(
        r"\b(?:" + "|".join(words) + r")\b",
        re.I,
    )


SCAM_RULES = [
    {
        "type": "KYC / account block scam",
        "weight": 3,
        "pattern": _w(
            r"kyc",
            r"update your (?:pan|aadhaar|account)",
            r"account (?:will be |has been )?(?:blocked|suspended|closed)",
            r"verify your account",
        ),
        "explain": (
            "Unexpected account-block warnings and KYC links should be "
            "verified through the bank's official app or website."
        ),
    },
    {
        "type": "OTP / PIN theft",
        "weight": 4,
        "pattern": _w(
            r"otp",
            r"cvv",
            r"upi pin",
            r"share (?:the )?code",
            r"verification code",
        ),
        "explain": (
            "Never share an OTP, UPI PIN, password, or CVV with another person."
        ),
    },
    {
        "type": "Digital arrest / police threat",
        "weight": 5,
        "pattern": _w(
            r"digital arrest",
            r"cbi",
            r"narcotics",
            r"customs",
            r"arrest warrant",
            r"money laundering",
            r"trai",
            r"your parcel (?:contains|has)",
        ),
        "explain": (
            "Threats involving digital arrest or demands for money by "
            "video call are major warning signs. Verify independently."
        ),
    },
    {
        "type": "Fake job / task scam",
        "weight": 3,
        "pattern": _w(
            r"work from home",
            r"part[- ]time job",
            r"earn \S+ per day",
            r"like and (?:subscribe|share)",
            r"registration fee",
            r"task (?:and )?earn",
        ),
        "explain": (
            "Be cautious if a job requires an upfront fee or payment "
            "to unlock tasks or earnings."
        ),
    },
    {
        "type": "Lottery / prize scam",
        "weight": 4,
        "pattern": _w(
            r"you (?:have )?won",
            r"lottery",
            r"lucky draw",
            r"prize",
            r"claim your reward",
            r"cashback",
        ),
        "explain": (
            "Unexpected prize claims and advance-fee requests can be scam signs."
        ),
    },
    {
        "type": "Investment / crypto group",
        "weight": 3,
        "pattern": _w(
            r"guaranteed returns?",
            r"double your money",
            r"stock tips",
            r"vip group",
            r"crypto",
            r"100% profit",
        ),
        "explain": (
            "Promises of guaranteed high returns are a warning sign. "
            "Verify investment providers before sending money."
        ),
    },
    {
        "type": "Electricity / bill disconnection",
        "weight": 3,
        "pattern": _w(
            r"electricity (?:bill|connection)",
            r"power (?:will be )?disconnected",
            r"bill (?:is )?overdue",
        ),
        "explain": (
            "Check electricity bills using your provider's official website "
            "or app rather than an unexpected message link."
        ),
    },
    {
        "type": "UPI collect / refund trick",
        "weight": 3,
        "pattern": _w(
            r"refund",
            r"collect request",
            r"scan (?:this )?qr",
            r"enter (?:your )?pin to receive",
        ),
        "explain": (
            "You do not need to share your UPI PIN to receive money. "
            "Read payment requests carefully before approving them."
        ),
    },
    {
        "type": "Fake delivery / courier",
        "weight": 2,
        "pattern": _w(
            r"package (?:is )?held",
            r"delivery failed",
            r"courier",
            r"customs fee",
            r"redelivery",
        ),
        "explain": (
            "Check delivery status using the courier's official tracking service."
        ),
    },
    {
        "type": "Loan app harassment",
        "weight": 2,
        "pattern": _w(
            r"instant loan",
            r"loan approved",
            r"no documents",
            r"processing fee",
        ),
        "explain": (
            "Verify lenders before installing loan apps or sharing personal data."
        ),
    },
]

URGENCY = _w(
    r"urgent",
    r"immediately",
    r"within \d+ (?:hours?|minutes?)",
    r"last chance",
    r"today only",
    r"act now",
    r"expires? (?:today|soon)",
)

PAYMENT_ASK = _w(
    r"pay",
    r"send money",
    r"transfer",
    r"deposit",
    r"fee",
)

URL_RE = re.compile(
    r"(?:https?://|www\.)\S+|\b[\w-]+\.(?:xyz|top|click|link|in|com)/\S*",
    re.I,
)

PHONE_RE = re.compile(r"(?:\+91[\s-]?)?[6-9]\d{9}")


def check_message(text):
    """
    Analyse an SMS or WhatsApp message.

    Returns a dictionary containing:
    level, score, types, reasons, advice, and links.
    """
    text = (text or "").strip()

    if not text:
        return {
            "level": "NONE",
            "score": 0,
            "types": [],
            "reasons": [],
            "advice": ["Please paste the message."],
            "links": [],
        }

    score = 0
    types = []
    reasons = []

    for rule in SCAM_RULES:
        if rule["pattern"].search(text):
            score += rule["weight"]
            types.append(rule["type"])
            reasons.append(rule["explain"])

    if URGENCY.search(text):
        score += 2
        reasons.append("The message pressures you to act quickly.")

    if PAYMENT_ASK.search(text) and types:
        score += 1

    links = URL_RE.findall(text)

    for raw in links:
        cleaned = raw.rstrip(".,!?;:)]}")
        candidate = (
            cleaned if cleaned.lower().startswith(("http://", "https://"))
            else "http://" + cleaned
        )

        host = urlparse(candidate).hostname or ""
        points, why = link_risk_signals(host)

        score += points
        reasons.extend(why)

    if links and types:
        score += 1
        reasons.append(
            "A link combined with suspicious message content is a warning sign."
        )

    level = (
        "HIGH" if score >= 6
        else "MEDIUM" if score >= 3
        else "LOW"
    )

    advice = {
        "HIGH": [
            "Do not click the link or call numbers in the suspicious message.",
            "Never share an OTP, PIN, password, or CVV.",
            "Contact the organisation using independently verified official details.",
            "If you lost money, contact your bank and call India's cybercrime helpline 1930 promptly.",
        ],
        "MEDIUM": [
            "Verify the sender through an official source before taking action.",
            "Avoid the message link; open the official app or website yourself.",
        ],
        "LOW": [
            "No strong scam signs were detected by these rules; this is not a guarantee of safety.",
            "Verify requests for money or personal details independently.",
        ],
    }[level]

    return {
        "level": level,
        "score": score,
        "types": list(dict.fromkeys(types)),
        "reasons": list(dict.fromkeys(reasons)),
        "advice": advice,
        "links": links,
    }


# -------------------------------------------------
# 5. CUSTOMER CARE NUMBER CHECKER
# -------------------------------------------------

# Add numbers here ONLY after checking the organisation's official website
# or official app. Use lowercase organisation names and digits-only numbers.

VERIFIED_NUMBERS = {
    # Example format:
    # "example bank": {"18001234567"},
}

# Add a number here only when a report has been reviewed.
# Store digits-only values.
REPORTED_FAKE_NUMBERS = set()


def digits_only(number):
    """Keep digits; for numbers of 10 or more digits, use the last 10."""
    digits = re.sub(r"\D", "", number or "")

    if len(digits) >= 10:
        return digits[-10:]

    return digits


def check_customer_care(name, number):
    """Compare a number with configured records without claiming live verification."""
    n = digits_only(number)

    if not n:
        return "Please enter a number."

    if n in REPORTED_FAKE_NUMBERS:
        return (
            "RED: This number has been reported as suspicious. "
            "Do not rely on it without independent verification."
        )

    key = (name or "").strip().lower()

    if key in VERIFIED_NUMBERS:
        verified = {
            digits_only(value)
            for value in VERIFIED_NUMBERS[key]
        }

        if n in verified:
            return (
                "GREEN: This matches the official number recorded for "
                + (name or "this organisation")
                + ". Recheck the official source if in doubt."
            )

        return (
            "AMBER: This number does not match the configured official list for "
            + (name or "this organisation")
            + ". Find the number through its official app or website."
        )

    if re.fullmatch(r"[6-9]\d{9}", n):
        return (
            "AMBER: This looks like an ordinary mobile number. "
            "That alone does not prove it is fake. Verify it through "
            "the organisation's official website or app."
        )

    return (
        "BLUE: No matching record is configured in ScamShield. "
        "This does not prove the number is fake or genuine. "
        "Verify it through the official website or app."
    )


# -------------------------------------------------
# 6. COMPLAINT SUMMARY
# -------------------------------------------------

def build_complaint_summary(form):
    """Build a plain-text summary from a dictionary-like form."""
    def get_value(key):
        value = form.get(key) or "Not provided"
        return str(value).strip()

    return f"""SCAM COMPLAINT SUMMARY (prepared with ScamShield)

Date and time of incident : {get_value('when')}
How the scammer contacted : {get_value('channel')}
Scammer phone / UPI / link: {get_value('scammer_id')}
Amount lost (INR)         : {get_value('amount')}
Payment method            : {get_value('method')}
Transaction ID / UTR      : {get_value('txn')}
Bank / wallet used        : {get_value('bank')}

What happened:
{get_value('story')}

Next steps:
1. If money was lost, contact your bank immediately and call 1930 in India.
2. File a complaint at https://cybercrime.gov.in
3. Contact your bank through its official number and ask about securing the account or transaction.
4. Keep screenshots, call logs, messages, and transaction records.
"""
