"""
ScamShield - Your Digital Safety Helper  (full app.py)

Folder layout:
    app.py
    scamshield_core.py
    templates/index.html
    requirements.txt

Run:
    pip install -r requirements.txt
    python app.py
"""

import csv
import os
import re
import time
from datetime import datetime
from urllib.parse import urlparse

import cv2
import pytesseract
from bs4 import BeautifulSoup
from flask import Flask, Response, render_template, request, send_from_directory
from markupsafe import escape

from scamshield_core import (
    ALLOWED_IMAGE_EXT,
    ALLOWED_VIDEO_EXT,
    build_complaint_summary,
    check_customer_care,
    check_message,
    cleanup_uploads,
    link_risk_signals,
    safe_fetch,
    save_upload,
)

# -------------------------------------------------
# APP SETUP
# -------------------------------------------------

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB

# Set TESSERACT_CMD if tesseract is not on your PATH
pytesseract.pytesseract.tesseract_cmd = os.environ.get(
    "TESSERACT_CMD", r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)

FEEDBACK_FILE = "feedback.csv"


@app.before_request
def auto_cleanup():
    """Privacy: delete uploaded/processed files older than 1 hour."""
    cleanup_uploads(UPLOAD_FOLDER, max_age_seconds=3600)


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.errorhandler(413)
def too_big(_error):
    return "File is too large (maximum 50 MB).", 413


# -------------------------------------------------
# SMALL HELPERS
# -------------------------------------------------

BOX_COLOURS = {
    "red": ("#fff3f3", "#e53935", "#c62828"),
    "orange": ("#fff7e8", "#ff9800", "#8a4b00"),
    "blue": ("#eef4fb", "#607d9b", "#35516f"),
    "green": ("#e8f5e9", "#4caf50", "#2e7d32"),
}


def box(kind, title, body_html=""):
    bg, border, colour = BOX_COLOURS[kind]
    return (
        f'<div style="padding:20px;border-radius:15px;background:{bg};'
        f'border:2px solid {border};margin-top:10px;">'
        f'<h3 style="color:{colour};margin-top:0;">{title}</h3>{body_html}</div>'
    )


def kw_match(text, words):
    """ASCII words match as whole words ('pin' will not match 'shopping').
    Non-ASCII words (Kannada, Telugu, Hindi) match as substrings."""
    for word in words:
        if word.isascii():
            if re.search(r"\b" + re.escape(word) + r"\b", text):
                return True
        elif word in text:
            return True
    return False


def li(items):
    return "".join(f"<li>{escape(i)}</li>" for i in items)


# -------------------------------------------------
# HOME PAGE AND UPLOADED FILES
# -------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/uploads/<filename>")
def uploaded_file(filename):
    if not filename.lower().endswith((".png", ".jpg", ".jpeg")):
        return "Not found", 404
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# -------------------------------------------------
# VOICE ASSISTANT  (English, Kannada, Telugu, Hindi)
# -------------------------------------------------

VOICE = {
    "en-IN": {
        "empty": "Please tell me what happened.",
        "default": (
            "I can help you understand suspicious digital content. "
            "You can tell me what happened, or show me a link, image, or video."
        ),
        "rules": [
            (["already clicked", "i clicked", "clicked the link", "opened the link"],
             "Do not panic. Stop interacting with the link. If you entered your "
             "password, OTP, card details, or made a payment, contact your bank or "
             "service provider immediately and secure your account. If money was "
             "lost, call 1930."),
            (["otp", "password", "pin", "cvv", "bank details", "card details"],
             "Do not share your OTP, password, PIN, CVV, or banking details with "
             "anyone. If someone is asking for them on a call or message, treat it "
             "with caution."),
            (["payment", "send money", "transfer money", "pay money"],
             "Do not send money until you verify who contacted you. Never make a "
             "payment only because someone is pressuring you on a call or message."),
            (["scam", "fraud", "suspicious", "fake"],
             "This may require caution. Do not share personal information or money "
             "until you verify the sender through an official source."),
            (["what is this", "what does this mean", "i don't understand",
              "i do not understand"],
             "I can help you understand it. Show me the message, link, image, or "
             "video and I will explain it."),
        ],
    },
    "kn-IN": {
        "empty": "ಏನಾಯಿತು ಎಂದು ದಯವಿಟ್ಟು ಹೇಳಿ.",
        "default": ("ನಾನು ನಿಮ್ಮ ಡಿಜಿಟಲ್ ಸುರಕ್ಷತಾ ಸಹಾಯಕ. ಏನಾಯಿತು ಎಂದು ಹೇಳಿ ಅಥವಾ "
                    "ಮೆಸೇಜ್, ಲಿಂಕ್, ಚಿತ್ರ ಅಥವಾ ವೀಡಿಯೊವನ್ನು ತೋರಿಸಿ."),
        "rules": [
            (["ಕ್ಲಿಕ್", "clicked"],
             "ಗಾಬರಿಯಾಗಬೇಡಿ. ಆ ಲಿಂಕ್‌ನಲ್ಲಿ ಮುಂದೆ ಏನನ್ನೂ ಮಾಡಬೇಡಿ. ನೀವು ಪಾಸ್ವರ್ಡ್, "
             "OTP ಅಥವಾ ಕಾರ್ಡ್ ಮಾಹಿತಿ ನೀಡಿದ್ದರೆ ತಕ್ಷಣ ನಿಮ್ಮ ಬ್ಯಾಂಕ್‌ನ ಅಧಿಕೃತ ಸಂಖ್ಯೆಗೆ "
             "ಕರೆ ಮಾಡಿ. ಹಣ ಹೋಗಿದ್ದರೆ 1930 ಗೆ ಕರೆ ಮಾಡಿ."),
            (["otp", "ಪಾಸ್ವರ್ಡ್", "ಪಿನ್", "ಬ್ಯಾಂಕ್", "ಕಾರ್ಡ್"],
             "ನಿಮ್ಮ OTP, ಪಾಸ್ವರ್ಡ್, PIN, CVV ಅಥವಾ ಬ್ಯಾಂಕ್ ಮಾಹಿತಿಯನ್ನು ಯಾರಿಗೂ "
             "ನೀಡಬೇಡಿ. ಯಾರಾದರೂ ಫೋನ್ ಅಥವಾ ಮೆಸೇಜ್ ಮೂಲಕ ಕೇಳಿದರೆ ಎಚ್ಚರಿಕೆಯಿಂದಿರಿ."),
            (["ಪಾವತಿ", "payment"],
             "ಯಾರು ಸಂಪರ್ಕಿಸಿದ್ದಾರೆ ಎಂದು ಪರಿಶೀಲಿಸುವವರೆಗೆ ಹಣ ಕಳುಹಿಸಬೇಡಿ. ಕರೆ ಅಥವಾ "
             "ಮೆಸೇಜ್‌ನಲ್ಲಿ ಒತ್ತಡ ಹಾಕಿದರೆ ಪಾವತಿ ಮಾಡಬೇಡಿ."),
            (["ಸ್ಕ್ಯಾಮ್", "ಮೋಸ", "fraud", "fake"],
             "ಇದು ಮೋಸವಾಗಿರುವ ಸಾಧ್ಯತೆ ಇದೆ. ಯಾರಿಗೂ ವೈಯಕ್ತಿಕ ಮಾಹಿತಿ ಅಥವಾ ಹಣ ನೀಡುವ "
             "ಮೊದಲು ಅಧಿಕೃತ ಮೂಲದಿಂದ ಪರಿಶೀಲಿಸಿ."),
            (["ಅರ್ಥ", "ಏನು", "ಗೊತ್ತಾಗುತ್ತಿಲ್ಲ"],
             "ನಾನು ನಿಮಗೆ ಅರ್ಥಮಾಡಿಕೊಳ್ಳಲು ಸಹಾಯ ಮಾಡುತ್ತೇನೆ. ಮೆಸೇಜ್, ಲಿಂಕ್, ಚಿತ್ರ "
             "ಅಥವಾ ವೀಡಿಯೊವನ್ನು ತೋರಿಸಿ."),
        ],
    },
    "te-IN": {
        "empty": "దయచేసి ఏం జరిగిందో చెప్పండి.",
        "default": ("నేను మీ డిజిటల్ సేఫ్టీ అసిస్టెంట్. ఏం జరిగిందో చెప్పండి లేదా "
                    "మెసేజ్, చిత్రం లేదా వీడియోను చూపించండి."),
        "rules": [
            (["క్లిక్", "clicked"],
             "కంగారు పడకండి. ఆ లింక్‌లో ఇక ఏమీ చేయకండి. మీరు పాస్వర్డ్, OTP లేదా "
             "కార్డ్ వివరాలు ఇచ్చి ఉంటే వెంటనే మీ బ్యాంక్ అధికారిక నంబర్‌కు కాల్ "
             "చేయండి. డబ్బు పోయి ఉంటే 1930 కు కాల్ చేయండి."),
            (["otp", "పాస్వర్డ్", "పిన్", "బ్యాంక్", "కార్డ్"],
             "మీ OTP, పాస్వర్డ్, PIN, CVV లేదా బ్యాంక్ వివరాలను ఎవరితోనూ పంచుకోవద్దు. "
             "ఫోన్ లేదా మెసేజ్ ద్వారా అడిగితే జాగ్రత్తగా ఉండండి."),
            (["చెల్లింపు", "payment"],
             "ఎవరు సంప్రదించారో ధృవీకరించే వరకు డబ్బు పంపకండి. ఫోన్ లేదా మెసేజ్‌లో "
             "ఒత్తిడి చేసినా చెల్లింపు చేయకండి."),
            (["స్కామ్", "మోసం", "fraud", "fake"],
             "ఇది మోసం అయ్యే అవకాశం ఉంది. వ్యక్తిగత సమాచారం లేదా డబ్బు ఇవ్వడానికి "
             "ముందు అధికారిక మార్గం ద్వారా ధృవీకరించండి."),
            (["అర్థం", "ఏమిటి", "తెలియడం లేదు"],
             "నేను మీకు అర్థం చేసుకోవడంలో సహాయం చేస్తాను. మెసేజ్, లింక్, చిత్రం "
             "లేదా వీడియోను చూపించండి."),
        ],
    },
    "hi-IN": {
        "empty": "कृपया बताइए क्या हुआ।",
        "default": ("मैं आपका डिजिटल सुरक्षा सहायक हूं। बताइए क्या हुआ, या मैसेज, "
                    "लिंक, फोटो या वीडियो दिखाइए।"),
        "rules": [
            (["क्लिक", "clicked"],
             "घबराएं नहीं। उस लिंक पर आगे कुछ न करें। अगर आपने पासवर्ड, OTP या कार्ड "
             "की जानकारी डाली है, तो तुरंत अपने बैंक के आधिकारिक नंबर पर संपर्क करें। "
             "पैसे कट गए हों तो 1930 पर कॉल करें।"),
            (["otp", "पासवर्ड", "पिन", "बैंक", "कार्ड", "cvv"],
             "अपना OTP, पासवर्ड, PIN, CVV या बैंक की जानकारी किसी को न दें। अगर कोई "
             "फोन या मैसेज पर मांगे तो सावधान रहें।"),
            (["पैसे", "पेमेंट", "भुगतान", "payment"],
             "जब तक आप यह पक्का न कर लें कि किसने संपर्क किया है, पैसे न भेजें। कॉल या "
             "मैसेज पर दबाव डालने से भुगतान न करें।"),
            (["स्कैम", "धोखा", "ठगी", "fraud", "fake"],
             "यह धोखाधड़ी हो सकती है। व्यक्तिगत जानकारी या पैसे देने से पहले "
             "आधिकारिक स्रोत से जांच करें।"),
            (["मतलब", "क्या है", "समझ नहीं"],
             "मैं समझाने में मदद करूंगा। मैसेज, लिंक, फोटो या वीडियो दिखाइए।"),
        ],
    },
}


def get_voice_answer(message, language):
    text = (message or "").lower().strip()
    pack = VOICE.get(language, VOICE["en-IN"])

    if not text:
        return pack["empty"]

    for words, answer in pack["rules"]:
        if kw_match(text, words):
            return answer

    return pack["default"]


@app.route("/voice-answer", methods=["POST"])
def voice_answer():
    message = request.form.get("message", "").strip()
    language = request.form.get("language", "en-IN")
    return get_voice_answer(message, language)


# -------------------------------------------------
# CHECK A MESSAGE (SMS / WhatsApp)
# -------------------------------------------------

@app.route("/check-message", methods=["POST"])
def check_message_route():
    result = check_message(request.form.get("message", ""))

    if result["level"] == "NONE":
        return box("blue", "Please paste a message first.")

    kind, title = {
        "HIGH": ("red", "🚨 HIGH RISK - LIKELY A SCAM"),
        "MEDIUM": ("orange", "⚠️ BE CAREFUL"),
        "LOW": ("blue", "🔵 NO STRONG SCAM SIGNS FOUND"),
    }[result["level"]]

    body = ""
    if result["types"]:
        body += "<h4>This looks like:</h4><ul>" + li(result["types"]) + "</ul>"
    if result["reasons"]:
        body += "<h4>Why:</h4><ul>" + li(result["reasons"]) + "</ul>"
    body += "<h4>What to do:</h4><ul>" + li(result["advice"]) + "</ul>"
    body += (
        '<p style="font-size:12px;color:#666;">This is an automatic check and can '
        "be wrong. When in doubt, verify through the official app or website.</p>"
    )
    return box(kind, title, body)


# -------------------------------------------------
# LINK ANALYSIS
# -------------------------------------------------

def could_not_inspect(domain_reasons):
    body = (
        "<p>ScamShield could not open this webpage for inspection.</p>"
        "<p>This does <b>not</b> mean the website is safe or dangerous.</p>"
    )
    if domain_reasons:
        body += "<p><b>But the link itself looks unusual:</b></p><ul>" + li(domain_reasons) + "</ul>"
    body += (
        "<p>Do not enter OTP, PIN, password, card or banking information until "
        "the website is independently verified.</p>"
    )
    return box("orange", "⚠️ LINK COULD NOT BE INSPECTED", body)


@app.route("/analyze-link", methods=["POST"])
def analyze_link():
    """Inspect a URL without opening it in the user's browser."""
    raw_link = (request.form.get("link") or "").strip()
    if not raw_link:
        return box("orange", "⚠️ Please enter a link.")

    link = raw_link if raw_link.lower().startswith(("http://", "https://")) else "https://" + raw_link
    parsed = urlparse(link)
    if not parsed.netloc or not parsed.hostname:
        return box("red", "❌ Invalid link", "<p>Please enter a complete website address.</p>")

    original_domain = (parsed.hostname or "").lower()
    domain_points, domain_reasons = link_risk_signals(original_domain)
    final_url, page_html, hops = link, "", []
    inspection_note = ""

    # safe_fetch is responsible for validating destinations and blocking private/internal IPs.
    try:
        final_url, page_html, hops = safe_fetch(link)
        hops = hops or []
    except ValueError as error:
        return box("red", "⛔ Link blocked from inspection",
                   f"<p>{escape(str(error))}</p><p>ScamShield did not open this link in your browser.</p>")
    except Exception as error:
        print("LINK FETCH ERROR:", error)
        inspection_note = "The webpage could not be retrieved for inspection. This is not proof that it is safe or unsafe."

    final_domain = (urlparse(final_url).hostname or "").lower()
    final_points, final_reasons = link_risk_signals(final_domain) if final_domain else (0, [])
    all_reasons = list(dict.fromkeys(list(domain_reasons or []) + list(final_reasons or [])))
    findings = []
    high_risk = []
    for reason in all_reasons:
        findings.append(("Domain warning", str(reason)))
    if original_domain != final_domain and final_domain:
        findings.append(("Redirect", f"The inspected page ended at {final_domain}, different from the original host."))

    page_text = ""
    password_inputs = []
    if page_html:
        try:
            soup = BeautifulSoup(page_html, "html.parser")
            password_inputs = soup.find_all("input", attrs={"type": lambda value: value and value.lower() == "password"})
            for tag in soup(["script", "style", "noscript"]):
                tag.decompose()
            page_text = soup.get_text(" ", strip=True).lower()
        except Exception as error:
            print("PAGE PARSE ERROR:", error)

    checks = [
        (password_inputs, "Password field", "A password input field was found.", "PASSWORD"),
        (kw_match(page_text, ["otp", "one time password", "one-time password", "verification code"]), "OTP request", "The page text mentions an OTP or verification code.", "OTP"),
        (kw_match(page_text, ["upi pin", "atm pin", "card pin", "enter your pin", "pin number"]), "PIN request", "The page text appears to request a PIN.", "PIN"),
        (kw_match(page_text, ["card number", "credit card", "debit card", "cvv", "expiry date", "expiration date"]), "Card details", "The page text mentions payment-card details.", "CARD"),
        (kw_match(page_text, ["bank account", "account number", "ifsc", "bank details"]), "Bank details", "The page text mentions bank information.", "BANK"),
        (kw_match(page_text, ["make payment", "pay now", "upi payment", "send money", "transfer money", "processing fee", "registration fee"]), "Payment request", "The page text mentions a payment or fee.", "PAYMENT"),
        ((".apk" in final_url.lower() or ".apk" in page_text or kw_match(page_text, ["download apk", "install apk", "download app", "install app"])), "App download", "The URL or page text suggests an app/APK download.", "APK"),
        (kw_match(page_text, ["aadhaar", "pan card", "date of birth", "mobile number", "phone number", "email address"]), "Personal information", "The page text mentions personal information.", "PERSONAL"),
        (kw_match(page_text, ["login", "log in", "sign in", "verify your account", "account verification"]), "Login/verification", "The page text mentions account login or verification.", "LOGIN"),
    ]
    for condition, label, explanation, code in checks:
        if condition:
            findings.append((label, explanation))
            if code in {"PASSWORD", "OTP", "PIN", "CARD", "BANK", "PAYMENT", "APK"}:
                high_risk.append(code)

    # Highlight URL components for a visual investigation result (never make it a clickable link).
    host = parsed.hostname or ""
    url_parts = [
        ("Protocol", parsed.scheme + "://"),
        ("Host", host),
    ]
    if parsed.port:
        url_parts.append(("Port", f":{parsed.port}"))
    if parsed.path and parsed.path != "/":
        url_parts.append(("Path", parsed.path))
    if parsed.query:
        url_parts.append(("Query parameters", "?" + parsed.query))
    if parsed.fragment:
        url_parts.append(("Fragment", "#" + parsed.fragment))
    url_html = "".join(
        '<div style="padding:9px 12px;margin:6px 0;background:#fff;border:1px solid #ead7d7;border-radius:8px;overflow-wrap:anywhere;">'
        f'<b>{escape(label)}:</b> <code>{escape(value)}</code></div>'
        for label, value in url_parts
    )

    # Show redirect observations only; safe_fetch does not submit forms or log in.
    redirect_items = []
    if isinstance(hops, (list, tuple)):
        for hop in hops[:10]:
            if isinstance(hop, str):
                text = hop
            elif isinstance(hop, dict):
                text = hop.get("url") or hop.get("location") or str(hop)
            elif isinstance(hop, (list, tuple)):
                text = " → ".join(str(part) for part in hop)
            else:
                text = str(hop)
            redirect_items.append(str(text))
    redirect_html = (
        "<ol>" + "".join(f"<li style='overflow-wrap:anywhere'>{escape(item)}</li>" for item in redirect_items) + "</ol>"
        if redirect_items else "<p>No redirect chain details were returned by the fetch helper.</p>"
    )

    if max(domain_points or 0, final_points or 0) >= 2 and not any(label == "Domain warning" for label, _ in findings):
        findings.append(("Domain warning", "The domain name has characteristics that the current heuristic treats as unusual."))
    if not findings:
        findings.append(("No obvious indicator found", "The checks did not find the basic warning patterns they currently look for."))

    finding_html = "".join(
        f"<li style='margin:8px 0'><b>{escape(label)}:</b> {escape(explanation)}</li>"
        for label, explanation in findings
    )
    actions = [
        "Do not enter an OTP, UPI PIN, password, or card details on a page reached from an unexpected message.",
        "Verify the offer or request by opening the official app or typing the known official website address yourself.",
        "Do not install an APK or app sent by an unknown person.",
    ]
    if high_risk or max(domain_points or 0, final_points or 0) >= 2:
        title = "🚨 SCAMSHIELD LINK INVESTIGATION — CAUTION"
        kind = "red"
        summary = "Several warning indicators may be present. Treat this link as suspicious until independently verified."
    elif inspection_note:
        title = "⚠️ LINK COULD NOT BE FULLY INSPECTED"
        kind = "orange"
        summary = inspection_note
    else:
        title = "🔎 LINK INVESTIGATION RESULTS"
        kind = "blue"
        summary = "No strong warning was detected by the current checks. This does not certify the website as safe."

    body = (
        f"<p><b>Submitted address:</b> <span style='overflow-wrap:anywhere'>{escape(raw_link)}</span></p>"
        f"<p>{escape(summary)}</p>"
        "<h4>🧩 Suspicious URL parts highlighted</h4>"
        + url_html
        + "<h4>🔬 Investigation findings</h4><ul style='line-height:1.6'>"
        + finding_html + "</ul>"
        + "<h4>🔄 Redirect / destination observations</h4>"
        + f"<p><b>Final inspected host:</b> {escape(final_domain or 'Not available')}</p>"
        + redirect_html
        + "<h4>🛡️ Recommended actions</h4><ul>" + li(actions) + "</ul>"
        + '<p style="font-size:12px;color:#666">Safety note: ScamShield inspects retrievable page content and URL signals only. It does not prove a site is safe, and it does not click buttons, submit forms, or log in.</p>'
        + ('<button type="button" class="btn btn-danger" onclick="playScamAlert()">🔊 PLAY WARNING</button>' if kind == "red" else "")
    )
    return box(kind, title, body)


# -------------------------------------------------
# QR HELPERS (used by image analysis and photo protection)
# -------------------------------------------------

def find_qr(image):
    """Return a list of (4x2 point array, decoded text) for QR codes found."""
    detector = cv2.QRCodeDetector()
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))

    variants = [
        (image, 1.0),
        (cv2.resize(image, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC), 2.0),
        (cv2.resize(image, None, fx=3, fy=3, interpolation=cv2.INTER_CUBIC), 3.0),
        (gray, 1.0),
        (clahe.apply(gray), 1.0),
    ]

    for img, scale in variants:
        try:
            ok, texts, points, _ = detector.detectAndDecodeMulti(img)
            if ok and points is not None and len(points):
                return [(p.reshape(-1, 2) / scale, t) for p, t in zip(points, texts)]
        except Exception:
            pass
        try:
            text, points, _ = detector.detectAndDecode(img)
            if points is not None:
                return [(points.reshape(-1, 2) / scale, text)]
        except Exception:
            pass

    try:
        ok, points = detector.detect(image)
        if ok and points is not None:
            return [(points.reshape(-1, 2), "")]
    except Exception:
        pass

    return []


def has_word(text, words):
    return kw_match(text, words)


def obscure(img, x1, y1, x2, y2):
    """Pixelate + blur a region so the text cannot be recovered."""
    height, width = img.shape[:2]
    x1, y1 = max(0, int(x1)), max(0, int(y1))
    x2, y2 = min(width, int(x2)), min(height, int(y2))
    if x2 <= x1 or y2 <= y1:
        return
    region = img[y1:y2, x1:x2]
    small = cv2.resize(
        region,
        (max(1, (x2 - x1) // 12), max(1, (y2 - y1) // 12)),
        interpolation=cv2.INTER_LINEAR,
    )
    pixelated = cv2.resize(small, (x2 - x1, y2 - y1), interpolation=cv2.INTER_NEAREST)
    img[y1:y2, x1:x2] = cv2.GaussianBlur(pixelated, (31, 31), 0)


def safe_remove(path):
    try:
        os.remove(path)
    except OSError:
        pass


# -------------------------------------------------
# IMAGE ANALYSIS
# -------------------------------------------------

IMAGE_RULES = [
    ("OTP request", ["otp", "one time password"]),
    ("Password request", ["password", "passcode"]),
    ("PIN/CVV request", ["pin", "cvv"]),
    ("Payment request", ["pay", "payment", "send money", "transfer"]),
    ("Urgent/pressure message", ["urgent", "immediately", "act now",
                                 "account blocked", "account will be blocked"]),
    ("Prize/reward claim", ["winner", "won", "prize", "reward", "lottery"]),
]


@app.route("/analyze-image", methods=["POST"])
def analyze_image():
    file = request.files.get("image")
    if not file or file.filename == "":
        return box("orange", "Please select an image.")

    try:
        path, filename = save_upload(file, UPLOAD_FOLDER, ALLOWED_IMAGE_EXT)
    except ValueError as error:
        return box("orange", escape(str(error)))

    image = cv2.imread(path)
    safe_remove(path)  # Do not retain the original upload.
    if image is None:
        return box("orange", "Unable to read the image.")

    highlighted = image.copy()
    warnings = []
    extracted_tokens = []
    qr_results = []
    qr_notes = []

    # OCR text and mark words that match the current scam-warning rules.
    try:
        ocr = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
        for i in range(len(ocr["text"])):
            word = (ocr["text"][i] or "").strip()
            if not word:
                continue
            extracted_tokens.append(word)
            x, y = int(ocr["left"][i]), int(ocr["top"][i])
            w, h = int(ocr["width"][i]), int(ocr["height"][i])
            low = word.lower()
            reason = ""
            for label, words in IMAGE_RULES:
                if has_word(low, words):
                    reason = label
                    break
            if not reason and ("http://" in low or "https://" in low or "www." in low):
                reason = "Link detected"
            if reason:
                cv2.rectangle(highlighted, (max(0, x - 6), max(0, y - 6)),
                              (min(image.shape[1] - 1, x + w + 6), min(image.shape[0] - 1, y + h + 6)),
                              (0, 0, 255), 3)
                cv2.putText(highlighted, reason, (max(0, x), max(22, y - 8)),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.55, (0, 0, 255), 2)
                if reason not in warnings:
                    warnings.append(reason)
    except Exception as error:
        print("OCR ERROR:", error)

    extracted_text = " ".join(extracted_tokens).strip()
    if not extracted_text:
        extracted_text = "No readable text was extracted. This can happen with blurry, low-contrast, or text-free images."

    # Decode QR codes, mark them in the preview, and inspect URL-shaped destinations without opening them in a browser.
    try:
        for points, decoded in find_qr(image):
            pts = points.astype(int)
            cv2.polylines(highlighted, [pts], True, (0, 0, 255), 4)
            bx, by, _bw, _bh = cv2.boundingRect(pts)
            cv2.putText(highlighted, "QR CODE", (max(0, bx), max(25, by - 8)),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
            decoded = (decoded or "").strip()
            qr_results.append(decoded or "QR detected, but its content could not be decoded.")
            if "QR code detected." not in warnings:
                warnings.append("QR code detected.")
            if decoded.lower().startswith(("http://", "https://")):
                host = (urlparse(decoded).hostname or "").lower()
                score, reasons = link_risk_signals(host) if host else (0, [])
                qr_notes.append(
                    f"<p><b>QR website host:</b> {escape(host or 'Unknown')} "
                    f"— heuristic score: {int(score or 0)}.</p>"
                    + ("<ul>" + li([str(r) for r in reasons]) + "</ul>" if reasons else "")
                    + "<p>Use Check Link to inspect the full address before opening it.</p>"
                )
                if score >= 2 and "Suspicious QR destination" not in warnings:
                    warnings.append("Suspicious QR destination")
            elif decoded.lower().startswith("upi://"):
                qr_notes.append("<p><b>QR payment request detected.</b> Check the recipient and amount carefully. A QR code is not needed to receive money, and you should never enter your UPI PIN just to receive money.</p>")
            elif decoded:
                qr_notes.append(f"<p><b>QR content:</b> {escape(decoded[:250])}</p>")
    except Exception as error:
        print("QR ERROR:", error)

    highlighted_filename = os.path.splitext(filename)[0] + "_analyzed.png"
    cv2.imwrite(os.path.join(UPLOAD_FOLDER, highlighted_filename), highlighted)
    highlighted_url = "/uploads/" + highlighted_filename

    text_panel = (
        "<details style='margin:12px 0;padding:12px;background:#fff;border:1px solid #ddd;border-radius:10px'>"
        "<summary style='cursor:pointer;font-weight:bold'>📝 View extracted text</summary>"
        f"<p style='white-space:pre-wrap;overflow-wrap:anywhere'>{escape(extracted_text[:6000])}</p></details>"
    )
    qr_panel = ""
    if qr_results:
        qr_panel = "<h4>🔳 QR-code results</h4><ul>" + li(qr_results) + "</ul>" + "".join(qr_notes)
    findings_panel = (
        "<h4>🔍 Visual Scam Investigator findings</h4><ul>"
        + ("".join(f"<li>{escape(w)}</li>" for w in warnings) if warnings else "<li>No current rule matched the visible text or decoded QR contents.</li>")
        + "</ul>"
    )
    image_panel = (
        '<h4>🖼️ Analyzed image preview</h4>'
        f'<img src="{escape(highlighted_url)}" alt="Analyzed image with warning highlights" '
        'style="display:block;width:100%;max-width:680px;height:auto;max-height:600px;object-fit:contain;'
        'border-radius:12px;border:2px solid #ddd;margin:10px auto;">'
        "<p><b>Red boxes</b> mark text patterns or QR codes that need review.</p>"
    )
    if warnings:
        title, kind = "🚨 VISUAL SCAM INVESTIGATOR — REVIEW FINDINGS", "red"
        intro = "<p>ScamShield found one or more patterns that deserve attention. A match is a warning signal, not proof that the image is fraudulent.</p>"
    else:
        title, kind = "🔎 VISUAL SCAM INVESTIGATOR — NO BASIC PATTERN MATCHED", "blue"
        intro = "<p>The current checks did not find a basic suspicious pattern. This does not prove the image is genuine or safe.</p>"

    body = (
        intro + findings_panel + text_panel + qr_panel + image_panel
        + "<h4>✅ Recommended next steps</h4><ul>"
        + li([
            "Do not share an OTP, password, PIN, or card details because an image asks you to.",
            "If the image contains a website address or QR link, inspect the full address in Check Link before opening it.",
            "Verify offers, prizes, payment requests, and customer-care details through an official source.",
        ])
        + "</ul><p style='font-size:12px;color:#666'>This feature checks visible text and decodable QR contents. It does not currently prove image authenticity or detect deepfakes/manipulation.</p>"
    )
    return box(kind, title, body)


# -------------------------------------------------
# VIDEO ANALYSIS
# -------------------------------------------------

VIDEO_WORDS = [
    "otp", "password", "pin", "cvv", "urgent", "immediately", "prize", "winner",
    "payment", "pay", "bank", "verify", "account", "transfer", "money",
]

MAX_VIDEO_SECONDS = 300
MAX_PROCESSING_SECONDS = 60


@app.route("/analyze-video", methods=["POST"])
def analyze_video():
    file = request.files.get("video")
    if not file or file.filename == "":
        return "Please select a video."

    try:
        video_path, filename = save_upload(file, UPLOAD_FOLDER, ALLOWED_VIDEO_EXT)
    except ValueError as error:
        return str(error)

    capture = cv2.VideoCapture(video_path)
    if not capture.isOpened():
        safe_remove(video_path)
        return "Unable to open the video."

    fps = capture.get(cv2.CAP_PROP_FPS)
    if not fps or fps <= 0:
        fps = 25
    total_frames = int(capture.get(cv2.CAP_PROP_FRAME_COUNT))
    duration = total_frames / fps

    if duration > MAX_VIDEO_SECONDS:
        capture.release()
        safe_remove(video_path)
        return "Please upload a video shorter than 5 minutes."

    interval = max(1, int(fps * 2))  # about every 2 seconds
    suspicious_frames = []
    frame_number = 0
    started = time.time()

    while True:
        success, frame = capture.read()
        if not success:
            break

        if frame_number % interval == 0:
            try:
                text = pytesseract.image_to_string(frame).lower()
                found = [w for w in VIDEO_WORDS if has_word(text, [w])]
                if found:
                    suspicious_frames.append({
                        "frame": frame.copy(),
                        "time": frame_number / fps,
                        "words": found,
                        "text": " ".join(text.split())[:300],
                    })
            except Exception:
                pass

        frame_number += 1

        if len(suspicious_frames) >= 8:
            break
        if time.time() - started > MAX_PROCESSING_SECONDS:
            break

    capture.release()
    safe_remove(video_path)  # privacy: keep only the review frames

    frame_html = ""
    base = os.path.splitext(filename)[0]

    for index, item in enumerate(suspicious_frames):
        frame = item["frame"]
        timestamp = item["time"]
        time_text = f"{int(timestamp // 60):02d}:{int(timestamp % 60):02d}"

        cv2.rectangle(frame, (5, 5), (frame.shape[1] - 5, frame.shape[0] - 5),
                      (0, 0, 255), 6)
        cv2.putText(frame, "REVIEW MOMENT " + time_text, (20, 40),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 0, 255), 2)

        frame_filename = f"{base}_moment_{index + 1}.jpg"
        cv2.imwrite(os.path.join(UPLOAD_FOLDER, frame_filename), frame)
        frame_url = "/uploads/" + frame_filename

        frame_html += f"""
        <div style="display:flex;flex-direction:row;align-items:flex-start;gap:25px;width:100%;
                    box-sizing:border-box;margin:20px 0;padding:20px;border:3px solid #e53935;
                    border-radius:15px;background:#fff5f5;flex-wrap:wrap;">
            <div style="flex:1 1 260px;min-width:0;">
                <h4 style="color:#c62828;margin-top:0;font-size:20px;">🔴 {time_text}</h4>
                <img src="{frame_url}" alt="Video moment {time_text}"
                     style="display:block;width:100%;height:auto;max-height:400px;object-fit:contain;
                            border-radius:10px;border:1px solid #ddd;">
            </div>
            <div style="flex:1 1 260px;min-width:0;padding-top:5px;">
                <h4 style="color:#8a1c1c;margin-top:0;margin-bottom:15px;">🔎 Detected Information</h4>
                <p style="line-height:1.6;word-wrap:break-word;"><b>Detected words:</b><br>{escape(", ".join(item["words"]))}</p>
                <p style="line-height:1.6;word-wrap:break-word;max-height:180px;overflow:auto;"><b>Text at this moment:</b><br>{escape(item["text"])}</p>
                <p style="color:#8a4b00;background:#fff8e1;padding:12px;border-radius:8px;line-height:1.5;">
                    ⚠️ This does not by itself prove that the video is a scam. The words only
                    indicate that this moment may need attention.
                </p>
            </div>
        </div>
        """

    if suspicious_frames:
        return box(
            "red",
            "⚠️ MOMENTS THAT MAY NEED ATTENTION",
            "<p>ScamShield found words related to sensitive information at the following "
            "moments. The detected words alone do not prove that the video is a scam.</p>"
            f"{frame_html}"
            "<p style='margin-top:20px;'>⚠️ Review the actual words shown at each timestamp. "
            "Do not share OTPs, passwords, PINs, banking information or money simply because "
            "a video asks you to do so. Verify important requests independently.</p>"
            "<p style='font-size:12px;color:#666;'>Note: only on-screen text is checked, "
            "not spoken words.</p>",
        )

    return box(
        "blue",
        "🔵 NO OBVIOUS SUSPICIOUS MOMENTS DETECTED",
        "<p>ScamShield sampled the video and did not detect the basic suspicious words "
        "it currently checks on screen.</p>"
        '<p style="color:#35516f;">This does not guarantee that the entire video is safe. '
        "Spoken words are not checked. Continue to verify important requests before "
        "taking action.</p>",
    )


# -------------------------------------------------
# PROTECT MY PHOTO
# -------------------------------------------------

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
UPI_RE = re.compile(
    r"\b[a-zA-Z0-9.\-_]{2,}@(?:ok[a-z]+|ybl|ibl|axl|paytm|upi|apl|sbi|hdfcbank|icici|axisbank)\b"
)
PHONE_DIGITS_RE = re.compile(r"(?:\+?91)?[6-9]\d{9}")
FOUR_DIGITS_RE = re.compile(r"\d{4}")


@app.route("/protect-photo", methods=["POST"])
def protect_photo():
    photo = request.files.get("photo")
    if not photo or photo.filename == "":
        return box("orange", "❌ Please select a photo.")

    try:
        path, filename = save_upload(photo, UPLOAD_FOLDER, ALLOWED_IMAGE_EXT)
    except ValueError as error:
        return box("orange", escape(str(error)))

    image = cv2.imread(path)
    safe_remove(path)  # privacy: the original is not kept

    if image is None:
        return box("orange", "❌ Could not read the photo.")

    protected = image.copy()
    detected = []

    def note(label):
        if label not in detected:
            detected.append(label)

    # ---------- QR codes ----------
    try:
        for points, _text in find_qr(image):
            pts = points.astype("int32")
            x, y, w, h = cv2.boundingRect(pts)
            pad = max(15, int(min(w, h) * 0.08))
            obscure(protected, x - pad, y - pad, x + w + pad, y + h + pad)
            note("QR code")
    except Exception as error:
        print("QR ERROR:", error)

    # ---------- OCR ----------
    try:
        rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
        ocr = pytesseract.image_to_data(rgb, output_type=pytesseract.Output.DICT)

        tokens = []
        for i in range(len(ocr["text"])):
            text = ocr["text"][i].strip()
            if text:
                tokens.append({
                    "text": text,
                    "x": int(ocr["left"][i]), "y": int(ocr["top"][i]),
                    "w": int(ocr["width"][i]), "h": int(ocr["height"][i]),
                })

        flagged = set()

        for i, tok in enumerate(tokens):
            text = tok["text"]
            low = text.lower()
            digits = re.sub(r"\D", "", text)
            hit = False

            if EMAIL_RE.search(text):
                note("Email address"); hit = True

            if UPI_RE.search(text):
                note("UPI ID"); hit = True

            phone = PHONE_DIGITS_RE.fullmatch(re.sub(r"[^0-9+]", "", text))
            if phone:
                note("Phone number"); hit = True
            elif len(digits) == 12:
                note("Aadhaar-like number"); hit = True
            elif len(digits) == 16:
                note("Card number"); hit = True

            if has_word(low, ["otp", "pin", "cvv", "password", "passcode",
                              "verification code"]):
                for word in ["otp", "pin", "cvv", "password", "passcode",
                             "verification code"]:
                    if has_word(low, [word]):
                        note(word.upper())
                hit = True

            if has_word(low, ["account number", "bank account", "ifsc",
                              "credit card", "debit card"]):
                note("Bank/payment information"); hit = True

            if hit:
                flagged.add(i)

        # numbers split in groups of four (1234 5678 9012 / 1234 5678 9012 3456)
        i = 0
        while i < len(tokens):
            j = i
            while j < len(tokens) and FOUR_DIGITS_RE.fullmatch(tokens[j]["text"]):
                j += 1
            run = j - i
            if run == 3:
                note("Aadhaar-like number"); flagged.update(range(i, j))
            elif run == 4:
                note("Card number"); flagged.update(range(i, j))
            i = max(j, i + 1)

        for i in flagged:
            t = tokens[i]
            obscure(protected, t["x"] - 15, t["y"] - 15,
                    t["x"] + t["w"] + 15, t["y"] + t["h"] + 15)
    except Exception as error:
        print("OCR ERROR:", error)

    protected_filename = os.path.splitext(filename)[0] + "_protected.png"
    cv2.imwrite(os.path.join(UPLOAD_FOLDER, protected_filename), protected)
    protected_url = "/uploads/" + protected_filename

    if detected:
        kind = "green"
        text = "Photo protected successfully. Hidden: " + ", ".join(detected) + "."
    else:
        kind = "blue"
        text = ("A protected copy was created. No obvious sensitive information was "
                "detected by the current checks.")

    body = (
        f"<p>{escape(text)}</p>"
        f'<img src="{protected_url}" alt="Protected photo" style="width:100%;max-width:600px;'
        'border-radius:12px;display:block;margin:15px auto;">'
        "<p><b>Protected copy:</b> sensitive information detected by ScamShield has been "
        "hidden where possible. Check the image yourself before sharing it.</p>"
        f'<a href="{protected_url}" download="{protected_filename}" style="display:block;'
        "text-align:center;text-decoration:none;padding:14px 20px;border-radius:10px;"
        'background:#27ae60;color:white;font-weight:bold;margin-top:15px;">'
        "⬇️ Download Protected Photo</a>"
        '<p style="font-size:13px;color:#666;margin-top:12px;">⚠️ This does not guarantee '
        "that every sensitive item in the photo was detected. The copy is deleted from "
        "the server after about an hour.</p>"
    )
    return box(kind, "🛡️ Photo Protection Complete", body)


# -------------------------------------------------
# ALREADY CLICKED
# -------------------------------------------------

@app.route("/clicked-help", methods=["POST"])
def clicked_help():
    """Interactive recovery guidance based on the user's selected answers."""
    form = request.form
    selected = []
    if form.get("payment") == "yes":
        selected.append(("Payment made / money lost", [
            "Call India's cyber-fraud helpline 1930 immediately.",
            "Contact your bank or payment app using its official app/number and ask them to report/block the transaction or secure the account.",
            "Save transaction IDs, screenshots, phone numbers, messages, and timestamps. Report at cybercrime.gov.in.",
        ]))
    if form.get("otp") == "yes":
        selected.append(("OTP shared or entered", [
            "Contact the affected bank/service through its official channel immediately.",
            "Do not share any further OTPs. Review recent transactions and account activity.",
        ]))
    if form.get("password") == "yes":
        selected.append(("Password / PIN entered", [
            "From a trusted device, change the affected password using the official app/site; change it anywhere else you reused it.",
            "For banking or UPI credentials, contact the bank/payment provider through its official channel. Never tell anyone your UPI PIN.",
            "Sign out other sessions and enable multi-factor authentication where available.",
        ]))
    if form.get("downloaded") == "yes":
        selected.append(("File or app downloaded", [
            "Do not open an untrusted file. If an unknown app was installed, disconnect from the internet temporarily if you suspect active misuse.",
            "Uninstall the unknown app, run the phone's built-in security scan, and review recent downloads.",
            "If you cannot remove it or suspect remote access, use a trusted device to secure accounts and seek reputable technical help.",
        ]))
    if form.get("permissions") == "yes":
        selected.append(("App permissions granted", [
            "Review and revoke unnecessary SMS, accessibility, notification, contacts, camera, microphone, and file permissions.",
            "Remove the suspicious app if you do not trust it. Check for device-admin/accessibility access before uninstalling.",
            "Monitor account activity and contact your bank if banking or SMS access may have been exposed.",
        ]))
    if form.get("clicked") == "yes":
        selected.append(("Link opened", [
            "Close the page and do not enter information, approve prompts, or download anything else.",
            "Opening a link alone does not always mean your device or account is compromised. Take additional steps based on what you entered or installed.",
        ]))
    if form.get("number") == "yes":
        selected.append(("Called or messaged the number", [
            "Stop the conversation and do not follow instructions to install apps, share screen, disclose OTPs, or transfer money.",
            "Verify the organisation using a number from its official website/app, not the number in the suspicious message.",
        ]))

    if not selected:
        selected.append(("First steps", [
            "Stop interacting with the suspicious content and do not share personal or financial information.",
            "If money was lost or an unauthorised transaction occurred, call 1930 immediately and contact your bank.",
            "Save evidence and verify the sender using an official source.",
        ]))

    sections = []
    for title, steps in selected:
        sections.append(
            f"<section style='margin:12px 0;padding:14px;background:#fff;border:1px solid #ead7d7;border-radius:10px'>"
            f"<h4>{escape(title)}</h4><ol>" + "".join(f"<li style='margin:7px 0'>{escape(step)}</li>" for step in steps) + "</ol></section>"
        )
    return box("orange", "🛡️ RECOVERY PLAN — WHAT TO DO NEXT",
               "<p>These steps are guidance based on your answers; ScamShield cannot inspect or repair your device automatically.</p>"
               + "".join(sections)
               + "<p><b>India:</b> If financial cyber fraud occurred, report promptly at <code>1930</code> and <code>cybercrime.gov.in</code>.</p>")


# -------------------------------------------------
# CUSTOMER CARE NUMBER, COMPLAINT SUMMARY, FEEDBACK
# -------------------------------------------------

@app.route("/check-number", methods=["POST"])
def check_number_route():
    name = (request.form.get("name") or "").strip()
    number = (request.form.get("number") or "").strip()
    if not number:
        return box("orange", "☎️ Enter a customer-care number",
                   "<p>Enter the number you want to check. Do not share OTPs or account passwords.</p>")
    digits = re.sub(r"\D", "", number)
    if len(digits) < 7 or len(digits) > 15:
        return box("orange", "⚠️ Check the number format",
                   "<p>The number does not look like a typical phone number. Check the digits and country code, then try again.</p>")

    message = check_customer_care(name, number)
    prefix = message.split(":", 1)[0].strip().upper()
    kind = {"RED": "red", "AMBER": "orange", "GREEN": "green", "BLUE": "blue"}.get(prefix, "blue")
    body = (
        f"<p><b>Organisation entered:</b> {escape(name or 'Not provided')}</p>"
        f"<p><b>Number entered:</b> {escape(number)}</p>"
        f"<p style='white-space:pre-wrap'>{escape(message)}</p>"
        "<hr><h4>How to use this result</h4><ul>"
        "<li>Do not treat a number as official just because it appears in search results or a message.</li>"
        "<li>Compare it with contact details inside the organisation's official app or website that you open yourself.</li>"
        "<li>Never share OTPs, UPI PINs, passwords, or screen-sharing access with customer care.</li>"
        "</ul><p style='font-size:12px;color:#666'>ScamShield can only report the checks available to its current number-checking helper. Unless the result cites a reliable official source, it should not be treated as a verified identity or definitive scam verdict.</p>"
    )
    return box(kind, "☎️ CUSTOMER-CARE NUMBER CHECK", body)


@app.route("/report-summary", methods=["POST"])
def report_summary_route():
    text = build_complaint_summary(request.form)
    return Response(
        text,
        mimetype="text/plain; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=scam_complaint_summary.txt"},
    )


@app.route("/feedback", methods=["POST"])
def feedback():
    answer = "yes" if request.form.get("helpful") == "yes" else "no"
    with open(FEEDBACK_FILE, "a", newline="", encoding="utf-8") as handle:
        csv.writer(handle).writerow([datetime.now().isoformat(timespec="seconds"), answer])
    return "Thank you for your feedback."


# -------------------------------------------------
# RUN APPLICATION
# -------------------------------------------------

if __name__ == "__main__":
    app.run(
        debug=os.environ.get("FLASK_DEBUG") == "1",
        host="127.0.0.1",
        port=5000,
    )