import re
from email import policy
from email.parser import Parser

# ─── KEYWORD LISTS ────────────────────────────────────────────

URGENCY_KEYWORDS = [
    "verify your account", "verify account", "account suspended",
    "click here immediately", "click now", "act now", "urgent action",
    "your account will be", "confirm your password", "confirm password",
    "update your information", "unusual activity", "suspicious activity",
    "limited time", "expires soon", "final notice", "last warning",
    "you have won", "congratulations you", "claim your prize",
    "security alert", "unauthorized access", "login attempt",
    "reset your password", "verify your identity", "identity verification",
    "bank account", "credit card details", "enter your details",
    "click the link below", "failure to respond", "respond immediately",
    "account will be closed", "account will be terminated",
    "validate your", "reactivate your", "unlock your account"
]

SENSITIVE_REQUEST_KEYWORDS = [
    "ssn", "social security", "password", "credit card", "cvv",
    "bank account number", "routing number", "pin number",
    "date of birth", "mother's maiden", "security question"
]

FREE_EMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "mail.com", "protonmail.com", "icloud.com",
    "live.com", "msn.com", "ymail.com", "rocketmail.com"
]

FINANCIAL_KEYWORDS = [
    "bank", "paypal", "amazon", "apple", "microsoft", "google",
    "netflix", "ebay", "instagram", "facebook", "irs", "tax",
    "social security", "medicare", "government"
]

BULK_MAILERS = [
    "sendgrid", "mailchimp", "constantcontact", "bulk-mailer",
    "mass-mail", "phpmailer", "smtp2go"
]

# ─── URL EXTRACTOR ─────────────────────────────────────────────

def extract_urls(text):
    pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
    return re.findall(pattern, text, re.IGNORECASE)

# ─── INDIVIDUAL RULE CHECKS ────────────────────────────────────

def check_urgency_keywords(text):
    text_lower = text.lower()
    return [kw for kw in URGENCY_KEYWORDS if kw in text_lower]

def check_sensitive_requests(text):
    text_lower = text.lower()
    return [kw for kw in SENSITIVE_REQUEST_KEYWORDS if kw in text_lower]

def check_sender_domain(from_address, body_text=""):
    findings = []
    if not from_address:
        return findings
    from_lower = from_address.lower()
    domain_match = re.search(r'@([\w.-]+)', from_lower)
    if not domain_match:
        return findings
    domain = domain_match.group(1)

    if any(free in domain for free in FREE_EMAIL_DOMAINS):
        body_lower = body_text.lower()
        if any(fin in body_lower for fin in FINANCIAL_KEYWORDS):
            findings.append(f"Free email domain '{domain}' used for financial/brand communication")

    suspicious_patterns = [
        r'\d+[a-z]|[a-z]\d+',
        r'-secure', r'-login', r'-verify', r'-support', r'-update',
        r'account-', r'confirm-', r'secure-'
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, domain):
            findings.append(f"Suspicious domain pattern in sender: '{domain}'")
            break
    return findings

def check_header_spoofing(msg):
    findings = []
    if not msg:
        return findings
    from_addr = str(msg.get('From', ''))
    reply_to = str(msg.get('Reply-To', ''))
    x_mailer = str(msg.get('X-Mailer', ''))

    from_email_match = re.search(r'<(.+?)>', from_addr)
    from_email = from_email_match.group(1) if from_email_match else from_addr
    reply_email_match = re.search(r'<(.+?)>', reply_to)
    reply_email = reply_email_match.group(1) if reply_email_match else reply_to

    if reply_to and reply_email.strip() != from_email.strip():
        from_domain = from_email.split('@')[-1] if '@' in from_email else ''
        reply_domain = reply_email.split('@')[-1] if '@' in reply_email else ''
        if from_domain and reply_domain and from_domain != reply_domain:
            findings.append(f"Reply-To ({reply_email}) differs from From ({from_email})")

    if x_mailer:
        for mailer in BULK_MAILERS:
            if mailer.lower() in x_mailer.lower():
                findings.append(f"Bulk mailing tool detected in X-Mailer: {x_mailer}")
                break
    return findings

def check_html_only(msg):
    if not msg:
        return False
    has_plain = False
    has_html = False
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == 'text/plain':
                has_plain = True
            if ct == 'text/html':
                has_html = True
    else:
        ct = msg.get_content_type()
        if ct == 'text/html':
            has_html = True
        elif ct == 'text/plain':
            has_plain = True
    return has_html and not has_plain

def check_suspicious_attachments(msg):
    dangerous_extensions = ['.exe', '.zip', '.js', '.vbs', '.bat', '.cmd', '.scr', '.pif']
    findings = []
    if not msg or not msg.is_multipart():
        return findings
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            ext = '.' + filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
            if ext in dangerous_extensions:
                findings.append(f"Dangerous attachment: {filename}")
    return findings

# ─── SCORING ENGINE ────────────────────────────────────────────

def score_email(text, filename=None, api_results=None):
    score = 0
    triggered_rules = []
    all_urls = extract_urls(text)

    msg = None
    try:
        msg = Parser(policy=policy.default).parsestr(text)
    except Exception:
        pass

    from_address = ""
    body_text = text
    if msg:
        from_address = str(msg.get('From', ''))
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    try:
                        body_text = part.get_content()
                    except Exception:
                        body_text = text
                    break
        else:
            try:
                body_text = msg.get_content()
            except Exception:
                body_text = text

    urgency = check_urgency_keywords(body_text)
    if urgency:
        pts = min(3, len(urgency))
        score += pts
        triggered_rules.append({
            "rule": "Urgency / Phishing Keywords",
            "detail": f"Found: {', '.join(urgency[:3])}{'...' if len(urgency) > 3 else ''}",
            "points": pts, "severity": "high"
        })

    sensitive = check_sensitive_requests(body_text)
    if sensitive:
        pts = 3
        score += pts
        triggered_rules.append({
            "rule": "Requests Sensitive Information",
            "detail": f"Asks for: {', '.join(sensitive[:3])}",
            "points": pts, "severity": "high"
        })

    sender_issues = check_sender_domain(from_address, body_text)
    if sender_issues:
        pts = 3
        score += pts
        triggered_rules.append({
            "rule": "Suspicious Sender Domain",
            "detail": sender_issues[0],
            "points": pts, "severity": "medium"
        })

    if msg:
        spoof_issues = check_header_spoofing(msg)
        if spoof_issues:
            pts = 3
            score += pts
            triggered_rules.append({
                "rule": "Email Header Spoofing",
                "detail": spoof_issues[0],
                "points": pts, "severity": "high"
            })

    if msg and check_html_only(msg):
        pts = 2
        score += pts
        triggered_rules.append({
            "rule": "HTML-Only Email (No Plain Text)",
            "detail": "Email has no plain text version — common phishing technique",
            "points": pts, "severity": "low"
        })

    if msg:
        attach_issues = check_suspicious_attachments(msg)
        if attach_issues:
            pts = 3
            score += pts
            triggered_rules.append({
                "rule": "Dangerous Attachment",
                "detail": attach_issues[0],
                "points": pts, "severity": "high"
            })

    if api_results and api_results.get('phishtank_hits'):
        pts = 5
        score += pts
        triggered_rules.append({
            "rule": "URL Found in PhishTank Database",
            "detail": f"Confirmed phishing URL: {api_results['phishtank_hits'][0]}",
            "points": pts, "severity": "critical"
        })

    if api_results and api_results.get('virustotal_hits'):
        hit = api_results['virustotal_hits'][0]
        pts = 4
        score += pts
        triggered_rules.append({
            "rule": "URL Flagged by VirusTotal",
            "detail": f"{hit['url']} flagged by {hit['positives']} engines",
            "points": pts, "severity": "critical"
        })

    max_score = 26
    if score >= 7:
        classification, color, emoji = "Phishing", "danger", "🚨"
        confidence = round(min(50 + (score / max_score) * 50, 99))
    elif score >= 4:
        classification, color, emoji = "Suspicious", "warning", "⚠️"
        confidence = round(30 + (score / max_score) * 40)
    else:
        classification, color, emoji = "Safe", "success", "✅"
        confidence = round(max(85 - (score / max_score) * 85, 40))

    return {
        "mode": "email",
        "score": score,
        "max_score": max_score,
        "confidence": confidence,
        "classification": classification,
        "color": color,
        "emoji": emoji,
        "triggered_rules": triggered_rules,
        "urls_found": all_urls,
        "total_rules_checked": 8
    }
