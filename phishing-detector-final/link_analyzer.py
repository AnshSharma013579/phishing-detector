import re
import urllib.parse
import unicodedata
import requests

KNOWN_BRANDS = [
    "amazon", "google", "paypal", "apple", "microsoft", "facebook",
    "instagram", "netflix", "ebay", "twitter", "linkedin", "dropbox",
    "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc",
    "barclays", "natwest", "santander", "irs", "dhl", "fedex", "ups"
]

LEGITIMATE_DOMAINS = {
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.in", "amazon.de"],
    "google": ["google.com", "google.co.uk", "gmail.com", "googleapis.com"],
    "paypal": ["paypal.com", "paypalobjects.com"],
    "apple": ["apple.com", "icloud.com", "itunes.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com", "office.com"],
    "facebook": ["facebook.com", "fb.com", "instagram.com"],
    "netflix": ["netflix.com"],
    "ebay": ["ebay.com", "ebay.co.uk"],
}

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.link", "buff.ly", "rb.gy", "is.gd", "cutt.ly",
    "shorte.st", "adf.ly", "bc.vc", "clk.sh"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".pw", ".top",
    ".club", ".info", ".biz", ".work", ".click", ".link"
]

def extract_domain(url):
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.netloc.lower()
        hostname = hostname.split(':')[0]
        if hostname.startswith('www.'):
            hostname = hostname[4:]
        return hostname
    except Exception:
        return ""

def get_tld(domain):
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.' + parts[-1]
    return ""

def levenshtein(s1, s2):
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[len(s2)]

def check_raw_ip(url):
    domain = extract_domain(url)
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    return bool(re.match(ip_pattern, domain))

def check_url_shortener(url):
    """Exact domain match only — substring matching causes false positives
    (e.g. 't.co' is a substring of 'support.com')."""
    domain = extract_domain(url)
    return domain in URL_SHORTENERS

def check_suspicious_tld(url):
    domain = extract_domain(url)
    tld = get_tld(domain)
    return tld in SUSPICIOUS_TLDS, tld

def check_lookalike_domain(url):
    domain = extract_domain(url)
    domain_without_tld = '.'.join(domain.split('.')[:-1]) if '.' in domain else domain
    for brand in KNOWN_BRANDS:
        if domain in LEGITIMATE_DOMAINS.get(brand, []):
            continue
        distance = levenshtein(domain_without_tld.lower(), brand.lower())
        if 0 < distance <= 2:
            return True, brand, domain
    return False, None, None

LEET_MAP = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a'}

def normalize_leet(s):
    """Convert common leetspeak substitutions back to letters, e.g. amaz0n -> amazon."""
    return ''.join(LEET_MAP.get(c, c) for c in s)

def check_brand_in_fake_domain(url):
    """
    Detect brand impersonation, including leetspeak substitutions:
    - amazon.verify-now.xyz   (brand before real domain)
    - login-paypal.com       (brand in subdomain/prefix)
    - amaz0n-secure-login.xyz (brand hidden via character substitution)
    """
    domain = extract_domain(url)
    parsed = urllib.parse.urlparse(url)
    full = (parsed.netloc + parsed.path).lower()
    full_normalized = normalize_leet(full)

    for brand in KNOWN_BRANDS:
        legit = LEGITIMATE_DOMAINS.get(brand, [])
        if any(l in domain for l in legit):
            continue
        if brand in full:
            return True, brand
        if brand in full_normalized and brand not in full:
            return True, brand  # caught via leetspeak normalization
    return False, None

def check_homograph_attack(url):
    domain = extract_domain(url)
    for char in domain:
        if ord(char) > 127:
            name = unicodedata.name(char, '')
            if 'LATIN' not in name and char not in ['.', '-']:
                return True, char
    return False, None

def check_excessive_subdomains(url):
    domain = extract_domain(url)
    parts = domain.split('.')
    return len(parts) > 4, len(parts)

def check_long_url(url):
    return len(url) > 100

def check_special_chars(url):
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc
    suspicious = ['@', '!', '#']
    found = [c for c in suspicious if c in domain]
    return bool(found), found

def check_redirect_chain(url, max_hops=5):
    try:
        session = requests.Session()
        session.max_redirects = max_hops
        resp = session.head(url, allow_redirects=True, timeout=5,
                            headers={'User-Agent': 'Mozilla/5.0'})
        return resp.url, len(resp.history)
    except requests.TooManyRedirects:
        return url, max_hops
    except Exception:
        return url, 0

def score_url(url, api_results=None, follow_redirects=True):
    score = 0
    triggered_rules = []
    original_url = url
    final_url = url
    redirect_hops = 0

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    domain = extract_domain(url)

    if follow_redirects:
        try:
            final_url, redirect_hops = check_redirect_chain(url)
            if final_url != url:
                domain = extract_domain(final_url)
        except Exception:
            pass

    if api_results and api_results.get('phishtank'):
        pts = 10
        score += pts
        triggered_rules.append({
            "rule": "Confirmed Phishing URL (PhishTank)",
            "detail": "This URL is in PhishTank's confirmed phishing database",
            "points": pts, "severity": "critical"
        })

    if api_results and api_results.get('virustotal_positives', 0) >= 3:
        pts = 8
        score += pts
        positives = api_results['virustotal_positives']
        triggered_rules.append({
            "rule": "VirusTotal Threat Detection",
            "detail": f"Flagged by {positives} security engines on VirusTotal",
            "points": pts, "severity": "critical"
        })

    if api_results:
        age_days = api_results.get('domain_age_days', None)
        if age_days is not None:
            if age_days < 7:
                pts = 6
                score += pts
                triggered_rules.append({
                    "rule": "Very New Domain (< 7 days old)",
                    "detail": f"Domain registered only {age_days} day(s) ago",
                    "points": pts, "severity": "critical"
                })
            elif age_days < 30:
                pts = 3
                score += pts
                triggered_rules.append({
                    "rule": "New Domain (< 30 days old)",
                    "detail": f"Domain registered {age_days} days ago — 94% of phishing domains are under 30 days old",
                    "points": pts, "severity": "high"
                })

    if check_raw_ip(url):
        pts = 4
        score += pts
        triggered_rules.append({
            "rule": "Raw IP Address Used",
            "detail": "URL uses IP address directly instead of a domain name",
            "points": pts, "severity": "high"
        })

    is_homograph, bad_char = check_homograph_attack(url)
    if is_homograph:
        pts = 5
        score += pts
        triggered_rules.append({
            "rule": "Unicode Homograph Attack",
            "detail": f"Non-Latin character detected in domain (character: '{bad_char}') — looks identical in browser",
            "points": pts, "severity": "critical"
        })

    is_lookalike, brand, found_domain = check_lookalike_domain(url)
    if is_lookalike:
        pts = 5
        score += pts
        triggered_rules.append({
            "rule": "Typosquatting / Lookalike Domain",
            "detail": f"Domain '{found_domain}' is very similar to '{brand}' — possible impersonation",
            "points": pts, "severity": "high"
        })

    is_impersonating, impersonated_brand = check_brand_in_fake_domain(url)
    if is_impersonating and not is_lookalike:
        pts = 4
        score += pts
        triggered_rules.append({
            "rule": "Brand Name in Suspicious Domain",
            "detail": f"'{impersonated_brand}' brand name found in non-official domain",
            "points": pts, "severity": "high"
        })

    if redirect_hops >= 3:
        pts = 3
        score += pts
        triggered_rules.append({
            "rule": "Suspicious Redirect Chain",
            "detail": f"URL redirects {redirect_hops} times before reaching destination — common phishing evasion",
            "points": pts, "severity": "medium"
        })

    if check_url_shortener(url):
        pts = 2
        score += pts
        triggered_rules.append({
            "rule": "URL Shortener Detected",
            "detail": "URL uses a shortener service that hides the real destination",
            "points": pts, "severity": "low"
        })

    has_bad_tld, tld = check_suspicious_tld(url)
    if has_bad_tld:
        pts = 2
        score += pts
        triggered_rules.append({
            "rule": "Suspicious Top-Level Domain",
            "detail": f"TLD '{tld}' is commonly used in phishing and spam",
            "points": pts, "severity": "low"
        })

    has_excess, subdomain_count = check_excessive_subdomains(url)
    if has_excess:
        pts = 2
        score += pts
        triggered_rules.append({
            "rule": "Excessive Subdomains",
            "detail": f"Domain has {subdomain_count} levels — e.g. a.b.c.evil.com",
            "points": pts, "severity": "low"
        })

    if check_long_url(url):
        pts = 1
        score += pts
        triggered_rules.append({
            "rule": "Unusually Long URL",
            "detail": f"URL is {len(url)} characters — often used to confuse users",
            "points": pts, "severity": "low"
        })

    has_special, special_found = check_special_chars(url)
    if has_special:
        pts = 2
        score += pts
        triggered_rules.append({
            "rule": "Suspicious Special Characters in URL",
            "detail": f"Special characters found in domain: {', '.join(special_found)}",
            "points": pts, "severity": "medium"
        })

    max_score = 54
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
        "mode": "link",
        "original_url": original_url,
        "final_url": final_url,
        "domain": domain,
        "redirect_hops": redirect_hops,
        "score": score,
        "max_score": max_score,
        "confidence": confidence,
        "classification": classification,
        "color": color,
        "emoji": emoji,
        "triggered_rules": triggered_rules,
        "total_rules_checked": 13
    }
