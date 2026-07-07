import requests
from datetime import datetime
import config

def check_virustotal(url):
    """Returns dict with virustotal_positives count. Skips if no API key set."""
    if not config.VIRUSTOTAL_API_KEY or config.VIRUSTOTAL_API_KEY == "your_key_here":
        return {"virustotal_positives": 0}
    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
    try:
        resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers, data={"url": url}, timeout=10
        )
        analysis_id = resp.json()["data"]["id"]
        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers, timeout=10
        ).json()
        stats = result["data"]["attributes"]["stats"]
        return {"virustotal_positives": stats.get("malicious", 0)}
    except Exception:
        return {"virustotal_positives": 0}

def check_phishtank(url):
    """Returns dict with phishtank bool. Skips if no API key set."""
    if not config.PHISHTANK_API_KEY or config.PHISHTANK_API_KEY == "your_key_here":
        return {"phishtank": False}
    try:
        resp = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": url, "format": "json", "app_key": config.PHISHTANK_API_KEY},
            timeout=10
        )
        data = resp.json()
        in_db = data["results"]["in_database"]
        valid = data["results"].get("valid", False)
        return {"phishtank": bool(in_db and valid)}
    except Exception:
        return {"phishtank": False}

def check_domain_age(domain):
    """Returns dict with domain_age_days. Requires python-whois installed."""
    try:
        import whois
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age = (datetime.now() - creation).days
            return {"domain_age_days": age}
    except Exception:
        pass
    return {"domain_age_days": None}

def get_all_api_results(url, domain):
    """Combine all API checks into one dict for score_url()/score_email()."""
    results = {}
    results.update(check_virustotal(url))
    results.update(check_phishtank(url))
    results.update(check_domain_age(domain))
    return results
