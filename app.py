import re
import ssl
import socket
import ipaddress
import threading
import webbrowser
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import requests
import urllib3
import tldextract
from bs4 import BeautifulSoup

import customtkinter as ctk
from tkinter import StringVar
import tkinter as tk

try:
    import whois
    HAS_WHOIS = True
except Exception:
    HAS_WHOIS = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── THEME ──────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

C_BG        = "#0a0f1e"
C_BG2       = "#0d1526"
C_PANEL     = "#111827"
C_PANEL2    = "#162035"
C_BORDER    = "#1e3a5f"
C_CYAN      = "#00d4ff"
C_CYAN_DIM  = "#007fa0"
C_GREEN     = "#00e676"
C_YELLOW    = "#ffd600"
C_RED       = "#ff1744"
C_TEXT      = "#cdd6f4"
C_TEXT_DIM  = "#4a6080"
C_WHITE     = "#e8f0ff"

FONT_TITLE  = ("Courier New", 26, "bold")
FONT_HEAD   = ("Courier New", 13, "bold")
FONT_MONO   = ("Courier New", 11)
FONT_MONO_S = ("Courier New", 10)
FONT_MONO_B = ("Courier New", 11, "bold")
FONT_BIG    = ("Courier New", 36, "bold")
FONT_MED    = ("Courier New", 20, "bold")

# ── ANALYSIS LOGIC ─────────────────────────────────────────────────────────
extractor = tldextract.TLDExtract(suffix_list_urls=None)

SHORTENERS = {
    "bit.ly","tinyurl.com","goo.gl","t.co","ow.ly","is.gd","buff.ly",
    "adf.ly","cutt.ly","rebrand.ly","shorturl.at","tiny.cc","rb.gy",
    "soo.gd","s2r.co","lnkd.in","bl.ink","tiny.one"
}
SUSPICIOUS_TLDS = {
    "zip","mov","gq","tk","ml","cf","ga","work","support","country","stream"
}
URL_KEYWORDS = {
    "login","verify","update","secure","account","signin","confirm",
    "password","wallet","payment","bonus","free","gift","reset",
    "support","billing","unlock","security","bank","ebayisapi","webscr"
}
TEXT_PATTERNS = [
    "verify your account","confirm your password","unusual activity",
    "urgent action required","click here immediately",
    "your account will be suspended","update your payment",
    "login to continue","confirm your identity","wallet connect",
    "seed phrase","claim reward","free gift","bank verification",
    "security alert","recover your account"
]
JS_PATTERNS = [
    "eval(","atob(","fromcharcode","unescape(","document.write(",
    "window.location","location.href","settimeout(","setinterval(",
    "innerhtml","escape(","decodeuricomponent("
]
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
}
SAFE_THRESHOLD = 25
WARN_THRESHOLD = 55


def normalize_url(url):
    url = url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    return url

def is_valid_url(url):
    try:
        p = urlparse(url)
        return bool(p.scheme and p.netloc)
    except Exception:
        return False

def host_from_url(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""

def get_ext(value):
    return extractor(value)

def registrable_domain(value):
    host = value
    if "://" in value:
        host = host_from_url(value)
    ext = get_ext(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return host.lower()

def same_registered_domain(a, b):
    return registrable_domain(a) == registrable_domain(b)

def add_finding(findings, status, name, detail, points):
    findings.append({"status": status, "name": name, "detail": detail, "points": points})

def dns_resolves(hostname):
    try:
        socket.gethostbyname(hostname)
        return True
    except Exception:
        return False

def check_ssl_certificate(hostname):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                if not not_after:
                    return "warning", "SSL cert found but expiry unreadable.", 5
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                if days_left < 0:
                    return "danger", "SSL certificate is expired.", 20
                if days_left < 15:
                    return "warning", f"SSL expires soon ({days_left} days).", 8
                return "safe", f"SSL valid ({days_left} days remaining).", 0
    except ssl.SSLError:
        return "danger", "SSL certificate validation failed.", 20
    except Exception:
        return "warning", "Could not verify SSL certificate.", 6

def check_domain_age(hostname):
    if not HAS_WHOIS:
        return None
    try:
        data = whois.whois(hostname)
        creation = data.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if not creation:
            return None
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - creation).days
        if age_days < 30:
            return "danger", f"Domain very new ({age_days} days old).", 20
        if age_days < 180:
            return "warning", f"Domain relatively new ({age_days} days old).", 10
        return "safe", f"Domain age okay ({age_days} days old).", 0
    except Exception:
        return None

def fetch_site(url):
    pre = []
    try:
        r = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True)
        return r, pre, None
    except requests.exceptions.SSLError:
        add_finding(pre, "danger", "HTTPS / SSL", "SSL validation failed on connect.", 20)
        try:
            r = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True, verify=False)
            return r, pre, None
        except Exception as e:
            return None, pre, str(e)
    except Exception as e:
        return None, pre, str(e)

def analyze_static(url, findings):
    hostname = host_from_url(url)

    try:
        ipaddress.ip_address(hostname)
        add_finding(findings, "danger", "IP Address in URL", "Direct IP used instead of domain.", 25)
    except Exception:
        add_finding(findings, "safe", "IP Address in URL", "No direct IP address used.", 0)

    add_finding(findings, "warning" if len(url) > 75 else "safe",
                "Long URL", f"URL length: {len(url)} characters.", 8 if len(url) > 75 else 0)

    add_finding(findings, "danger" if "@" in url else "safe",
                "@ Symbol", "The '@' can hide the real target." if "@" in url else "No '@' symbol found.", 15 if "@" in url else 0)

    add_finding(findings, "warning" if "-" in hostname else "safe",
                "Dash in Domain", "Hyphen found in hostname." if "-" in hostname else "No suspicious dash.", 6 if "-" in hostname else 0)

    https = url.lower().startswith("https://")
    add_finding(findings, "safe" if https else "danger",
                "HTTPS", "Using HTTPS." if https else "Not using HTTPS.", 0 if https else 20)

    sub_count = len([x for x in get_ext(hostname).subdomain.split(".") if x]) if get_ext(hostname).subdomain else 0
    add_finding(findings, "warning" if sub_count >= 3 else "safe",
                "Subdomains", f"Subdomain count: {sub_count}.", 12 if sub_count >= 3 else 0)

    kw = sorted([k for k in URL_KEYWORDS if k in url.lower()])
    add_finding(findings, "warning" if kw else "safe",
                "Suspicious URL Words", "Found: " + ", ".join(kw) if kw else "No phishing words found.", 10 if kw else 0)

    add_finding(findings, "warning" if hostname in SHORTENERS else "safe",
                "Shortened URL", f"Shortener: {hostname}" if hostname in SHORTENERS else "No shortener detected.", 15 if hostname in SHORTENERS else 0)

    add_finding(findings, "danger" if "xn--" in hostname else "safe",
                "Punycode Domain", "Possible homograph attack." if "xn--" in hostname else "No punycode detected.", 18 if "xn--" in hostname else 0)

    trick = "//" in url.replace("://", "", 1)
    add_finding(findings, "warning" if trick else "safe",
                "Redirect Trick", "Extra '//' found." if trick else "No redirect trick.", 10 if trick else 0)

    try:
        port = urlparse(url).port
        ab = port not in (None, 80, 443)
    except Exception:
        ab, port = False, None
    add_finding(findings, "warning" if ab else "safe",
                "Abnormal Port", f"Non-standard port: {port}" if ab else "No abnormal port.", 10 if ab else 0)

    ext_obj = get_ext(hostname)
    tld = ext_obj.suffix.lower()
    bad_tld = tld in SUSPICIOUS_TLDS
    add_finding(findings, "warning" if bad_tld else "safe",
                "Suspicious TLD", f"TLD '.{tld}' commonly abused." if bad_tld else f"TLD '.{tld}' looks normal.", 12 if bad_tld else 0)

    digits = sum(c.isdigit() for c in url)
    add_finding(findings, "warning" if digits >= 8 else "safe",
                "Too Many Digits", "High digit count." if digits >= 8 else "Digit count normal.", 6 if digits >= 8 else 0)

    encoded = bool(re.search(r"%[0-9a-fA-F]{2}", url))
    add_finding(findings, "warning" if encoded else "safe",
                "Encoded Characters", "Encoded chars (%xx) found." if encoded else "No encoded characters.", 6 if encoded else 0)

    if dns_resolves(hostname):
        add_finding(findings, "safe", "DNS Resolution", "Domain resolves successfully.", 0)
    else:
        add_finding(findings, "danger", "DNS Resolution", "Domain could not be resolved.", 15)

    if https and hostname:
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except Exception:
            is_ip = False

    if not is_ip:
        s, d, p = check_ssl_certificate(hostname)
        add_finding(findings, s, "SSL Certificate", d, p)

    age = check_domain_age(hostname)
    if age:
        add_finding(findings, age[0], "Domain Age", age[1], age[2])

def analyze_html(response, original_url, findings):
    final_url = response.url
    redirects = len(response.history)

    add_finding(findings, "danger" if redirects >= 5 else ("warning" if redirects >= 2 else "safe"),
                "Redirect Count", f"Redirect count: {redirects}.",
                18 if redirects >= 5 else (8 if redirects >= 2 else 0))

    if not same_registered_domain(original_url, final_url):
        add_finding(findings, "danger", "Domain Changed",
                    f"{registrable_domain(original_url)} → {registrable_domain(final_url)}", 18)
    else:
        add_finding(findings, "safe", "Domain Changed", "Final destination on same domain.", 0)

    add_finding(findings, "warning" if response.status_code >= 400 else "safe",
                "HTTP Status", f"Status code: {response.status_code}.",
                5 if response.status_code >= 400 else 0)

    ct = response.headers.get("content-type", "").lower()
    if "text/html" not in ct:
        add_finding(findings, "warning", "Content Type", f"Unexpected type: {ct or 'unknown'}", 4)
        return

    try:
        soup = BeautifulSoup(response.text, "html.parser")
    except Exception:
        add_finding(findings, "warning", "HTML Parsing", "Could not parse HTML.", 5)
        return

    title = (soup.title.string.strip().lower() if soup.title and soup.title.string else "")
    visible_text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True).lower())
    forms = soup.find_all("form")
    pw_inputs = [i for i in soup.find_all("input") if (i.get("type") or "").strip().lower() == "password"]

    add_finding(findings, "warning" if pw_inputs else "safe",
                "Password Field", f"{len(pw_inputs)} password field(s)." if pw_inputs else "No password field.", 8 if pw_inputs else 0)

    ext_actions = 0
    js_actions = 0
    for form in forms:
        action = (form.get("action") or "").strip()
        if not action or action.lower().startswith("javascript:"):
            js_actions += 1
        else:
            if not same_registered_domain(final_url, urljoin(final_url, action)):
                ext_actions += 1

    add_finding(findings, "danger" if ext_actions else "safe",
                "External Form Action", f"{ext_actions} form(s) submit externally." if ext_actions else "No external form actions.", 20 if ext_actions else 0)
    add_finding(findings, "warning" if js_actions else "safe",
                "Empty/JS Form Action", f"{js_actions} form(s) with empty/JS action." if js_actions else "Form actions look normal.", 8 if js_actions else 0)

    iframes = soup.find_all("iframe")
    hidden = sum(1 for i in iframes if "display:none" in ((i.get("style") or "")).replace(" ","").lower()
                 or str(i.get("width","")) in {"0","1"} or str(i.get("height","")) in {"0","1"})
    add_finding(findings, "danger" if hidden else ("warning" if iframes else "safe"),
                "Iframes", f"{hidden} hidden iframe(s)." if hidden else (f"{len(iframes)} iframe(s)." if iframes else "No iframes."),
                15 if hidden else (5 if iframes else 0))

    meta_refresh = any((m.get("http-equiv") or "").strip().lower() == "refresh" for m in soup.find_all("meta"))
    add_finding(findings, "warning" if meta_refresh else "safe",
                "Meta Refresh", "Page uses meta refresh." if meta_refresh else "No meta refresh.", 10 if meta_refresh else 0)

    js_blob = "\n".join((s.string or s.text or "").lower() for s in soup.find_all("script"))
    js_hits = sum(js_blob.count(p) for p in JS_PATTERNS)
    add_finding(findings, "danger" if js_hits >= 6 else ("warning" if js_hits >= 2 else "safe"),
                "Obfuscated JavaScript", f"Suspicious JS patterns: {js_hits} hits.",
                15 if js_hits >= 6 else (8 if js_hits >= 2 else 0))

    matched = [p for p in TEXT_PATTERNS if p in visible_text or p in title]
    add_finding(findings, "danger" if len(matched) >= 3 else ("warning" if matched else "safe"),
                "Phishing Words", "Found: " + ", ".join(matched[:5]) if matched else "No phishing words found.",
                15 if len(matched) >= 3 else (8 if matched else 0))

    all_scripts = soup.find_all("script", src=True)
    ext_s = sum(1 for s in all_scripts if not same_registered_domain(final_url, urljoin(final_url, s.get("src",""))))
    add_finding(findings, "warning" if ext_s >= 8 else "safe",
                "External Scripts", f"{ext_s}/{len(all_scripts)} external scripts.", 8 if ext_s >= 8 else 0)

    if pw_inputs and matched:
        add_finding(findings, "danger", "Credential Harvesting", "Password field + phishing words detected.", 18)

def calculate_score(findings):
    return min(sum(f["points"] for f in findings), 100)

def risk_label(score):
    if score < SAFE_THRESHOLD:
        return "SAFE", C_GREEN
    if score < WARN_THRESHOLD:
        return "SUSPICIOUS", C_YELLOW
    return "HIGH RISK", C_RED

def run_analysis(url):
    findings = []
    analyze_static(url, findings)
    response, pre, error = fetch_site(url)
    findings.extend(pre)
    if response is None:
        add_finding(findings, "danger", "Website Fetch", f"Could not fetch: {error}", 15)
    else:
        analyze_html(response, url, findings)
        url = response.url
    score = calculate_score(findings)
    label, color = risk_label(score)
    hostname = host_from_url(url)
    domain = registrable_domain(url)
    return {
        "url": url, "host": hostname, "domain": domain,
        "score": score, "label": label, "color": color,
        "findings": findings,
        "danger": sum(1 for f in findings if f["status"] == "danger"),
        "warning": sum(1 for f in findings if f["status"] == "warning"),
        "safe": sum(1 for f in findings if f["status"] == "safe"),
    }


# ── GUI APPLICATION ─────────────────────────────────────────────────────────
class PhishGuardApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PhishGuard — Advanced Phishing Detector")
        self.geometry("1200x820")
        self.minsize(900, 700)
        self.configure(fg_color=C_BG)
        self._scan_result = None
        self._filter = "all"
        self._all_finding_rows = []
        self._build_ui()

    # ── BUILD ────────────────────────────────────────────────────────────────
    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self._build_header()
        self._build_input_bar()
        self._build_body()
        self._build_status_bar()

    def _build_header(self):
        hdr = ctk.CTkFrame(self, fg_color=C_BG2, corner_radius=0, height=80)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_columnconfigure(0, weight=1)
        hdr.grid_propagate(False)

        inner = ctk.CTkFrame(hdr, fg_color="transparent")
        inner.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(inner, text="⬡  PHISHGUARD", font=("Courier New", 28, "bold"),
                     text_color=C_CYAN).pack(side="left", padx=(0, 16))
        ctk.CTkLabel(inner, text="ADVANCED PHISHING WEBSITE DETECTOR",
                     font=("Courier New", 11), text_color=C_TEXT_DIM).pack(side="left", pady=(6, 0))

        # Top accent line
        accent = ctk.CTkFrame(self, fg_color=C_CYAN, height=2, corner_radius=0)
        accent.grid(row=0, column=0, sticky="ew")
        accent.lower()

    def _build_input_bar(self):
        bar = ctk.CTkFrame(self, fg_color=C_PANEL, corner_radius=0, height=72)
        bar.grid(row=1, column=0, sticky="ew")
        bar.grid_columnconfigure(1, weight=1)
        bar.grid_propagate(False)

        ctk.CTkLabel(bar, text="TARGET URL :", font=FONT_MONO_B,
                     text_color=C_CYAN).grid(row=0, column=0, padx=(24, 10), pady=20)

        self.url_var = StringVar()
        self.url_entry = ctk.CTkEntry(
            bar, textvariable=self.url_var,
            placeholder_text="https://example.com",
            font=FONT_MONO, text_color=C_CYAN,
            fg_color=C_BG, border_color=C_BORDER, border_width=1,
            corner_radius=4, height=40,
        )
        self.url_entry.grid(row=0, column=1, sticky="ew", padx=(0, 12), pady=16)
        self.url_entry.bind("<Return>", lambda e: self._start_scan())

        self.scan_btn = ctk.CTkButton(
            bar, text="▶  SCAN", font=("Courier New", 12, "bold"),
            fg_color="transparent", border_color=C_CYAN, border_width=1,
            text_color=C_CYAN, hover_color=C_BG2,
            corner_radius=4, width=120, height=40,
            command=self._start_scan
        )
        self.scan_btn.grid(row=0, column=2, padx=(0, 16), pady=16)

        self.clear_btn = ctk.CTkButton(
            bar, text="✕", font=("Courier New", 12, "bold"),
            fg_color="transparent", border_color=C_BORDER, border_width=1,
            text_color=C_TEXT_DIM, hover_color=C_BG2,
            corner_radius=4, width=40, height=40,
            command=self._clear
        )
        self.clear_btn.grid(row=0, column=3, padx=(0, 24), pady=16)

    def _build_body(self):
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=2, column=0, sticky="nsew", padx=0, pady=0)
        body.grid_columnconfigure(0, weight=0)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        self._build_left_panel(body)
        self._build_right_panel(body)

    # ── LEFT PANEL ───────────────────────────────────────────────────────────
    def _build_left_panel(self, parent):
        left = ctk.CTkFrame(parent, fg_color=C_PANEL, corner_radius=0, width=300)
        left.grid(row=0, column=0, sticky="nsew")
        left.grid_propagate(False)
        left.grid_columnconfigure(0, weight=1)

        # Welcome state
        self.left_welcome = ctk.CTkFrame(left, fg_color="transparent")
        self.left_welcome.grid(row=0, column=0, sticky="nsew", padx=20, pady=40)
        left.grid_rowconfigure(0, weight=1)

        ctk.CTkLabel(self.left_welcome, text="⬡", font=("Courier New", 48),
                     text_color=C_BORDER).pack(pady=(40, 10))
        ctk.CTkLabel(self.left_welcome, text="ENTER A URL\nTO BEGIN SCAN",
                     font=FONT_MONO, text_color=C_TEXT_DIM,
                     justify="center").pack()

        # Results state (hidden initially)
        self.left_results = ctk.CTkFrame(left, fg_color="transparent")
        self.left_results.grid(row=0, column=0, sticky="nsew")
        self.left_results.grid_remove()
        self.left_results.grid_columnconfigure(0, weight=1)

        # Verdict box
        self.verdict_frame = ctk.CTkFrame(self.left_results, fg_color=C_BG2,
                                           corner_radius=0, height=140)
        self.verdict_frame.grid(row=0, column=0, sticky="ew", padx=0, pady=(0, 2))
        self.verdict_frame.grid_propagate(False)
        self.verdict_frame.grid_columnconfigure(0, weight=1)

        self.verdict_icon_lbl = ctk.CTkLabel(self.verdict_frame, text="",
                                              font=("Courier New", 32, "bold"), text_color=C_GREEN)
        self.verdict_icon_lbl.place(relx=0.5, rely=0.35, anchor="center")

        self.verdict_lbl = ctk.CTkLabel(self.verdict_frame, text="",
                                         font=("Courier New", 16, "bold"), text_color=C_GREEN)
        self.verdict_lbl.place(relx=0.5, rely=0.72, anchor="center")

        # Score
        score_f = ctk.CTkFrame(self.left_results, fg_color=C_BG, corner_radius=0)
        score_f.grid(row=1, column=0, sticky="ew", pady=(0, 2))
        self.score_lbl = ctk.CTkLabel(score_f, text="--", font=("Courier New", 52, "bold"),
                                       text_color=C_CYAN)
        self.score_lbl.pack(pady=(12, 0))
        ctk.CTkLabel(score_f, text="RISK SCORE / 100",
                     font=FONT_MONO_S, text_color=C_TEXT_DIM).pack(pady=(0, 12))

        # Stats 3-grid
        stats_f = ctk.CTkFrame(self.left_results, fg_color="transparent")
        stats_f.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 4))
        stats_f.grid_columnconfigure((0, 1, 2), weight=1)

        self.danger_lbl = self._stat_card(stats_f, "0", "FAIL", C_RED, 0)
        self.warn_lbl   = self._stat_card(stats_f, "0", "WARN", C_YELLOW, 1)
        self.safe_lbl   = self._stat_card(stats_f, "0", "PASS", C_GREEN, 2)

        # Domain info
        info_f = ctk.CTkFrame(self.left_results, fg_color=C_BG, corner_radius=6)
        info_f.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 10))
        info_f.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(info_f, text="── DOMAIN INFO ──",
                     font=FONT_MONO_S, text_color=C_TEXT_DIM).grid(row=0, column=0, pady=(8, 4))

        self.info_labels = {}
        for i, key in enumerate(["HOST", "DOMAIN", "PROTOCOL"]):
            ctk.CTkLabel(info_f, text=key, font=("Courier New", 9, "bold"),
                         text_color=C_TEXT_DIM).grid(row=1 + i*2, column=0, sticky="w", padx=12)
            lbl = ctk.CTkLabel(info_f, text="—", font=FONT_MONO_S,
                               text_color=C_CYAN, wraplength=250, justify="left")
            lbl.grid(row=2 + i*2, column=0, sticky="w", padx=12, pady=(0, 6))
            self.info_labels[key] = lbl

        # Open in browser button
        self.open_btn = ctk.CTkButton(
            self.left_results, text="🌐  OPEN IN BROWSER",
            font=FONT_MONO_S, fg_color="transparent",
            border_color=C_BORDER, border_width=1,
            text_color=C_TEXT_DIM, hover_color=C_BG2,
            corner_radius=4, height=36,
            command=self._open_browser
        )
        self.open_btn.grid(row=4, column=0, sticky="ew", padx=10, pady=(0, 10))

    def _stat_card(self, parent, value, label, color, col):
        f = ctk.CTkFrame(parent, fg_color=C_BG, corner_radius=4)
        f.grid(row=0, column=col, padx=3, pady=3, sticky="ew")
        n = ctk.CTkLabel(f, text=value, font=("Courier New", 26, "bold"), text_color=color)
        n.pack(pady=(8, 0))
        ctk.CTkLabel(f, text=label, font=("Courier New", 8, "bold"),
                     text_color=C_TEXT_DIM).pack(pady=(0, 8))
        return n

    # ── RIGHT PANEL ──────────────────────────────────────────────────────────
    def _build_right_panel(self, parent):
        right = ctk.CTkFrame(parent, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(1, weight=1)

        # Filter bar
        filter_f = ctk.CTkFrame(right, fg_color=C_PANEL, corner_radius=0, height=50)
        filter_f.grid(row=0, column=0, sticky="ew")
        filter_f.grid_propagate(False)

        ctk.CTkLabel(filter_f, text="SECURITY CHECKS :", font=FONT_MONO_B,
                     text_color=C_TEXT_DIM).pack(side="left", padx=(16, 12), pady=12)

        self.filter_btns = {}
        filters = [("ALL", "all", C_CYAN), ("FAILED", "danger", C_RED),
                   ("WARNINGS", "warning", C_YELLOW), ("PASSED", "safe", C_GREEN)]

        for label, key, color in filters:
            btn = ctk.CTkButton(
                filter_f, text=label, font=("Courier New", 10, "bold"),
                fg_color="transparent", border_color=color, border_width=1,
                text_color=color, hover_color=C_BG2,
                corner_radius=2, width=80, height=28,
                command=lambda k=key: self._apply_filter(k)
            )
            btn.pack(side="left", padx=4, pady=11)
            self.filter_btns[key] = btn

        # Scrollable findings area
        self.findings_scroll = ctk.CTkScrollableFrame(
            right, fg_color=C_BG, corner_radius=0,
            scrollbar_button_color=C_BORDER,
            scrollbar_button_hover_color=C_CYAN_DIM,
        )
        self.findings_scroll.grid(row=1, column=0, sticky="nsew")
        self.findings_scroll.grid_columnconfigure(0, weight=1)

        # Welcome placeholder
        self.welcome_placeholder = ctk.CTkFrame(self.findings_scroll, fg_color="transparent")
        self.welcome_placeholder.grid(row=0, column=0, sticky="nsew", pady=80)
        self.findings_scroll.grid_rowconfigure(0, weight=1)

        ctk.CTkLabel(self.welcome_placeholder,
                     text="No analysis yet.\nEnter a URL and press SCAN to begin.",
                     font=FONT_MONO, text_color=C_TEXT_DIM, justify="center").pack(expand=True)

        # Loader
        self.loader_frame = ctk.CTkFrame(self.findings_scroll, fg_color="transparent")
        self.loader_lbl = ctk.CTkLabel(self.loader_frame, text="⟳  SCANNING...",
                                        font=("Courier New", 14, "bold"), text_color=C_CYAN)
        self.loader_lbl.pack(pady=(60, 8))
        self.loader_step_lbl = ctk.CTkLabel(self.loader_frame, text="",
                                             font=FONT_MONO_S, text_color=C_TEXT_DIM)
        self.loader_step_lbl.pack()

        # Column headers (hidden initially)
        self.col_header = ctk.CTkFrame(self.findings_scroll, fg_color=C_BG2, corner_radius=0, height=30)
        self.col_header.grid_columnconfigure(1, weight=1)
        self.col_header.grid_columnconfigure(2, weight=2)

        for col, txt, w in [
            (0, "STATUS", 70), (1, "CHECK NAME", 200),
            (2, "DETAILS", 400), (3, "RISK +", 60)
        ]:
            ctk.CTkLabel(self.col_header, text=txt, font=("Courier New", 9, "bold"),
                         text_color=C_TEXT_DIM).grid(row=0, column=col, sticky="w",
                                                       padx=(12 if col==0 else 6, 6), pady=6)

        self.col_header.grid_remove()

    # ── SCAN ─────────────────────────────────────────────────────────────────
    def _start_scan(self):
        raw = self.url_var.get().strip()
        if not raw:
            return
        url = normalize_url(raw)
        if not is_valid_url(url):
            self._set_status("⚠ Invalid URL", C_RED)
            return

        self.scan_btn.configure(state="disabled", text="SCANNING...")
        self._show_loader()
        self._set_status("Scanning: " + url, C_CYAN)

        thread = threading.Thread(target=self._run_scan_thread, args=(url,), daemon=True)
        thread.start()
        self._animate_loader(0)

    def _run_scan_thread(self, url):
        result = run_analysis(url)
        self.after(0, lambda: self._on_scan_done(result))

    def _on_scan_done(self, result):
        self._scan_result = result
        self._stop_loader_anim = True
        self._show_results(result)
        self.scan_btn.configure(state="normal", text="▶  SCAN")
        self._set_status(f"Scan complete  ·  Score: {result['score']}/100  ·  {result['label']}", result['color'])

    def _animate_loader(self, step):
        steps = [
            "[ RESOLVING DNS... ]",
            "[ CHECKING SSL CERTIFICATE... ]",
            "[ FETCHING WEBSITE... ]",
            "[ PARSING HTML STRUCTURE... ]",
            "[ ANALYZING JAVASCRIPT... ]",
            "[ CHECKING REDIRECTS... ]",
            "[ COMPILING THREAT SCORE... ]",
        ]
        if hasattr(self, '_stop_loader_anim') and self._stop_loader_anim:
            return
        self.loader_step_lbl.configure(text=steps[step % len(steps)])
        self._loader_job = self.after(700, lambda: self._animate_loader(step + 1))

    def _show_loader(self):
        self._stop_loader_anim = False
        self.welcome_placeholder.grid_remove()
        self.col_header.grid_remove()
        # Clear old findings
        for w in self._all_finding_rows:
            w.destroy()
        self._all_finding_rows = []

        self.loader_frame.grid(row=0, column=0)
        self.left_welcome.grid_remove()
        self.left_results.grid_remove()

    def _show_results(self, r):
        self.loader_frame.grid_remove()

        # Update left panel
        self.left_results.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        self.left_results.tkraise()

        icon = "✔" if r['label'] == "SAFE" else ("⚠" if r['label'] == "SUSPICIOUS" else "✖")
        self.verdict_icon_lbl.configure(text=icon, text_color=r['color'])
        self.verdict_lbl.configure(text=r['label'], text_color=r['color'])
        self.verdict_frame.configure(fg_color=C_BG2)

        self.score_lbl.configure(text=str(r['score']), text_color=r['color'])
        self.danger_lbl.configure(text=str(r['danger']))
        self.warn_lbl.configure(text=str(r['warning']))
        self.safe_lbl.configure(text=str(r['safe']))

        host = r['host']
        domain = r['domain']
        proto = "HTTPS ✔" if r['url'].lower().startswith("https") else "HTTP ✖"
        self.info_labels["HOST"].configure(text=host or "—")
        self.info_labels["DOMAIN"].configure(text=domain or "—")
        self.info_labels["PROTOCOL"].configure(text=proto,
            text_color=C_GREEN if "HTTPS" in proto else C_RED)

        # Findings rows
        self.col_header.grid(row=0, column=0, sticky="ew")
        self._all_finding_rows = []

        for i, f in enumerate(r['findings']):
            row = self._make_finding_row(self.findings_scroll, f, i + 1)
            self._all_finding_rows.append((row, f['status']))

        self._apply_filter(self._filter)

    def _make_finding_row(self, parent, f, row_idx):
        status = f['status']
        color = C_GREEN if status == "safe" else (C_YELLOW if status == "warning" else C_RED)
        badge  = "PASS" if status == "safe" else ("WARN" if status == "warning" else "FAIL")
        bg     = C_PANEL if row_idx % 2 == 0 else C_BG

        frame = ctk.CTkFrame(parent, fg_color=bg, corner_radius=0, height=36)
        frame.grid(row=row_idx, column=0, sticky="ew", pady=1)
        frame.grid_columnconfigure(2, weight=1)
        frame.grid_propagate(False)

        # Left accent stripe
        stripe = ctk.CTkFrame(frame, fg_color=color, width=3, corner_radius=0)
        stripe.place(x=0, y=0, relheight=1)

        # Status badge
        ctk.CTkLabel(frame, text=badge, font=("Courier New", 8, "bold"),
                     text_color=color, width=55, anchor="center").grid(
            row=0, column=0, padx=(10, 4), pady=8)

        # Name
        ctk.CTkLabel(frame, text=f['name'], font=FONT_MONO_B,
                     text_color=C_TEXT, anchor="w", width=170).grid(
            row=0, column=1, padx=(0, 8), pady=8, sticky="w")

        # Detail
        ctk.CTkLabel(frame, text=f['detail'], font=FONT_MONO_S,
                     text_color=C_TEXT_DIM, anchor="w", wraplength=480, justify="left").grid(
            row=0, column=2, padx=(0, 8), pady=8, sticky="w")

        # Points
        pts = f"+{f['points']}" if f['points'] > 0 else "0"
        pts_color = C_RED if f['points'] > 0 else C_TEXT_DIM
        ctk.CTkLabel(frame, text=pts, font=("Courier New", 11, "bold"),
                     text_color=pts_color, width=46, anchor="e").grid(
            row=0, column=3, padx=(0, 12), pady=8)

        return frame

    def _apply_filter(self, f):
        self._filter = f

        # Update button styles
        filter_colors = {"all": C_CYAN, "danger": C_RED, "warning": C_YELLOW, "safe": C_GREEN}
        for key, btn in self.filter_btns.items():
            col = filter_colors[key]
            if key == f:
                btn.configure(fg_color=col, text_color=C_BG)
            else:
                btn.configure(fg_color="transparent", text_color=col)

        for row_frame, status in self._all_finding_rows:
            if f == "all" or status == f:
                row_frame.grid()
            else:
                row_frame.grid_remove()

    def _clear(self):
        self.url_var.set("")
        self._stop_loader_anim = True
        self.left_results.grid_remove()
        self.loader_frame.grid_remove()
        self.left_welcome.grid(row=0, column=0, sticky="nsew")
        self.welcome_placeholder.grid(row=0, column=0, sticky="nsew")
        self.col_header.grid_remove()
        for w, _ in self._all_finding_rows:
            w.destroy()
        self._all_finding_rows = []
        self._set_status("Ready", C_TEXT_DIM)

    def _open_browser(self):
        if self._scan_result:
            webbrowser.open(self._scan_result['url'])

    # ── STATUS BAR ───────────────────────────────────────────────────────────
    def _build_status_bar(self):
        bar = ctk.CTkFrame(self, fg_color=C_BG2, corner_radius=0, height=28)
        bar.grid(row=3, column=0, sticky="ew")
        bar.grid_propagate(False)
        bar.grid_columnconfigure(0, weight=1)

        self.status_lbl = ctk.CTkLabel(bar, text="Ready", font=("Courier New", 10),
                                        text_color=C_TEXT_DIM, anchor="w")
        self.status_lbl.grid(row=0, column=0, padx=16, pady=5, sticky="w")

        ctk.CTkLabel(bar, text="PhishGuard v2.0  ·  Neural Threat Engine",
                     font=("Courier New", 10), text_color=C_TEXT_DIM).grid(
            row=0, column=1, padx=16, pady=5)

    def _set_status(self, msg, color=None):
        self.status_lbl.configure(text=msg, text_color=color or C_TEXT_DIM)


if __name__ == "__main__":
    app = PhishGuardApp()
    app.mainloop()
