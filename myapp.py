from flask_socketio import SocketIO, emit
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from typing import Optional
from flask import (
    Flask,
    request,
    render_template_string,
    redirect,
    url_for,
    Response,
    send_file,
)
import requests
from requests.exceptions import ProxyError, RequestException
import time
import urllib3
import csv
import io
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque
from threading import Thread

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ----------------- GLOBAL STATE -----------------
SCAN_RESULTS = []      # current scan flows
SCAN_HISTORY = []      # previous scans
SCANNING = False
CURRENT_TARGET = ""
CURRENT_MODE = "single"
STOP_REQUESTED = False
PROXY_ENABLED = False  # Proxy toggle (uses 127.0.0.1:8080 when ON)


# ----------------- HELPERS -----------------
def classify_risk(url: str, has_post: bool) -> str:
    u = url.lower()
    if any(x in u for x in ["admin", "login", "dashboard", "upload", "panel", "wp-admin"]):
        return "High"
    if "?" in u or has_post:
        return "Medium"
    return "Low"


def build_flags(url: str, has_post=False, from_default=False) -> str:
    flags = []
    u = url.lower()

    if any(x in u for x in ["admin", "wp-admin", "/manager", "/cpanel", "/dashboard"]):
        flags.append("Admin/Portal")
    if any(x in u for x in ["/login", "signin", "auth"]):
        flags.append("Login/Auth")

    if u.endswith((".php", ".asp", ".aspx", ".jsp", ".do", ".action", ".cfm")):
        flags.append("Backend script")
    if u.endswith((".js", ".css", ".map")):
        flags.append("Frontend asset")
    if "/api/" in u or "/api." in u:
        flags.append("API endpoint")

    if u.endswith((
        ".env", ".sql", ".db", ".sqlite", ".zip", ".rar", ".7z", ".tar", ".tar.gz",
        ".bak", ".backup", ".old", ".gz", ".log", ".yml", ".yaml"
    )):
        flags.append("Sensitive/Backup file")

    if "/.git/" in u:
        flags.append("Git metadata")
    if "/server-status" in u:
        flags.append("Server status")
    if from_default:
        flags.append("Default path probe")
    if has_post:
        flags.append("Form page")

    return ", ".join(flags)


def extract_params(url: str, soup: Optional[BeautifulSoup]) -> str:
    """Collect query + form parameter names for display in Params column."""
    names = set()

    parsed = urlparse(url)
    q = parse_qs(parsed.query)
    for key in q.keys():
        if key:
            names.add(key)

    if soup is not None:
        for form in soup.find_all("form"):
            for inp in form.find_all(["input", "select", "textarea"]):
                name = inp.get("name")
                if name:
                    names.add(name)

    if not names:
        return ""
    return ", ".join(sorted(names))


# ---------------- SAFE FLAG APPENDER ----------------
def append_flags(flags, items):
    """
    Safely append findings to flags without leading commas.
    items can be list or string.
    """
    if not items:
        return flags
    if isinstance(items, list):
        items = ", ".join(items)
    if items.strip() == "":
        return flags
    if flags:
        return flags + ", " + items
    else:
        return items


# ----------------- BASIC VULNERABILITY SCANNER -----------------

def detect_vulnerabilities(url, response_text, params):
    """
    Basic vulnerability detection for SQLi and XSS.
    """
    findings = []

    # SQL error patterns
    sql_errors = [
        "sql syntax",
        "mysql_fetch",
        "ORA-01756",
        "SQLSTATE",
        "syntax error near",
        "unclosed quotation mark"
    ]

    # Check SQL errors
    lower_text = (response_text or "").lower()
    for err in sql_errors:
        if err in lower_text:
            findings.append("Possible SQL Injection")
            break

    # Check reflected XSS
    xss_payload = "<script>alert(1)</script>"
    if xss_payload in (response_text or ""):
        findings.append("Possible XSS")

    # Parameter presence check
    if params:
        findings.append("Input Parameters Detected")

    return findings


# ---------------- SECURITY HEADER ANALYZER ----------------

def analyze_security_headers(headers):
    findings = []

    important_headers = [
        "X-Frame-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "Referrer-Policy"
    ]

    # headers param may be a dict-like object
    for h in important_headers:
        if h not in headers:
            findings.append(f"Missing Security Header: {h}")

    return findings


# ---------------- SECURITY HEADER SCORE ----------------

def calculate_security_score(headers):
    required_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy"
    ]

    score = 0
    per_header = 100 / len(required_headers)
    for h in required_headers:
        if h in headers:
            score += per_header
    # round to nearest integer
    return int(score)


# ---------------- TECHNOLOGY DETECTION ----------------

def detect_technologies(headers, body):
    tech = []

    server = headers.get("Server", "") if headers else ""
    server = server.lower()

    if "nginx" in server:
        tech.append("Server: Nginx")
    if "apache" in server:
        tech.append("Server: Apache")

    body_l = (body or "").lower()
    if "php" in body_l:
        tech.append("PHP Detected")
    if "wp-content" in body_l or "wordpress" in body_l:
        tech.append("WordPress Detected")
    if "react" in body_l:
        tech.append("React Detected")

    return tech


# ---------------- ACTIVE VULNERABILITY TESTER ----------------

def active_vulnerability_scan(url, params):
    findings = []

    payloads = [
        "'",
        "' OR '1'='1",
        "<script>alert(1)</script>",
        "`id`"
    ]

    if not params:
        return findings

    for param in params.split(","):
        param = param.strip()
        if not param:
            continue
        for payload in payloads:
            try:
                test_url = url + payload
                r = requests.get(test_url, timeout=6)

                text = (r.text or "").lower()

                if "sql" in text or "syntax error" in text:
                    findings.append(f"SQL Injection test on {param}")

                if "<script>alert(1)</script>" in (r.text or ""):
                    findings.append(f"Reflected XSS on {param}")

                if "uid=" in text or "gid=" in text:
                    findings.append(f"Command Injection on {param}")

            except:
                pass

    return findings


# ---------------- OPEN REDIRECT TEST ----------------

def detect_open_redirect(url):
    findings = []
    payload = "https://evil.com"

    try:
        test_url = url + "?redirect=" + payload
        r = requests.get(test_url, allow_redirects=False, timeout=6)
        location = r.headers.get("Location", "") if r and r.headers else ""
        if payload in location:
            findings.append("Possible Open Redirect")
    except:
        pass

    return findings


# ---------------- CORS MISCONFIG DETECTION ----------------

def detect_cors(headers):
    findings = []
    origin = headers.get("Access-Control-Allow-Origin") if headers else None
    if origin == "*":
        findings.append("CORS Misconfiguration: Wildcard Origin")
    return findings


# ---------------- DIRECTORY LISTING DETECTION ----------------

def detect_directory_listing(response_text):
    indicators = [
        "Index of /",
        "Directory listing for",
        "<title>Index of"
    ]
    for i in indicators:
        if i.lower() in (response_text or "").lower():
            return ["Directory Listing Enabled"]
    return []


# ----------------- DEFAULT PATH PROBER -----------------
def probe_default_files(root_url, visited, base_headers, proxies):
    global SCAN_RESULTS, PROXY_ENABLED

    parsed = urlparse(root_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    default_paths = [
        ("/", "Root"),
        ("/robots.txt", "Robots"),
        ("/sitemap.xml", "Sitemap"),
        ("/admin", "Admin area"),
        ("/admin.php", "Admin PHP"),
        ("/administrator", "Admin area"),
        ("/login", "Login page"),
        ("/login.php", "Login PHP"),
        ("/config.php", "Config file"),
        ("/phpinfo.php", "PHP info"),
        ("/wp-admin", "WP admin"),
        ("/.env", "Env file"),
        ("/.git/HEAD", "Git HEAD"),
        ("/backup.zip", "Backup archive"),
        ("/db.sql", "DB dump"),
        ("/server-status", "Server status"),
    ]

    for path, label in default_paths:
        url = root + path
        if url in visited:
            continue
        visited.add(url)

        proxy_note = ""
        r = None
        error_msg = None

        try:
            r = requests.get(
                url,
                headers=base_headers,
                timeout=8,
                verify=False,
                proxies=proxies,
            )
        except ProxyError as e:
            # proxy not reachable → retry once direct and switch proxy OFF
            error_msg = str(e)
            if proxies:
                try:
                    r = requests.get(
                        url,
                        headers=base_headers,
                        timeout=8,
                        verify=False,
                        proxies=None,
                    )
                    proxy_note = f"Proxy error: {error_msg}; retried direct"
                    PROXY_ENABLED = False
                except RequestException as e2:
                    error_msg = str(e2)
                    r = None
        except RequestException as e:
            error_msg = str(e)
            r = None

        if r is None:
            # could not fetch at all
            flags = "Default path probe"
            if error_msg:
                flags = append_flags(flags, f"Request error: {error_msg}")
            SCAN_RESULTS.append({
                "id": len(SCAN_RESULTS) + 1,
                "time": time.strftime("%H:%M:%S"),
                "method": "GET",
                "url": url,
                "status": None,
                "risk": "Medium",
                "params": "",
                "flags": flags,
                "raw_response": f"Request failed: {error_msg}",
                "req_headers_text": "\n".join(f"{k}: {v}" for k, v in base_headers.items()),
                "req_body_text": "",
            })
            continue

        if r.status_code in (200, 301, 302, 401, 403):
            has_post = False
            risk = "High" if any(
                x in path.lower()
                for x in [".env", ".git", "phpinfo", "backup", "db.sql", "config", "server-status"]
            ) else classify_risk(url, has_post)

            req_headers_text = "\n".join(f"{k}: {v}" for k, v in base_headers.items())
            resp_headers_text = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            raw_response = f"HTTP {r.status_code}\n{resp_headers_text}\n\n{r.text[:4000]}"

            flags = build_flags(url, has_post=False, from_default=True)
            if label not in flags:
                flags = append_flags(flags, label)
            if proxy_note:
                flags = append_flags(flags, proxy_note)

            SCAN_RESULTS.append({
                "id": len(SCAN_RESULTS) + 1,
                "time": time.strftime("%H:%M:%S"),
                "method": "GET",
                "url": url,
                "status": r.status_code,
                "risk": risk,
                "params": "",
                "flags": flags,
                "raw_response": raw_response,
                "req_headers_text": req_headers_text,
                "req_body_text": "",
            })


# ---------------- FUZZING PAYLOADS ----------------

FUZZ_PAYLOADS = [
    "'",
    "\"",
    "' OR 1=1--",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "`id`",
    ";cat /etc/passwd",
    "|whoami"
]


# ---------------- PARAMETER FUZZER ----------------

def fuzz_parameters(url, params):

    findings = []

    if not params:
        return findings

    for param in params.split(","):
        param = param.strip()
        if not param:
            continue

        for payload in FUZZ_PAYLOADS:

            try:

                if "?" in url:
                    test_url = url + payload
                else:
                    test_url = url + "?" + param + "=" + payload

                r = requests.get(test_url, timeout=6)
                text = (r.text or "").lower()

                if "sql" in text or "syntax error" in text:
                    findings.append(f"SQL error via fuzzing ({param})")

                if "<script>alert(1)</script>" in (r.text or ""):
                    findings.append(f"Reflected XSS ({param})")

                if "root:" in text or "uid=" in text:
                    findings.append(f"Possible LFI / Command Injection ({param})")

            except:
                pass

    return findings


# ----------------- CRAWLER -----------------
def crawl_worker(start_url, mode):
    global SCANNING, STOP_REQUESTED, SCAN_RESULTS, PROXY_ENABLED

    visited = set()
    q = deque([start_url])
    root = urlparse(start_url).netloc

    base_headers = {
        "User-Agent": "InterceptPro/1.0",
        "Accept": "*/*",
    }

    proxies = {
        "http": "http://127.0.0.1:8080",
        "https": "http://127.0.0.1:8080",
    } if PROXY_ENABLED else None

    max_pages = 1 if mode == "single" else (40 if mode == "browser" else 120)

    while q and not STOP_REQUESTED and len(visited) < max_pages:

        url = q.popleft()

        if url in visited:
            continue

        visited.add(url)

        try:
            r = requests.get(
                url,
                headers=base_headers,
                timeout=12,
                verify=False,
                proxies=proxies,
            )
        except Exception as e:

            SCAN_RESULTS.append({
                "id": len(SCAN_RESULTS) + 1,
                "time": time.strftime("%H:%M:%S"),
                "method": "GET",
                "url": url,
                "status": None,
                "risk": "Medium",
                "params": "",
                "flags": f"Request error: {str(e)}",
                "raw_response": "",
                "req_headers_text": "",
                "req_body_text": "",
            })

            continue

        soup = None
        has_post = False

        try:
            if "text" in (r.headers.get("Content-Type", "") or "").lower():
                soup = BeautifulSoup(r.text, "html.parser")
                has_post = any(
                    (f.get("method", "GET").upper() == "POST")
                    for f in soup.find_all("form")
                )
        except:
            soup = None

        risk = classify_risk(url, has_post)

        params_str = extract_params(url, soup)

        # build initial flags from URL patterns
        flags = build_flags(url, has_post)

        # Security header analysis & score
        header_findings = analyze_security_headers(r.headers)
        score = calculate_security_score(r.headers)
        flags = append_flags(flags, f"Security Header Score: {score}/100")
        flags = append_flags(flags, header_findings)

        # CORS
        cors_findings = detect_cors(r.headers)
        flags = append_flags(flags, cors_findings)

        # Technology detection
        tech_findings = detect_technologies(r.headers, r.text)
        flags = append_flags(flags, tech_findings)

        # Open redirect detection
        redirect_findings = detect_open_redirect(url)
        flags = append_flags(flags, redirect_findings)

        # Passive vulnerability detection
        vuln = detect_vulnerabilities(url, r.text, params_str)
        flags = append_flags(flags, vuln)

        # Directory listing detection
        dir_listing = detect_directory_listing(r.text)
        flags = append_flags(flags, dir_listing)

        # Active vulnerability scan
        active = active_vulnerability_scan(url, params_str)
        flags = append_flags(flags, active)

        # Parameter fuzzing
        fuzz = fuzz_parameters(url, params_str)
        flags = append_flags(flags, fuzz)

        SCAN_RESULTS.append({
            "id": len(SCAN_RESULTS) + 1,
            "time": time.strftime("%H:%M:%S"),
            "method": "GET",
            "url": url,
            "status": r.status_code,
            "risk": risk,
            "params": params_str,
            "flags": flags,
            "raw_response": r.text[:8000],
            "req_headers_text": "",
            "req_body_text": "",
        })

        if mode != "single" and soup is not None:
            for a in soup.find_all("a", href=True):
                link = urljoin(url, a["href"])
                if urlparse(link).netloc == root:
                    q.append(link)

    # Run additional scanners after crawl

    dirs = directory_bruteforce(start_url)
    for d in dirs:
        SCAN_RESULTS.append({
            "id": len(SCAN_RESULTS) + 1,
            "time": time.strftime("%H:%M:%S"),
            "method": "GET",
            "url": d,
            "status": 200,
            "risk": "High",
            "params": "",
            "flags": "Discovered Directory",
            "raw_response": "",
            "req_headers_text": "",
            "req_body_text": "",
        })

    domain = urlparse(start_url).netloc
    subs = discover_subdomains(domain)
    for s in subs:
        SCAN_RESULTS.append({
            "id": len(SCAN_RESULTS) + 1,
            "time": time.strftime("%H:%M:%S"),
            "method": "GET",
            "url": s,
            "status": 200,
            "risk": "Medium",
            "params": "",
            "flags": "Discovered Subdomain",
            "raw_response": "",
            "req_headers_text": "",
            "req_body_text": "",
        })

    probe_default_files(start_url, visited, base_headers, proxies)

    # reset scanning state
    SCANNING = False
    STOP_REQUESTED = False


# ----------------- ROUTES -----------------
@app.route("/")
def index():
    method_filter = (request.args.get("method") or "").upper()
    status_group = (request.args.get("status") or "").strip()
    q = (request.args.get("q") or "").strip().lower()

    def match(row):
        if method_filter and row["method"].upper() != method_filter:
            return False
        if status_group and row["status"] is not None:
            if not str(row["status"]).startswith(status_group):
                return False
        if q:
            if q not in row["url"].lower():
                return False
        return True

    filtered_rows = [type("R", (), r) for r in SCAN_RESULTS if match(r)]

    return render_template_string(
        DASHBOARD_HTML,
        rows=filtered_rows,
        total=len(SCAN_RESULTS),
        scanning=SCANNING,
        target=CURRENT_TARGET or "None",
        mode=CURRENT_MODE,
        method_filter=method_filter,
        status_group=status_group,
        q=(request.args.get("q") or ""),
        proxy_enabled=PROXY_ENABLED,
    )


@app.route("/scan", methods=["POST"])
def scan():
    global SCAN_RESULTS, SCANNING, CURRENT_TARGET, CURRENT_MODE, STOP_REQUESTED

    if CURRENT_TARGET and SCAN_RESULTS:
        SCAN_HISTORY.append({
            "target": CURRENT_TARGET,
            "mode": CURRENT_MODE,
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "results": list(SCAN_RESULTS),
        })

    target = request.form["target"].strip()
    mode = request.form["mode"]

    if not target.startswith("http"):
        target = "https://" + target

    CURRENT_TARGET = target
    CURRENT_MODE = mode
    SCAN_RESULTS = []
    STOP_REQUESTED = False
    SCANNING = True

    Thread(target=crawl_worker, args=(target, mode), daemon=True).start()
    return redirect(url_for("index"))


@app.route("/stop", methods=["POST"])
def stop():
    global STOP_REQUESTED, SCANNING
    STOP_REQUESTED = True
    SCANNING = False
    return redirect(url_for("index"))


@app.route("/reset", methods=["POST"])
def reset():
    global SCAN_RESULTS, CURRENT_TARGET, CURRENT_MODE, SCANNING
    SCAN_RESULTS = []
    CURRENT_TARGET = ""
    CURRENT_MODE = "single"
    SCANNING = False
    return redirect(url_for("index"))


@app.route("/toggle-proxy", methods=["POST"])
def toggle_proxy():
    global PROXY_ENABLED
    PROXY_ENABLED = not PROXY_ENABLED
    return redirect(url_for("index"))


@app.route("/history")
def history():
    return render_template_string(HISTORY_HTML, history=SCAN_HISTORY[::-1])


@app.route("/load/<int:i>")
def load_old(i):
    global SCAN_RESULTS, CURRENT_TARGET, CURRENT_MODE, SCANNING
    if i < 0 or i >= len(SCAN_HISTORY):
        return redirect(url_for("history"))
    h = SCAN_HISTORY[len(SCAN_HISTORY) - 1 - i]
    SCAN_RESULTS = h["results"]
    CURRENT_TARGET = h["target"]
    CURRENT_MODE = h["mode"]
    SCANNING = False
    return redirect(url_for("index"))


@app.route("/flow/<int:i>", methods=["GET", "POST"])
def flow(i):
    global PROXY_ENABLED

    # bounds check to avoid IndexError
    if i < 1 or i > len(SCAN_RESULTS):
        return redirect(url_for("index"))

    flow = SCAN_RESULTS[i - 1]

    method = flow["method"]
    url = flow["url"]
    headers_text = flow.get("req_headers_text", "")
    body_text = flow.get("req_body_text", "")
    response_text = flow.get("raw_response", "")

    if request.method == "POST":
        method = request.form.get("method", method)
        url = request.form.get("url", url)
        headers_text = request.form.get("headers", "")
        body_text = request.form.get("body", "")

        headers = {}
        for line in headers_text.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

        proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080",
        } if PROXY_ENABLED else None

        r = None
        error_msg = None

        try:
            r = requests.request(
                method,
                url,
                headers=headers,
                data=body_text,
                timeout=15,
                verify=False,
                proxies=proxies,
            )
        except ProxyError as e:
            error_msg = str(e)
            if proxies:
                try:
                    r = requests.request(
                        method,
                        url,
                        headers=headers,
                        data=body_text,
                        timeout=15,
                        verify=False,
                        proxies=None,
                    )
                    PROXY_ENABLED = False
                except RequestException as e2:
                    error_msg = str(e2)
                    r = None
        except RequestException as e:
            error_msg = str(e)
            r = None

        if r is not None:
            resp_headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            response_text = f"HTTP {r.status_code}\n{resp_headers}\n\n{r.text[:8000]}"
        else:
            response_text = f"Request failed: {error_msg}"

    return render_template_string(
        FLOW_HTML,
        flow=type("F", (), flow),
        method=method,
        url=url,
        headers=headers_text,
        body=body_text,
        response=response_text,
    )


@app.route("/export/csv")
def export_csv():
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow([
        "ID", "Time", "Method", "URL", "Status", "Risk",
        "Params", "Flags", "Response_Size"
    ])
    for r in SCAN_RESULTS:
        cw.writerow([
            r["id"], r["time"], r["method"], r["url"],
            r["status"], r["risk"], r.get("params", ""), r.get("flags", ""),
            len(r.get("raw_response", "")),
        ])

    out = io.BytesIO()
    out.write(si.getvalue().encode())
    out.seek(0)
    return send_file(out, mimetype="text/csv", as_attachment=True, download_name="interceptpro.csv")

@app.route("/export/pdf")
def export_pdf():

    buffer = io.BytesIO()

    doc = SimpleDocTemplate(buffer)

    styles = getSampleStyleSheet()

    elements = []

    title = Paragraph("InterceptPro Security Scan Report", styles['Title'])

    elements.append(title)

    data = [["ID","Method","URL","Status","Risk","Flags"]]

    for r in SCAN_RESULTS:
        data.append([
            r["id"],
            r["method"],
            r["url"][:60],
            r["status"],
            r["risk"],
            r["flags"][:80]
        ])

    table = Table(data)

    table.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.grey),
        ("GRID",(0,0),(-1,-1),1,colors.black),
    ]))

    elements.append(table)

    doc.build(elements)

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="interceptpro_report.pdf",
        mimetype="application/pdf"
    )

@app.route("/logo.svg")
def logo():
    return Response(
        '<svg width="64" height="64" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">'
        '<rect x="4" y="4" width="56" height="56" rx="16" fill="#020617" stroke="#22c55e" stroke-width="2"/>'
        '<text x="32" y="40" text-anchor="middle" font-size="16" fill="#22c55e" font-weight="bold">IP</text>'
        '</svg>',
        mimetype="image/svg+xml",
    )


# ---------------- DIRECTORY BRUTEFORCE ----------------

def directory_bruteforce(base_url):

    common_dirs = [
        "admin",
        "login",
        "dashboard",
        "config",
        "backup",
        "uploads",
        "api",
        "panel"
    ]

    results = []

    for d in common_dirs:
        url = base_url.rstrip("/") + "/" + d

        try:
            r = requests.get(url, timeout=6)

            if r.status_code in [200, 301, 302, 403]:
                results.append(url)

        except:
            pass

    return results


# ---------------- SUBDOMAIN DISCOVERY ----------------

def discover_subdomains(domain):

    subdomains = [
        "admin",
        "api",
        "dev",
        "test",
        "staging",
        "mail",
        "portal"
    ]

    found = []

    for sub in subdomains:
        url = f"http://{sub}.{domain}"

        try:
            r = requests.get(url, timeout=5)

            if r.status_code < 500:
                found.append(url)

        except:
            pass

    return found


# ----------------- TEMPLATES -----------------
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>InterceptPro</title>
  <link rel="icon" href="{{ url_for('logo') }}">
  <style>

  .flag-tag{
    display:inline-block;
    padding:3px 8px;
    margin:2px;
    border-radius:6px;
    font-size:11px;
    font-weight:500;
}

.flag-high{
    background:#7f1d1d;
    color:#fecaca;
}

.flag-medium{
    background:#78350f;
    color:#fed7aa;
}

.flag-info{
    background:#1e3a8a;
    color:#bfdbfe;
}

.flag-tech{
    background:#14532d;
    color:#bbf7d0;
}

    *{box-sizing:border-box}
    body{
        margin:0;
        font-family:Segoe UI,system-ui;
        background:#020617;
        color:#e5e7eb;
    }
    header{
        height:60px;
        padding:0 28px;
        display:flex;
        align-items:center;
        justify-content:space-between;
        border-bottom:1px solid #111827;
        background:rgba(2,6,23,.96);
        backdrop-filter:blur(14px);
        position:sticky;
        top:0;
        z-index:20;
    }
    .logo-wrap{
        display:flex;
        align-items:center;
        gap:10px;
        font-weight:700;
        letter-spacing:.18em;
    }
    .nav-right{
        display:flex;
        gap:10px;
        align-items:center;
    }
    .nav-btn{
        border-radius:999px;
        padding:6px 14px;
        font-size:13px;
        border:1px solid #1f2937;
        background:#020617;
        color:#e5e7eb;
        text-decoration:none;
        cursor:pointer;
    }
    .proxy-pill{
        border-radius:999px;
        padding:6px 14px;
        border:1px solid #1f2937;
        font-size:13px;
        display:flex;
        align-items:center;
        gap:6px;
        background:#020617;
        color:#e5e7eb;
    }
    .proxy-pill span{
        font-size:11px;
        padding:2px 8px;
        border-radius:999px;
        border:1px solid #1f2937;
    }
    .proxy-on{background:#064e3b;color:#bbf7d0;border-color:#22c55e;}
    .proxy-off{background:#111827;color:#9ca3af;}
    main{
        padding:18px 28px 28px;
        max-width:1600px;
        margin:0 auto;
    }
    .card{
        background:#020617;
        border-radius:16px;
        border:1px solid #111827;
        box-shadow:0 24px 60px rgba(0,0,0,.85);
        padding:18px 18px 16px;
        margin-bottom:16px;
    }
    .top-row{
        display:flex;
        justify-content:space-between;
        align-items:flex-start;
        gap:12px;
        flex-wrap:wrap;
    }
    .target-input{
        width:320px;
        max-width:100%;
        padding:10px 14px;
        border-radius:999px;
        border:1px solid #1f2937;
        background:#020617;
        color:#e5e7eb;
    }
    select{
        padding:10px 12px;
        border-radius:999px;
        border:1px solid #1f2937;
        background:#020617;
        color:#e5e7eb;
        min-width:110px;
    }
    button{
        padding:10px 18px;
        border-radius:999px;
        border:none;
        background:#22c55e;
        color:#020617;
        font-weight:600;
        cursor:pointer;
        font-size:13px;
    }
    .btn-danger{background:#ef4444;color:#f9fafb;}
    .btn-ghost{
        background:#020617;
        color:#e5e7eb;
        border:1px solid #1f2937;
    }
    .meta-line{
        margin-top:10px;
        font-size:12px;
        color:#9ca3af;
    }
    .filters-row{
        display:flex;
        justify-content:space-between;
        align-items:flex-end;
        gap:12px;
        flex-wrap:wrap;
        margin-bottom:12px;
    }
    .filters-left{
        display:flex;
        gap:8px;
        flex-wrap:wrap;
        align-items:flex-end;
    }
    .field-label{
        font-size:12px;
        color:#9ca3af;
        margin-bottom:2px;
    }
    .search-input{
        padding:10px 14px;
        border-radius:999px;
        border:1px solid #1f2937;
        background:#020617;
        color:#e5e7eb;
        min-width:240px;
    }
    .btn-link{
        border-radius:999px;
        padding:8px 14px;
        border:1px solid #1f2937;
        background:#020617;
        color:#e5e7eb;
        font-size:12px;
        text-decoration:none;
        display:inline-block;
    }
    .btn-export{
        border-color:#22c55e;
        color:#22c55e;
    }
    table{
        width:100%;
        border-collapse:collapse;
        font-size:13px;
    }
    th,td{
        padding:10px 10px;
        border-bottom:1px solid #111827;
        text-align:left;
    }
    th{
        font-weight:500;
        color:#9ca3af;
        font-size:12px;
    }
    tbody tr:hover{
        background:#020617;
    }
    .col-id{width:40px;}
    .col-time{width:80px;}
    .col-method{width:70px;}
    .col-status{width:70px;}
    .col-risk{width:80px;}
    .col-params{width:220px;}
    .col-flags{width:320px;}
    .col-actions{width:80px;text-align:right;}
    .status-ok{color:#22c55e;}
    .status-err{color:#f97316;}
    .risk-pill{
        padding:3px 10px;
        border-radius:999px;
        font-size:11px;
        display:inline-block;
    }
    .risk-high{background:#7f1d1d;color:#fecaca;}
    .risk-medium{background:#78350f;color:#fed7aa;}
    .risk-low{background:#14532d;color:#bbf7d0;}
    .params-cell{
        max-width:220px;
        white-space:nowrap;
        overflow:hidden;
        text-overflow:ellipsis;
        font-size:12px;
        color:#e5e7eb;
    }
    .flags-cell{
        max-width:320px;
        white-space:nowrap;
        overflow:hidden;
        text-overflow:ellipsis;
        font-size:12px;
        color:#e5e7eb;
    }
    .details-link{
        color:#22c55e;
        text-decoration:none;
        font-size:12px;
    }
  </style>

  {% if scanning %}
  <script>
    // auto refresh while scanning
    setTimeout(function(){ window.location.reload(); }, 2000);
  </script>
  {% endif %}
</head>
<body>

<header>
  <div class="logo-wrap">
    <img src="{{ url_for('logo') }}" width="26" height="26">
    INTERCEPTPRO
  </div>
  <div class="nav-right">
    <a href="{{ url_for('index') }}" class="nav-btn">Dashboard</a>
    <a href="{{ url_for('history') }}" class="nav-btn">History</a>
    <form method="post" action="{{ url_for('toggle_proxy') }}">
      <button class="proxy-pill" type="submit">
        Proxy:
        {% if proxy_enabled %}
          <span class="proxy-on">ON</span>
        {% else %}
          <span class="proxy-off">OFF</span>
        {% endif %}
      </button>
    </form>
  </div>
</header>

<main>

  <div class="card">
    <div class="top-row">
      <form method="post" action="{{ url_for('scan') }}" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
        <input class="target-input" name="target" placeholder="https://example.com" required>
        <select name="mode">
          <option value="single">Single</option>
          <option value="browser">Browser</option>
          <option value="crawler">Crawler</option>
        </select>
        <button type="submit">Start Scan</button>
      </form>

      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
        {% if scanning %}
        <form method="post" action="{{ url_for('stop') }}">
          <button type="submit" class="btn-danger">Stop</button>
        </form>
        {% endif %}
        <form method="post" action="{{ url_for('reset') }}">
          <button type="submit" class="btn-ghost">New Project</button>
        </form>
      </div>
    </div>

    <div class="meta-line">
      Target: {{ target }} | Mode: {{ mode }} | Results: {{ total }}
    </div>
  </div>

  <div class="card">
    <form method="get" class="filters-row">
      <div class="filters-left">
        <div>
          <div class="field-label">Method</div>
          <select name="method">
            <option value="">Any</option>
            <option value="GET" {% if method_filter=='GET' %}selected{% endif %}>GET</option>
          </select>
        </div>
        <div>
          <div class="field-label">Status</div>
          <select name="status">
            <option value="">Any</option>
            <option value="2" {% if status_group=='2' %}selected{% endif %}>2xx</option>
            <option value="3" {% if status_group=='3' %}selected{% endif %}>3xx</option>
            <option value="4" {% if status_group=='4' %}selected{% endif %}>4xx</option>
            <option value="5" {% if status_group=='5' %}selected{% endif %}>5xx</option>
          </select>
        </div>
        <div>
          <br>
          <button type="submit">Filter</button>
        </div>
        <div>
          <br>
          <a href="{{ url_for('index') }}" class="btn-link">Clear</a>
        </div>
        <div>
          <div class="field-label">Search URL</div>
          <input class="search-input" type="text" name="q" placeholder="path, file, keyword..." value="{{ q }}">
        </div>
      </div>

      <div>
        <a href="{{ url_for('export_csv') }}" class="btn-link btn-export">Export CSV</a>
        <a href="{{ url_for('export_pdf') }}" class="btn-link btn-export">
Export PDF
</a>
      </div>
    </form>

    <table>
      <thead>
        <tr>
          <th class="col-id">ID</th>
          <th class="col-time">Time</th>
          <th class="col-method">Method</th>
          <th>URL</th>
          <th class="col-status">Status</th>
          <th class="col-risk">Risk</th>
          <th class="col-params">Params</th>
          <th class="col-flags">Flags / Notes</th>
          <th class="col-actions"></th>
        </tr>
      </thead>
      <tbody>
      {% for r in rows %}
        <tr>
          <td class="col-id">{{ r.id }}</td>
          <td class="col-time">{{ r.time }}</td>
          <td class="col-method">{{ r.method }}</td>
          <td>{{ r.url }}</td>
          <td class="col-status">
            {% if r.status is not none and r.status < 400 %}
              <span class="status-ok">{{ r.status }}</span>
            {% elif r.status is not none %}
              <span class="status-err">{{ r.status }}</span>
            {% else %}
              <span class="status-err">ERR</span>
            {% endif %}
          </td>
          <td class="col-risk">
            {% if r.risk == 'High' %}
              <span class="risk-pill risk-high">High</span>
            {% elif r.risk == 'Medium' %}
              <span class="risk-pill risk-medium">Medium</span>
            {% else %}
              <span class="risk-pill risk-low">Low</span>
            {% endif %}
          </td>
          <td class="params-cell col-params" title="{{ r.params }}">{{ r.params }}</td>
          <td class="flags-cell col-flags" title="{{ r.flags }}">

            {% for flag in (r.flags or "").split(",") %}

            {% set f = flag.strip() %}

            {% if "SQL" in f or "Injection" in f %}
            <span class="flag-tag flag-high" onclick="showFlag('{{f}}')">
              {{f}}
              </span>

            {% elif "XSS" in f %}
            <span class="flag-tag flag-high" onclick="showFlag('{{f}}')">
              {{f}}
              </span>

            {% elif "Missing Security Header" in f or "Security Header Score" in f %}
            <span class="flag-tag flag-medium">{{f}}</span>

            {% elif "Detected" in f %}
            <span class="flag-tag flag-tech">{{f}}</span>

            {% else %}
            <span class="flag-tag flag-info">{{f}}</span>

            {% endif %}

            {% endfor %}

</td>
          <td class="col-actions"><a class="details-link" href="{{ url_for('flow', i=r.id) }}">Details</a></td>
        </tr>
      {% endfor %}
      {% if not rows %}
        <tr>
          <td colspan="9" style="padding:16px;color:#6b7280;text-align:center;">
            {% if scanning %}
              Scanning in progress… waiting for first results.
            {% else %}
              No results yet. Start a scan above.
            {% endif %}
          </td>
        </tr>
      {% endif %}
      </tbody>
    </table>

  </div>

</main>

</body>
</html>
"""

FLOW_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Flow :: InterceptPro</title>
<link rel="icon" href="{{ url_for('logo') }}">
<style>
*{box-sizing:border-box}
body{
    margin:0;
    font-family:Segoe UI,system-ui;
    background:#020617;
    color:#e5e7eb;
}
header{
    height:56px;
    padding:0 24px;
    display:flex;
    align-items:center;
    justify-content:space-between;
    background:#020617;
    border-bottom:1px solid #111827;
}
.h-left{display:flex;flex-direction:column;gap:4px}
.h-title{
    font-size:13px;
    text-transform:uppercase;
    letter-spacing:.18em;
}
.h-sub{
    font-size:11px;
    color:#9ca3af;
    max-width:840px;
    white-space:nowrap;
    overflow:hidden;
    text-overflow:ellipsis;
}
.badge{
    padding:4px 10px;
    border-radius:999px;
    border:1px solid #1f2937;
    font-size:11px;
}
main{
    padding:16px 20px 20px;
}
.panel{
    background:#020617;
    border-radius:14px;
    border:1px solid #111827;
    box-shadow:0 24px 60px rgba(0,0,0,.9);
}
.panel-header{
    padding:10px 14px;
    border-bottom:1px solid #111827;
    display:flex;
    justify-content:space-between;
    align-items:center;
}
.tabs{
    display:flex;
    gap:4px;
}
.tab-btn{
    padding:6px 12px;
    border-radius:999px;
    font-size:12px;
    border:1px solid #1f2937;
    background:#020617;
    color:#9ca3af;
    cursor:pointer;
}
.tab-btn.active{
    background:#22c55e;
    border-color:#22c55e;
    color:#020617;
}
.panel-body{
    padding:12px 14px 14px;
}
.input-row{
    display:flex;
    gap:8px;
    margin-bottom:8px;
}
.method-select{
    width:110px;
    padding:6px 10px;
    border-radius:10px;
    border:1px solid #111827;
    background:#020617;
    color:#e5e7eb;
}
.url-input{
    flex:1;
    padding:6px 10px;
    border-radius:10px;
    border:1px solid #111827;
    background:#020617;
    color:#e5e7eb;
    font-size:13px;
}
textarea{
    width:100%;
    min-height:200px;
    background:#020617;
    border-radius:10px;
    border:1px solid #111827;
    padding:8px 10px;
    color:#e5e7eb;
    font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    font-size:12px;
    resize:vertical;
    white-space:pre;
}
.small-label{
    font-size:11px;
    color:#9ca3af;
    margin:4px 0;
}
.btn{
    padding:7px 14px;
    border-radius:999px;
    border:none;
    background:#22c55e;
    color:#020617;
    font-weight:600;
    cursor:pointer;
    font-size:12px;
}
.btn-back{
    background:#020617;
    color:#e5e7eb;
    border:1px solid #1f2937;
    text-decoration:none;
    padding:7px 14px;
    border-radius:999px;
    font-size:12px;
}
.footer-note{
    font-size:11px;
    color:#6b7280;
    margin-top:8px;
}
#req-panel, #res-panel{
    display:none;
}
#req-panel.active, #res-panel.active{
    display:block;
}
</style>
</head>
<body>
<header>
  <div class="h-left">
      <div class="h-title">INTERCEPTPRO :: FLOW {{flow.id}}</div>
      <div class="h-sub">{{method}} {{url}}</div>
  </div>
  <div style="display:flex;gap:8px;align-items:center">
      <span class="badge">
        Status: {{flow.status if flow.status is not none else 'N/A'}}
      </span>
      <a href="{{ url_for('index') }}" class="btn-back">← Back</a>
  </div>
</header>

<main>
  <div class="panel">
    <div class="panel-header">
      <div class="tabs">
        <button type="button" id="tab-req" class="tab-btn active">Request</button>
        <button type="button" id="tab-res" class="tab-btn">Response</button>
      </div>
      <button form="req-form" class="btn">⟳ Resend Request</button>
    </div>

    <div class="panel-body">

      <div id="req-panel" class="active">
        <form id="req-form" method="post">
          <div class="input-row">
            <select name="method" class="method-select">
              <option value="GET" {% if method=='GET' %}selected{% endif %}>GET</option>
              <option value="POST" {% if method=='POST' %}selected{% endif %}>POST</option>
              <option value="PUT" {% if method=='PUT' %}selected{% endif %}>PUT</option>
              <option value="DELETE" {% if method=='DELETE' %}selected{% endif %}>DELETE</option>
            </select>
            <input class="url-input" name="url" value="{{url}}">
          </div>

          <div class="small-label">Request headers</div>
          <textarea name="headers" spellcheck="false">{{headers}}</textarea>

          <div class="small-label">Request body</div>
          <textarea name="body" spellcheck="false">{{body}}</textarea>
        </form>
      </div>

      <div id="res-panel">
        <div class="small-label">Response (preview)</div>
        <textarea readonly spellcheck="false">{{response}}</textarea>
        <div class="footer-note">
          Preview shows only a truncated response. Use on systems you own or have explicit permission to test.
        </div>
      </div>

    </div>
  </div>
</main>

<script>
  const tabReq = document.getElementById('tab-req');
  const tabRes = document.getElementById('tab-res');
  const panelReq = document.getElementById('req-panel');
  const panelRes = document.getElementById('res-panel');

  function activate(tab){
      if(tab === 'req'){
          tabReq.classList.add('active');
          tabRes.classList.remove('active');
          panelReq.classList.add('active');
          panelRes.classList.remove('active');
      }else{
          tabRes.classList.add('active');
          tabReq.classList.remove('active');
          panelRes.classList.add('active');
          panelReq.classList.remove('active');
      }
  }
  tabReq.onclick = () => activate('req');
  tabRes.onclick = () => activate('res');

  {% if response %}
  activate('res');
  {% endif %}
</script>

</body>
</html>
"""

HISTORY_HTML = """
<body style="background:#0f172a;color:white;font-family:Segoe UI;padding:32px">
<h3>Scan History</h3>
{% for h in history %}
<div style="border:1px solid #334155;border-radius:12px;padding:14px;margin-bottom:12px">
<b>{{h.target}}</b><br>
{{h.time}} | Mode: {{h.mode}}
<a href="{{ url_for('load_old', i=loop.index0) }}" style="float:right;color:#22c55e">Load</a>
</div>
{% endfor %}
<a href="{{ url_for('index') }}" style="color:#22c55e">← Back</a>
</body>
"""


if __name__ == "__main__":
    app.run(debug=True)


    