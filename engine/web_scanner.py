#!/usr/bin/env python3
"""
ToolKitDev - Autonomous Web Application Security Scanner & DevSecOps Gate
Performs deep black-box and grey-box security assessments on web targets:
- OWASP Top 10 (2021) & ASVS v4.0 evaluation
- TLS/SSL Configuration, Certificate validation & Protocol enforcement
- HTTP Security Headers analysis (CSP, HSTS, X-Frame-Options, etc.)
- Cookie security auditing (HttpOnly, Secure, SameSite)
- CORS misconfiguration probing (Wildcards, Origin Reflection & Credentials)
- Sensitive files & exposed administrative endpoints discovery
- Information leakage & technology fingerprinting (Server, X-Powered-By)
- Client-side static secrets & DOM mixed-content inspection
"""

import os
import re
import ssl
import json
import socket
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

class WebSecurityScanner:
    """Enterprise-grade Autonomous Web Application Security Scanner."""

    USER_AGENT = "ToolKitDev-SecOps-Auditor/2.0 (+https://toolkitdev.ai/bot)"

    # Common sensitive and administrative paths to audit
    SENSITIVE_PATHS = [
        {"path": "/.env", "title": "Exposed Environment File (.env)", "severity": "CRITICAL", "category": "A05:2021-Security Misconfiguration", "cwe": "CWE-538", "indicator": "APP_KEY="},
        {"path": "/.env.local", "title": "Exposed Local Environment File (.env.local)", "severity": "CRITICAL", "category": "A05:2021-Security Misconfiguration", "cwe": "CWE-538", "indicator": "="},
        {"path": "/.git/HEAD", "title": "Exposed Git Repository Root (/.git/HEAD)", "severity": "CRITICAL", "category": "A05:2021-Security Misconfiguration", "cwe": "CWE-538", "indicator": "ref: refs/"},
        {"path": "/.git/config", "title": "Exposed Git Repository Configuration", "severity": "CRITICAL", "category": "A05:2021-Security Misconfiguration", "cwe": "CWE-538", "indicator": "[core]"},
        {"path": "/actuator/health", "title": "Exposed Spring Boot Actuator Health", "severity": "LOW", "category": "A05:2021-Security Misconfiguration", "cwe": "CWE-200", "indicator": "status"},
        {"path": "/actuator/env", "title": "Exposed Spring Boot Actuator Environment", "severity": "CRITICAL", "category": "A05:2021-Security Misconfiguration", "cwe": "CWE-200", "indicator": "propertySources"},
        {"path": "/swagger-ui.html", "title": "Exposed Swagger UI API Documentation", "severity": "LOW", "category": "A05:2021-Security Misconfiguration", "cwe": "CWE-200", "indicator": "swagger"},
        {"path": "/openapi.json", "title": "Public OpenAPI Schema", "severity": "LOW", "category": "A05:2021-Security Misconfiguration", "cwe": "CWE-200", "indicator": "openapi"},
        {"path": "/v2/api-docs", "title": "Public Springfox API Documentation", "severity": "LOW", "category": "A05:2021-Security Misconfiguration", "cwe": "CWE-200", "indicator": "swagger"},
        {"path": "/phpinfo.php", "title": "Exposed PHP Information Script (phpinfo.php)", "severity": "HIGH", "category": "A05:2021-Security Misconfiguration", "cwe": "CWE-200", "indicator": "PHP Version"},
        {"path": "/.DS_Store", "title": "Exposed macOS Metadata File (.DS_Store)", "severity": "MEDIUM", "category": "A05:2021-Security Misconfiguration", "cwe": "CWE-538", "indicator": "Bud1"},
        {"path": "/robots.txt", "title": "Exposed robots.txt (Disallowed Endpoints)", "severity": "LOW", "category": "A05:2021-Security Misconfiguration", "cwe": "CWE-200", "indicator": "Disallow:"},
    ]

    SECRET_REGEXES = {
        "Google API / Firebase Key": r"AIza[0-9A-Za-z-_]{35}",
        "AWS Access Key ID": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "Generic Private Key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "Slack Bot/Webhook Token": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24}",
        "JWT Token": r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"
    }

    def __init__(self, target_url: str, timeout: int = 8):
        self.raw_target = target_url.strip()
        self.timeout = timeout
        
        # Ensure scheme
        if not self.raw_target.startswith(("http://", "https://")):
            self.target_url = "https://" + self.raw_target
        else:
            self.target_url = self.raw_target

        parsed = urllib.parse.urlparse(self.target_url)
        self.scheme = parsed.scheme
        self.hostname = parsed.hostname or ""
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        self.path = parsed.path or "/"

        self.ip_address: str = ""
        self.landing_headers: Dict[str, str] = {}
        self.landing_cookies: List[str] = []
        self.landing_html: str = ""
        self.landing_status: int = 0
        self.findings: List[Dict[str, Any]] = []

    def scan(self) -> Dict[str, Any]:
        """Executes full autonomous web security assessment."""
        # 1. Resolve DNS & IP
        self._resolve_host()

        # 2. Inspect TLS/SSL Certificate
        ssl_info = self._audit_ssl_tls()

        # 3. Request Landing Page
        self._fetch_landing_page()

        # 4. Audit Security Headers
        self._audit_security_headers()

        # 5. Audit Information Leakage (Server, Powered-By)
        self._audit_information_leakage()

        # 6. Audit Cookie Security Flags
        self._audit_cookies()

        # 7. Audit CORS Misconfigurations
        cors_info = self._audit_cors()

        # 8. Probe Sensitive Paths & Admin Surfaces
        sensitive_results = self._probe_sensitive_paths()

        # 9. Audit Client-side DOM & Secrets
        client_secrets = self._audit_client_side_secrets()

        # 10. Calculate Score & Posture
        score, posture = self._calculate_security_score()

        return {
            "platform": "web",
            "file_info": {
                "name": self.hostname,
                "url": self.target_url,
                "ip_address": self.ip_address,
                "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            "metadata": {
                "app_name": f"Web Application ({self.hostname})",
                "package_name": self.hostname,
                "version_name": "Live Web App",
                "bundle_id": self.hostname,
                "target_url": self.target_url,
                "ip_address": self.ip_address,
                "http_status": self.landing_status
            },
            "security_score": score,
            "security_posture": posture,
            "ssl_tls": ssl_info,
            "cors": cors_info,
            "sensitive_paths_probed": sensitive_results,
            "client_secrets_found": client_secrets,
            "findings": self.findings,
            "owasp_summary": self._group_owasp()
        }

    def _resolve_host(self):
        try:
            self.ip_address = socket.gethostbyname(self.hostname)
        except Exception:
            self.ip_address = "Unknown / Unresolved"

    def _fetch_landing_page(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            self.target_url,
            headers={"User-Agent": self.USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*"}
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                self.landing_status = resp.status
                self.landing_headers = {k.lower(): v for k, v in resp.headers.items()}
                self.landing_cookies = resp.headers.get_all("Set-Cookie") or []
                raw_bytes = resp.read(1024 * 512) # Read up to 512 KB
                self.landing_html = raw_bytes.decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            self.landing_status = e.code
            self.landing_headers = {k.lower(): v for k, v in e.headers.items()}
            self.landing_cookies = e.headers.get_all("Set-Cookie") or []
        except Exception as e:
            self._add_finding(
                finding_id="WEB-NET-ERR",
                title="Target Connection Unreachable",
                severity="HIGH",
                category="A05:2021-Security Misconfiguration",
                cwe="CWE-1188",
                description=f"Gagal melakukan koneksi HTTP ke {self.target_url}: {e}",
                recommendation="Pastikan hostname valid, server online, dan firewall tidak memblokir probe keamanan."
            )

    def _audit_ssl_tls(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {"https_enforced": self.scheme == "https", "valid_cert": False}

        if self.scheme != "https":
            self._add_finding(
                finding_id="WEB-TLS-NO-HTTPS",
                title="Cleartext HTTP Scheme Enforced (No Transport Encryption)",
                severity="CRITICAL",
                category="A02:2021-Cryptographic Failures",
                cwe="CWE-319",
                description="Aplikasi web melayani request melalui protokol HTTP tidak terenkripsi. Seluruh traffic, kredensial, dan data sesi dapat di-sniff atau dimanipulasi via serangan Man-In-The-Middle (MITM).",
                recommendation="Konfigurasikan TLS v1.3 / v1.2 dan alihkan seluruh traffic HTTP (port 80) secara permanen ke HTTPS (port 443) dengan HTTP 301 Redirect."
            )
            return info

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    info["valid_cert"] = True
                    info["tls_version"] = ssock.version()
                    info["cipher"] = ssock.cipher()
                    info["subject"] = dict(x[0] for x in cert.get("subject", []))
                    info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    info["not_after"] = cert.get("notAfter")
        except ssl.SSLCertVerificationError as e:
            self._add_finding(
                finding_id="WEB-TLS-INVALID-CERT",
                title="Invalid / Self-Signed SSL/TLS Certificate",
                severity="HIGH",
                category="A02:2021-Cryptographic Failures",
                cwe="CWE-295",
                description=f"Sertifikat SSL/TLS server gagal diverifikasi: {e}. Pengguna akan melihat peringatan keamanan merah di browser.",
                recommendation="Gunakan sertifikat SSL/TLS valid yang diterbitkan oleh Certificate Authority (CA) tepercaya (misal Let's Encrypt, DigiCert)."
            )
        except Exception as e:
            info["error"] = str(e)

        return info

    def _audit_security_headers(self):
        """Audits essential browser defense headers."""
        # 1. Content-Security-Policy (CSP)
        csp = self.landing_headers.get("content-security-policy")
        if not csp:
            self._add_finding(
                finding_id="WEB-HDR-NO-CSP",
                title="Missing Content-Security-Policy (CSP)",
                severity="HIGH",
                category="A05:2021-Security Misconfiguration",
                cwe="CWE-1021",
                description="Header Content-Security-Policy tidak ditemukan. CSP sangat penting untuk mencegah injeksi skrip jahat (Cross-Site Scripting / XSS), clickjacking, dan data injection attacks.",
                recommendation="Implementasikan header CSP yang ketat, misalnya: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';"
            )
        elif "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
            self._add_finding(
                finding_id="WEB-HDR-WEAK-CSP",
                title="Weak CSP Configuration ('unsafe-inline' / 'unsafe-eval')",
                severity="MEDIUM",
                category="A05:2021-Security Misconfiguration",
                cwe="CWE-1021",
                description="Content-Security-Policy mengizinkan 'unsafe-inline' atau 'unsafe-eval', yang melemahkan proteksi terhadap eksekusi script XSS.",
                recommendation="Gunakan nonce-based atau hash-based CSP untuk inline scripts dan hindari penggunaan eval() dalam kode JavaScript."
            )

        # 2. Strict-Transport-Security (HSTS)
        hsts = self.landing_headers.get("strict-transport-security")
        if not hsts and self.scheme == "https":
            self._add_finding(
                finding_id="WEB-HDR-NO-HSTS",
                title="Missing HTTP Strict Transport Security (HSTS)",
                severity="MEDIUM",
                category="A02:2021-Cryptographic Failures",
                cwe="CWE-319",
                description="Header Strict-Transport-Security (HSTS) tidak ditemukan. Browser dapat membiarkan user mengakses via HTTP sebelum dialihkan ke HTTPS, membuka celah SSL Stripping.",
                recommendation="Tambahkan header HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            )

        # 3. X-Frame-Options (Clickjacking)
        xfo = self.landing_headers.get("x-frame-options")
        if not xfo:
            self._add_finding(
                finding_id="WEB-HDR-NO-XFO",
                title="Missing X-Frame-Options (Clickjacking Risk)",
                severity="MEDIUM",
                category="A05:2021-Security Misconfiguration",
                cwe="CWE-1021",
                description="Header X-Frame-Options tidak ditemukan. Halaman web berpotensi disematkan di dalam <iframe> oleh situs penyerang untuk melakukan serangan UI Redressing / Clickjacking.",
                recommendation="Konfigurasikan header: X-Frame-Options: DENY atau X-Frame-Options: SAMEORIGIN"
            )

        # 4. X-Content-Type-Options (MIME Sniffing)
        xcto = self.landing_headers.get("x-content-type-options")
        if not xcto or xcto.lower() != "nosniff":
            self._add_finding(
                finding_id="WEB-HDR-NO-XCTO",
                title="Missing X-Content-Type-Options ('nosniff')",
                severity="LOW",
                category="A05:2021-Security Misconfiguration",
                cwe="CWE-79",
                description="Header X-Content-Type-Options tidak disetel ke 'nosniff'. Browser dapat menebak MIME type file yang diunggah dan mengeksekusi konten berbahaya sebagai HTML/JS.",
                recommendation="Tambahkan header: X-Content-Type-Options: nosniff"
            )

        # 5. Referrer-Policy
        ref_pol = self.landing_headers.get("referrer-policy")
        if not ref_pol:
            self._add_finding(
                finding_id="WEB-HDR-NO-REFERRER",
                title="Missing Referrer-Policy Header",
                severity="LOW",
                category="A05:2021-Security Misconfiguration",
                cwe="CWE-116",
                description="Header Referrer-Policy tidak didefinisikan. URL sensitif dengan parameter query token berisiko bocor ke situs pihak ketiga saat pengguna mengklik tautan keluar.",
                recommendation="Tambahkan header: Referrer-Policy: strict-origin-when-cross-origin"
            )

    def _audit_information_leakage(self):
        """Checks for technology disclosure headers."""
        server = self.landing_headers.get("server")
        if server and any(char.isdigit() for char in server):
            self._add_finding(
                finding_id="WEB-INFO-SERVER",
                title=f"Detailed Server Version Disclosure ({server})",
                severity="LOW",
                category="A05:2021-Security Misconfiguration",
                cwe="CWE-200",
                description=f"Header 'Server' mengekspos versi software web server secara mendetail ({server}). Informasi ini mempermudah attacker memetakan celah CVE publik.",
                recommendation="Matikan penayangan versi server (misal 'server_tokens off;' di Nginx atau 'ServerSignature Off' di Apache)."
            )

        powered_by = self.landing_headers.get("x-powered-by")
        if powered_by:
            self._add_finding(
                finding_id="WEB-INFO-POWERED-BY",
                title=f"Technology Stack Disclosure (X-Powered-By: {powered_by})",
                severity="LOW",
                category="A05:2021-Security Misconfiguration",
                cwe="CWE-200",
                description=f"Header 'X-Powered-By' mengekspos framework backend ({powered_by}).",
                recommendation="Hapus header X-Powered-By di konfigurasi aplikasi web (misal 'app.disable('x-powered-by');' di Express)."
            )

    def _audit_cookies(self):
        """Audits Set-Cookie flags for security attributes."""
        for cookie_str in self.landing_cookies:
            parts = [p.strip() for p in cookie_str.split(";")]
            name_val = parts[0] if parts else "unknown_cookie"
            cookie_name = name_val.split("=")[0] if "=" in name_val else name_val

            attrs = [p.lower() for p in parts[1:]]

            is_secure = any(a == "secure" for a in attrs)
            is_httponly = any(a == "httponly" for a in attrs)
            has_samesite = any(a.startswith("samesite") for a in attrs)

            if not is_httponly:
                self._add_finding(
                    finding_id=f"WEB-COOKIE-NO-HTTPONLY-{cookie_name}",
                    title=f"Cookie '{cookie_name}' Missing HttpOnly Flag",
                    severity="MEDIUM",
                    category="A07:2021-Identification and Authentication Failures",
                    cwe="CWE-1004",
                    description=f"Cookie '{cookie_name}' tidak memiliki flag HttpOnly. Jika aplikasi mengalami kerentanan XSS, skrip penyerang dapat membaca nilai cookie ini via document.cookie.",
                    recommendation=f"Setel flag HttpOnly saat membuat cookie '{cookie_name}' di backend."
                )

            if not is_secure and self.scheme == "https":
                self._add_finding(
                    finding_id=f"WEB-COOKIE-NO-SECURE-{cookie_name}",
                    title=f"Cookie '{cookie_name}' Missing Secure Flag",
                    severity="MEDIUM",
                    category="A02:2021-Cryptographic Failures",
                    cwe="CWE-614",
                    description=f"Cookie '{cookie_name}' tidak memiliki flag Secure. Cookie ini berisiko ditransmisikan dalam jaringan plain-text yang tidak terenkripsi.",
                    recommendation=f"Pastikan flag Secure aktif pada cookie '{cookie_name}'."
                )

            if not has_samesite:
                self._add_finding(
                    finding_id=f"WEB-COOKIE-NO-SAMESITE-{cookie_name}",
                    title=f"Cookie '{cookie_name}' Missing SameSite Attribute",
                    severity="LOW",
                    category="A01:2021-Broken Access Control",
                    cwe="CWE-1275",
                    description=f"Cookie '{cookie_name}' tidak menyertakan atribut SameSite. Hal ini meningkatkan risiko Cross-Site Request Forgery (CSRF).",
                    recommendation=f"Setel SameSite=Lax atau SameSite=Strict pada cookie '{cookie_name}'."
                )

    def _audit_cors(self) -> Dict[str, Any]:
        """Probes for permissive Cross-Origin Resource Sharing (CORS) configurations."""
        cors_info = {"wildcard_origin": False, "reflects_origin": False}
        evil_origin = "https://evil-attacker-site.com"

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            self.target_url,
            headers={
                "User-Agent": self.USER_AGENT,
                "Origin": evil_origin,
                "Access-Control-Request-Method": "GET"
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                allow_origin = headers.get("access-control-allow-origin", "")
                allow_cred = headers.get("access-control-allow-credentials", "").lower() == "true"

                if allow_origin == evil_origin:
                    cors_info["reflects_origin"] = True
                    sev = "CRITICAL" if allow_cred else "HIGH"
                    self._add_finding(
                        finding_id="WEB-CORS-REFLECTED",
                        title="Vulnerable CORS Configuration: Arbitrary Origin Reflection",
                        severity=sev,
                        category="A01:2021-Broken Access Control",
                        cwe="CWE-942",
                        description=f"Server memantulkan origin penyerang ('{evil_origin}') ke Access-Control-Allow-Origin (Credentials: {allow_cred}). Penyerang dapat membaca respon sensitif pengguna via cross-origin AJAX request.",
                        recommendation="Whitelist domain origin secara ketat dan hindari memantulkan nilai header Origin sembarangan."
                    )
                elif allow_origin == "*":
                    cors_info["wildcard_origin"] = True
                    self._add_finding(
                        finding_id="WEB-CORS-WILDCARD",
                        title="Overly Permissive CORS Policy (Access-Control-Allow-Origin: *)",
                        severity="MEDIUM",
                        category="A01:2021-Broken Access Control",
                        cwe="CWE-942",
                        description="Access-Control-Allow-Origin disetel ke wildcard '*'. Setiap situs di internet diizinkan membaca respons dari endpoint ini.",
                        recommendation="Batasi Access-Control-Allow-Origin hanya ke domain aplikasi yang terpercaya."
                    )
        except Exception:
            pass

        return cors_info

    def _probe_sensitive_paths(self) -> List[Dict[str, Any]]:
        """Probes for critical files and exposed administrative endpoints."""
        discovered = []
        base_origin = f"{self.scheme}://{self.hostname}:{self.port}" if (self.port not in (80, 443)) else f"{self.scheme}://{self.hostname}"

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for item in self.SENSITIVE_PATHS:
            test_url = base_origin + item["path"]
            req = urllib.request.Request(test_url, headers={"User-Agent": self.USER_AGENT})
            try:
                with urllib.request.urlopen(req, timeout=4, context=ctx) as resp:
                    if resp.status == 200:
                        content_sample = resp.read(1024).decode("utf-8", errors="ignore")
                        indicator = item["indicator"]
                        if indicator in content_sample:
                            discovered.append({"path": item["path"], "status": resp.status})
                            self._add_finding(
                                finding_id=f"WEB-EXP-{item['path'].replace('/', '-').strip('-')}",
                                title=item["title"],
                                severity=item["severity"],
                                category=item["category"],
                                cwe=item["cwe"],
                                description=f"File sensitif terdeteksi dapat diakses publik di {test_url}. Konten file mengandung tanda unik ('{indicator}').",
                                recommendation=f"Blokir akses publik ke {item['path']} di reverse proxy/web server dan pastikan file sensitif tidak ditempatkan di web root directory."
                            )
            except Exception:
                pass

        return discovered

    def _audit_client_side_secrets(self) -> List[Dict[str, Any]]:
        """Audits landing HTML source for exposed API keys and mixed content."""
        secrets_found = []
        if not self.landing_html:
            return secrets_found

        # 1. Regex scanning for API Keys & Tokens
        for secret_name, pattern in self.SECRET_REGEXES.items():
            matches = re.findall(pattern, self.landing_html)
            if matches:
                sample = str(matches[0])[:12] + "..."
                secrets_found.append({"type": secret_name, "sample": sample})
                self._add_finding(
                    finding_id=f"WEB-SECRET-{secret_name.replace(' ', '-').upper()}",
                    title=f"Potential Hardcoded Secret in HTML/JS: {secret_name}",
                    severity="HIGH",
                    category="A02:2021-Cryptographic Failures",
                    cwe="CWE-798",
                    description=f"Ditemukan token atau API key dalam kode HTML frontend: {secret_name} ({sample}). Kunci ini dapat diekstraksi oleh siapa saja yang membuka halaman web.",
                    recommendation="Pindahkan operasi yang memerlukan kunci rahasia ke backend dan gunakan environment variables yang aman."
                )

        # 2. Mixed Content detection
        if self.scheme == "https":
            insecure_srcs = re.findall(r'(?:src|href)=["\']http://[^"\']+["\']', self.landing_html)
            if insecure_srcs:
                self._add_finding(
                    finding_id="WEB-MIXED-CONTENT",
                    title="Active/Passive Mixed Content Detected",
                    severity="MEDIUM",
                    category="A02:2021-Cryptographic Failures",
                    cwe="CWE-319",
                    description=f"Halaman HTTPS memuat resource eksternal via HTTP tidak terenkripsi ({len(insecure_srcs)} referensi ditemukan). Hal ini memicu pemblokiran browser atau serangan MITM.",
                    recommendation="Ganti seluruh URL resource (script, stylesheet, image) menjadi HTTPS atau relative protocol (//)."
                )

        return secrets_found

    def _add_finding(self, finding_id: str, title: str, severity: str, category: str, cwe: str, description: str, recommendation: str):
        self.findings.append({
            "id": finding_id,
            "title": title,
            "severity": severity,
            "category": category,
            "cwe": cwe,
            "description": description,
            "recommendation": recommendation
        })

    def _calculate_security_score(self) -> Tuple[int, str]:
        """Calculates security score 0-100 based on weighted penalties."""
        score = 100
        penalties = {
            "CRITICAL": 30,
            "HIGH": 15,
            "MEDIUM": 8,
            "LOW": 3
        }

        for f in self.findings:
            sev = f.get("severity", "LOW")
            score -= penalties.get(sev, 2)

        score = max(0, min(100, score))

        if score >= 85:
            posture = "EXCELLENT"
        elif score >= 70:
            posture = "GOOD"
        elif score >= 50:
            posture = "FAIR"
        elif score >= 30:
            posture = "POOR"
        else:
            posture = "CRITICAL"

        return score, posture

    def _group_owasp(self) -> Dict[str, int]:
        grouped: Dict[str, int] = {}
        for f in self.findings:
            cat = f.get("category", "Other")
            grouped[cat] = grouped.get(cat, 0) + 1
        return grouped

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://google.com"
    print(f"Scanning target: {target} ...")
    scanner = WebSecurityScanner(target)
    result = scanner.scan()
    print(json.dumps(result, indent=2))
