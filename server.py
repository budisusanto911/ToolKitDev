#!/usr/bin/env python3
"""
ToolKitDev - Main Application Server & API Gateway
Serves the Codexer.ai-styled frontend and handles:
- /api/correlations: Force-Directed Graph nodes and links
- /api/dashboard: Organization metrics and scoring
- /api/scan-sample-apk: Instant demo APK teardown
- /api/scan-apk: Multipart file upload APK analyzer
- /api/mcp: Multi-MCP connector status
- /api/history: Historical feature lineage search
- /api/chat: Context-grounded Q&A assistant
"""

import os
import io
import sys
import json
import cgi
import zipfile
import tempfile
import datetime
import time
import random
import re
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List, Optional

# Import engine modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from engine.apk_analyzer import ApkAnalyzer
from engine.correlation_graph import CorrelationGraphEngine
from engine.mcp_hub import McpHub
from engine.context_qa import ContextQaEngine
from engine.auth_manager import AuthManager
from engine.pdf_reporter import ExecutivePdfReporter
from engine.apk_comparator import ApkComparator
from engine.sca_scanner import ScaScanner
from engine.fix_pack_generator import FixPackGenerator
from engine.ipa_analyzer import IpaAnalyzer
from engine.frida_runner import FridaRunner

PORT = int(os.environ.get("PORT", 8080))
PUBLIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public")
UPLOADS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
SAMPLES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")

os.makedirs(UPLOADS_DIR, exist_ok=True)

# Initialize engines & caches
graph_engine = CorrelationGraphEngine(default_target="budisusanto911")
mcp_hub = McpHub()
qa_engine = ContextQaEngine()
auth_manager = AuthManager()
frida_runner = FridaRunner()
diff_cache: Dict[str, Any] = {}
sca_cache: Dict[str, Any] = {}


class ToolKitDevHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=PUBLIC_DIR, **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # API Routes
        if path == "/api/auth/me":
            token = self.headers.get("Authorization", "") or query.get("token", [""])[0]
            sess = auth_manager.get_session(token)
            if sess:
                self._send_json({"authenticated": True, "user": sess["user"], "token": sess["token"]})
            else:
                self._send_json({"authenticated": False}, status=401)
        elif path == "/api/correlations":
            self._send_json(graph_engine.get_correlation_graph())
        elif path == "/api/dashboard":
            self._send_json(graph_engine.get_dashboard_summary())
        elif path == "/api/mcp":
            self._send_json(mcp_hub.get_status())
        elif path == "/api/history":
            q_param = query.get("q", [""])[0]
            self._send_json(qa_engine.search_historical_features(q_param))
        elif path == "/api/scan-target":
            target_type = query.get("type", ["github"])[0]
            target_name = query.get("target", [""])[0]
            res = graph_engine.scan(target_type, target_name)
            self._send_json(res)
        elif path == "/api/repositories":
            self._send_json(graph_engine.get_repositories_list())
        elif path == "/api/vulnerabilities":
            self._send_json(graph_engine.get_vulnerabilities_list())
        elif path == "/api/dependencies":
            self._send_json(graph_engine.get_dependencies_list())
        elif path == "/api/scan-sample-apk":
            base_apk = os.path.join(UPLOADS_DIR, "base.apk")
            sample_apk = base_apk if os.path.exists(base_apk) else os.path.join(SAMPLES_DIR, "sample-debug.apk")
            if os.path.exists(sample_apk):
                analyzer = ApkAnalyzer(sample_apk)
                self._send_json(analyzer.analyze())
            else:
                self._send_json({"error": "Sample APK not found on server"}, status=404)
        elif path == "/api/scan-alfagift-aab" or path == "/api/scan-target-aab":
            target_aab = os.path.join(UPLOADS_DIR, "app (6).aab")
            if os.path.exists(target_aab):
                analyzer = ApkAnalyzer(target_aab)
                self._send_json(analyzer.analyze())
            else:
                self._send_json({"error": "Target AAB file not found in uploads"}, status=404)
        elif path == "/api/apk/decompiled":
            mode = query.get("mode", ["manifest"])[0]
            file_name = os.path.basename(query.get("file", [""])[0])
            target_path = self._resolve_apk_file(file_name)
            if not target_path:
                self._send_json({"error": "APK/AAB binary not found"}, status=404)
                return
            try:
                analyzer = ApkAnalyzer(target_path)
                if mode == "manifest":
                    xml_str = analyzer.get_reconstructed_manifest_xml()
                    self._send_json({"file": os.path.basename(target_path), "mode": "manifest", "content": xml_str})
                elif mode in ("java", "smali"):
                    files_list = analyzer.get_decompiled_sources(mode=mode, limit=80)
                    self._send_json({"file": os.path.basename(target_path), "mode": mode, "files": files_list})
                else:
                    self._send_json({"error": "Invalid mode"}, status=400)
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)
        elif path == "/api/apk/download":
            dl_type = query.get("type", ["apk"])[0]
            file_name = os.path.basename(query.get("file", [""])[0])
            target_path = self._resolve_apk_file(file_name)
            if not target_path:
                self._send_json({"error": "APK/AAB binary not found"}, status=404)
                return
            try:
                base_stem = os.path.splitext(os.path.basename(target_path))[0]
                if dl_type == "apk":
                    with open(target_path, "rb") as f:
                        raw_bytes = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/vnd.android.package-archive")
                    self.send_header("Content-Disposition", f'attachment; filename="{os.path.basename(target_path)}"')
                    self.send_header("Content-Length", str(len(raw_bytes)))
                    self.end_headers()
                    self.wfile.write(raw_bytes)
                elif dl_type in ("java", "smali"):
                    analyzer = ApkAnalyzer(target_path)
                    sources = analyzer.get_decompiled_sources(mode=dl_type, limit=120)
                    mem_zip = io.BytesIO()
                    with zipfile.ZipFile(mem_zip, "w", zipfile.ZIP_DEFLATED) as zf:
                        zf.writestr("AndroidManifest.xml", analyzer.get_reconstructed_manifest_xml())
                        prefix = "src/main/java/" if dl_type == "java" else "smali/"
                        for item in sources:
                            zf.writestr(prefix + item["path"], item["code"])
                    zip_bytes = mem_zip.getvalue()
                    out_name = f"{base_stem}-{dl_type}-code.zip"
                    self.send_response(200)
                    self.send_header("Content-Type", "application/zip")
                    self.send_header("Content-Disposition", f'attachment; filename="{out_name}"')
                    self.send_header("Content-Length", str(len(zip_bytes)))
                    self.end_headers()
                    self.wfile.write(zip_bytes)
                else:
                    self._send_json({"error": "Unsupported download type"}, status=400)
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)
        elif path == "/api/apk/export-pdf":
            file_name = query.get("file", [""])[0]
            auditor = query.get("auditor", ["ToolKitDev Autonomous SecOps"])[0]
            org = query.get("org", ["Enterprise Audit Target"])[0]
            scope = query.get("scope", ["OWASP MASVS, PCI-DSS & OJK Audit"])[0]
            is_inline = query.get("inline", ["0"])[0] in ("1", "true")

            analysis_data = None
            # 1. Check if an analysis json exists directly (e.g. alfagift_analysis.json)
            if file_name and file_name.endswith(".json"):
                json_path = os.path.join(PUBLIC_DIR, os.path.basename(file_name))
                if os.path.exists(json_path):
                    try:
                        with open(json_path, "r", encoding="utf-8") as fp:
                            analysis_data = json.load(fp)
                    except Exception as e:
                        sys.stderr.write(f"Error loading analysis json: {e}\n")

            # 2. Or check uploaded/sample apk/aab
            if not analysis_data:
                target_path = self._resolve_apk_file(os.path.basename(file_name) if file_name else "")
                if target_path and os.path.isfile(target_path):
                    try:
                        analyzer = ApkAnalyzer(target_path)
                        analysis_data = analyzer.analyze()
                    except Exception as e:
                        sys.stderr.write(f"Error analyzing apk for pdf: {e}\n")

            # 3. Fallback to alfagift_analysis.json
            if not analysis_data:
                alfagift_json = os.path.join(PUBLIC_DIR, "alfagift_analysis.json")
                if os.path.exists(alfagift_json):
                    try:
                        with open(alfagift_json, "r", encoding="utf-8") as fp:
                            analysis_data = json.load(fp)
                    except Exception as e:
                        sys.stderr.write(f"Error loading fallback json: {e}\n")

            if not analysis_data:
                self._send_json({"error": "No analysis data available to generate report"}, status=404)
                return

            try:
                reporter = ExecutivePdfReporter(analysis_data, auditor_name=auditor, organization=org, scope=scope)
                pdf_bytes = reporter.generate_pdf()
                target_pkg = analysis_data.get("metadata", {}).get("package_name") or "mobile-app"
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
                pdf_filename = f"ToolKitDev-Audit-Report-{target_pkg}-{timestamp}.pdf"

                disp = "inline" if is_inline else "attachment"
                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Disposition", f'{disp}; filename="{pdf_filename}"')
                self.send_header("Content-Length", str(len(pdf_bytes)))
                self.end_headers()
                self.wfile.write(pdf_bytes)
            except Exception as e:
                self._send_json({"error": f"Failed to generate PDF: {str(e)}"}, status=500)
        elif path == "/api/apk/diff-list":
            files_list = []
            if os.path.exists(PUBLIC_DIR):
                for f in sorted(os.listdir(PUBLIC_DIR)):
                    if f.endswith(".json") and "analysis" in f:
                        p = os.path.join(PUBLIC_DIR, f)
                        sz = os.path.getsize(p)
                        files_list.append({
                            "name": f"{f} (Pre-analyzed Baseline)",
                            "path": f,
                            "type": "JSON Analysis",
                            "folder": "public",
                            "size_fmt": f"{sz / (1024*1024):.2f} MB"
                        })
            if os.path.exists(UPLOADS_DIR):
                for f in sorted(os.listdir(UPLOADS_DIR)):
                    if f.endswith((".apk", ".aab", ".ipa")) and not f.startswith("."):
                        p = os.path.join(UPLOADS_DIR, f)
                        sz = os.path.getsize(p)
                        ftype = "IPA (iOS)" if f.endswith(".ipa") else ("AAB" if f.endswith(".aab") else "APK")
                        files_list.append({
                            "name": f,
                            "path": f"uploads/{f}",
                            "type": ftype,
                            "folder": "uploads",
                            "size_fmt": f"{sz / (1024*1024):.2f} MB"
                        })
            if os.path.exists(SAMPLES_DIR):
                for f in sorted(os.listdir(SAMPLES_DIR)):
                    if f.endswith((".apk", ".aab", ".ipa")):
                        p = os.path.join(SAMPLES_DIR, f)
                        sz = os.path.getsize(p)
                        ftype = "IPA (iOS)" if f.endswith(".ipa") else ("AAB" if f.endswith(".aab") else "APK")
                        files_list.append({
                            "name": f,
                            "path": f"samples/{f}",
                            "type": ftype,
                            "folder": "samples",
                            "size_fmt": f"{sz / (1024*1024):.2f} MB"
                        })
            self._send_json({"files": files_list})
        elif path == "/api/apk/diff":
            base_file = query.get("base", ["samples/sample-debug.apk"])[0]
            target_file = query.get("target", ["uploads/base.apk"])[0]

            cache_key = f"{base_file}:::_:::{target_file}"
            if cache_key in diff_cache:
                self._send_json(diff_cache[cache_key])
                return

            base_path = self._resolve_diff_target(base_file)
            target_path = self._resolve_diff_target(target_file)

            if not base_path or not target_path:
                self._send_json({"error": f"Base ({base_file}) or Target ({target_file}) not found"}, status=404)
                return

            try:
                comparator = ApkComparator(base_path, target_path)
                result = comparator.compare()
                diff_cache[cache_key] = result
                self._send_json(result)
            except Exception as e:
                self._send_json({"error": f"Comparison failed: {str(e)}"}, status=500)
        elif path == "/api/apk/sca":
            file_name = query.get("file", ["base.apk"])[0]
            resolved = self._resolve_diff_target(file_name)
            if not resolved or not os.path.isfile(resolved):
                resolved = os.path.join(UPLOADS_DIR, "base.apk")

            cache_key = resolved
            if cache_key in sca_cache:
                self._send_json(sca_cache[cache_key])
                return

            try:
                scanner = ScaScanner(resolved)
                res = scanner.scan()
                sca_cache[cache_key] = res
                self._send_json(res)
            except Exception as e:
                self._send_json({"error": f"SCA scan failed: {str(e)}"}, status=500)
        elif path == "/api/apk/fix-pack":
            file_name = query.get("file", [""])[0]
            analysis_data = None
            if file_name and file_name.endswith(".json"):
                json_path = os.path.join(PUBLIC_DIR, os.path.basename(file_name))
                if os.path.exists(json_path):
                    try:
                        with open(json_path, "r", encoding="utf-8") as fp:
                            analysis_data = json.load(fp)
                    except Exception as e:
                        sys.stderr.write(f"Error loading json for fix pack: {e}\n")
            if not analysis_data:
                target_path = self._resolve_apk_file(os.path.basename(file_name) if file_name else "")
                if target_path and os.path.isfile(target_path):
                    try:
                        if target_path.endswith(".ipa"):
                            analyzer = IpaAnalyzer(target_path)
                        else:
                            analyzer = ApkAnalyzer(target_path)
                        analysis_data = analyzer.analyze()
                    except Exception as e:
                        sys.stderr.write(f"Error analyzing for fix pack: {e}\n")
            if not analysis_data:
                alfagift_json = os.path.join(PUBLIC_DIR, "alfagift_analysis.json")
                if os.path.exists(alfagift_json):
                    try:
                        with open(alfagift_json, "r", encoding="utf-8") as fp:
                            analysis_data = json.load(fp)
                    except Exception:
                        pass
            if not analysis_data:
                self._send_json({"error": "No analysis data available to generate Fix Pack"}, status=404)
                return

            try:
                pkg = analysis_data.get("metadata", {}).get("package_name") or analysis_data.get("metadata", {}).get("bundle_id") or "app"
                app_name = analysis_data.get("metadata", {}).get("app_label") or analysis_data.get("metadata", {}).get("app_name") or pkg
                generator = FixPackGenerator(analysis_data, app_name=app_name)
                zip_data = generator.generate_zip_bytes()
                out_filename = f"ToolKitDev_FixPack_{pkg}.zip"
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Disposition", f'attachment; filename="{out_filename}"')
                self.send_header("Content-Length", str(len(zip_data)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(zip_data)
            except Exception as e:
                self._send_json({"error": f"Failed to generate Fix Pack: {str(e)}"}, status=500)
        elif path == "/api/ipa/inspect" or path == "/api/scan-sample-ipa":
            file_name = query.get("file", ["sample-ios.ipa"])[0]
            resolved = self._resolve_diff_target(file_name)
            if not resolved or not os.path.isfile(resolved):
                resolved = os.path.join(SAMPLES_DIR, "sample-ios.ipa")
            if not os.path.isfile(resolved):
                self._send_json({"error": "IPA sample or target file not found"}, status=404)
                return
            try:
                analyzer = IpaAnalyzer(resolved)
                result = analyzer.analyze()
                self._send_json(result)
            except Exception as e:
                self._send_json({"error": f"Failed to analyze IPA: {str(e)}"}, status=500)
        elif path == "/api/frida/scripts":
            self._send_json({"scripts": frida_runner.get_available_scripts()})
        elif path == "/api/billing/status":
            token = self.headers.get("Authorization", "") or query.get("token", [""])[0]
            sess = auth_manager.get_session(token)
            user_tier = sess.get("user", {}).get("tier", "Community Free") if sess else "Community Free"
            is_pro = user_tier.startswith("Enterprise") or (sess and sess.get("user", {}).get("is_premium", False))
            self._send_json({
                "tier": user_tier,
                "is_premium": is_pro,
                "scans_remaining": "Unlimited" if is_pro else 3,
                "features_unlocked": ["apk_diff", "sca_cve", "fix_pack", "ios_ipa", "formal_pdf", "ai_forensic_agent"] if is_pro else ["static_sast"]
            })
        elif path == "/api/mcp/oauth-url":
            conn = query.get("connector", ["github"])[0]
            cid = query.get("client_id", [""])[0]
            redirect_uri = query.get("redirect_uri", [f"http://localhost:{PORT}/api/mcp/oauth/callback"])[0]
            state = query.get("state", [""])[0]
            url = mcp_hub.get_oauth_url(conn, cid, redirect_uri, state)
            self._send_json({"auth_url": url, "connector": conn})
        elif path == "/api/mcp/oauth/callback":
            code = query.get("code", [""])[0]
            state = query.get("state", [""])[0]
            err = query.get("error", [""])[0]
            html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>ToolKitDev MCP - OAuth Authentication</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
        .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 24px 32px; max-width: 440px; text-align: center; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
        .spinner {{ width: 36px; height: 36px; border: 3px solid rgba(59,130,246,0.3); border-top-color: #3b82f6; border-radius: 50%; animation: spin 1s infinite linear; margin: 0 auto 16px; }}
        @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
        h2 {{ margin: 0 0 8px; font-size: 18px; color: #38bdf8; }}
        p {{ margin: 0 0 16px; color: #94a3b8; font-size: 13px; line-height: 1.5; }}
        code {{ background: #0f172a; padding: 4px 8px; border-radius: 6px; color: #a5b4fc; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="spinner"></div>
        <h2>Menghubungkan Akun OAuth...</h2>
        <p>Autentikasi provider berhasil diterima. ToolKitDev sedang memverifikasi token dan menyinkronkan profil.</p>
        <p><code>Code: {code[:12]}...</code></p>
    </div>
    <script>
        const authData = {{
            type: "mcp_oauth_response",
            code: "{code}",
            state: "{state}",
            error: "{err}"
        }};
        if (window.opener) {{
            window.opener.postMessage(authData, "*");
            setTimeout(() => window.close(), 1200);
        }} else {{
            localStorage.setItem("toolkitdev_oauth_pending", JSON.stringify(authData));
            setTimeout(() => window.location.href = "/", 1500);
        }}
    </script>
</body>
</html>"""
            body = html_content.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            # Fallback to static file serving
            super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/auth/login":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8")
            try:
                payload = json.loads(post_body) if post_body.strip().startswith("{") else {}
                email = payload.get("email", "")
                password = payload.get("password", "")
                res = auth_manager.login(email, password)
                self._send_json(res, status=200 if res.get("success") else 401)
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=400)

        elif path == "/api/auth/register":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8")
            try:
                payload = json.loads(post_body) if post_body.strip().startswith("{") else {}
                name = payload.get("name", "")
                email = payload.get("email", "")
                password = payload.get("password", "")
                res = auth_manager.register(name, email, password)
                self._send_json(res, status=200 if res.get("success") else 400)
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=400)

        elif path == "/api/auth/demo":
            res = auth_manager.login_demo()
            self._send_json(res)

        elif path == "/api/auth/oauth":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8")
            try:
                payload = json.loads(post_body) if post_body else {}
                provider = payload.get("provider", "github")
                res = auth_manager.login_oauth(provider, mcp_hub.get_status())
                self._send_json(res, status=200 if res.get("success") else 400)
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=400)

        elif path == "/api/auth/logout":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
            try:
                payload = json.loads(post_body) if post_body.strip().startswith("{") else {}
                token = self.headers.get("Authorization", "") or payload.get("token", "")
                res = auth_manager.logout(token)
                self._send_json(res)
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=400)

        elif path == "/api/chat":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8")
            try:
                payload = json.loads(post_body)
                q = payload.get("question", "")
                apk_ctx = payload.get("apk_context", None)
                res = qa_engine.answer_question(q, apk_ctx)
                self._send_json(res)
            except Exception as e:
                self._send_json({"error": str(e)}, status=400)

        elif path == "/api/chat/stream":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8")
            try:
                payload = json.loads(post_body) if post_body.strip().startswith("{") else {}
                q = payload.get("question", "")
                apk_ctx = payload.get("apk_context", None)
                res = qa_engine.answer_question(q, apk_ctx)
                full_text = res.get("answer", "")
                citations = res.get("citations", [])

                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()

                # Stream tokens
                tokens = re.findall(r"\S+|\n+", full_text)
                for idx, tok in enumerate(tokens):
                    is_nl = "\n" in tok
                    chunk = tok if is_nl else (tok + " ")
                    payload_chunk = json.dumps({"token": chunk})
                    self.wfile.write(f"data: {payload_chunk}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    if idx % 2 == 0:
                        time.sleep(0.012)

                terminal = json.dumps({"done": True, "citations": citations, "confidence": res.get("confidence", 0.95)})
                self.wfile.write(f"data: {terminal}\n\n".encode("utf-8"))
                self.wfile.flush()
            except Exception as e:
                self._send_json({"error": str(e)}, status=400)

        elif path == "/api/billing/checkout":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8")
            try:
                payload = json.loads(post_body) if post_body.strip().startswith("{") else {}
                plan = payload.get("plan", "pro")
                cycle = payload.get("cycle", "monthly")
                method = payload.get("method", "qris")
                token = self.headers.get("Authorization", "") or payload.get("token", "")

                inv_id = f"INV-TKD-{datetime.datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"
                amount = "$49.00 USD" if plan == "pro" else "$199.00 USD"

                # Upgrade session user to Pro
                sess = auth_manager.get_session(token)
                if sess and "user" in sess:
                    sess["user"]["tier"] = "Enterprise Pro"
                    sess["user"]["is_premium"] = True
                    sess["user"]["plan"] = plan

                self._send_json({
                    "success": True,
                    "invoice_id": inv_id,
                    "plan": plan.upper(),
                    "amount": amount,
                    "payment_method": method.upper(),
                    "status": "PAID_ACTIVE",
                    "activated_at": datetime.datetime.now().isoformat(),
                    "valid_until": (datetime.datetime.now() + datetime.timedelta(days=365 if cycle == 'annual' else 30)).strftime("%Y-%m-%d"),
                    "message": "Langganan Enterprise Pro berhasil diaktifkan. Seluruh kuota dan fitur otonom telah aktif!"
                })
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=400)

        elif path == "/api/frida/execute":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8")
            try:
                payload = json.loads(post_body) if post_body.strip().startswith("{") else {}
                script_id = payload.get("script_id", "ssl_unpinning")
                pkg = payload.get("package", "com.alfa.alfagift")
                session_result = frida_runner.execute_live_session(script_id, target_package=pkg)
                self._send_json(session_result)
            except Exception as e:
                self._send_json({"error": str(e)}, status=400)

        elif path == "/api/mcp/connect":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8")
            try:
                payload = json.loads(post_body)
                conn = payload.get("connector", "github")
                token = payload.get("token", "")
                code = payload.get("code", "")
                cid = payload.get("client_id", "")
                csecret = payload.get("client_secret", "")
                redirect_uri = payload.get("redirect_uri", f"http://localhost:{PORT}/api/mcp/oauth/callback")
                custom_target = payload.get("custom_target", "")

                if code and cid and csecret:
                    res = mcp_hub.exchange_oauth_code(conn, code, cid, csecret, redirect_uri)
                elif token:
                    res = mcp_hub.verify_and_connect(conn, token, custom_target)
                else:
                    res = {"success": False, "error": "Harap masukkan OAuth Access Token atau Client ID & Secret"}
                
                status_code = 200 if res.get("success") else 400
                self._send_json(res, status=status_code)
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)

        elif path == "/api/mcp/disconnect":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8")
            try:
                payload = json.loads(post_body)
                conn = payload.get("connector", "")
                res = mcp_hub.disconnect(conn)
                self._send_json(res)
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)

        elif path == "/api/apk/diff":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8")
            try:
                payload = json.loads(post_body) if post_body.strip().startswith("{") else {}
                base_file = payload.get("base", "samples/sample-debug.apk")
                target_file = payload.get("target", "uploads/base.apk")

                cache_key = f"{base_file}:::_:::{target_file}"
                if cache_key in diff_cache:
                    self._send_json(diff_cache[cache_key])
                    return

                base_path = self._resolve_diff_target(base_file)
                target_path = self._resolve_diff_target(target_file)

                if not base_path or not target_path:
                    self._send_json({"error": f"Base ({base_file}) or Target ({target_file}) not found"}, status=404)
                    return

                comparator = ApkComparator(base_path, target_path)
                result = comparator.compare()
                diff_cache[cache_key] = result
                self._send_json(result)
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)

        elif path == "/api/scan-apk":
            ctype, pdict = cgi.parse_header(self.headers.get("Content-Type", ""))
            if ctype == "multipart/form-data":
                pdict["boundary"] = bytes(pdict["boundary"], "utf-8")
                pdict["CONTENT-LENGTH"] = int(self.headers.get("Content-Length", 0))
                form = cgi.FieldStorage(
                    fp=self.rfile,
                    headers=self.headers,
                    environ={
                        "REQUEST_METHOD": "POST",
                        "CONTENT_TYPE": self.headers.get("Content-Type"),
                        "CONTENT_LENGTH": self.headers.get("Content-Length"),
                    }
                )

                if "apk" in form:
                    apk_item = form["apk"]
                    filename = apk_item.filename or "uploaded.apk"
                    # Clean filename
                    clean_name = os.path.basename(filename)
                    dest_path = os.path.join(UPLOADS_DIR, clean_name)
                    with open(dest_path, "wb") as f:
                        f.write(apk_item.file.read())

                    try:
                        if clean_name.lower().endswith(".ipa"):
                            analyzer = IpaAnalyzer(dest_path)
                        else:
                            analyzer = ApkAnalyzer(dest_path)
                        result = analyzer.analyze()
                        self._send_json(result)
                    except Exception as e:
                        self._send_json({"error": f"Failed to analyze package: {str(e)}"}, status=500)
                else:
                    self._send_json({"error": "No 'apk' file provided in form data"}, status=400)
            else:
                self._send_json({"error": "Invalid Content-Type, expected multipart/form-data"}, status=400)
        else:
            self._send_json({"error": "Not Found"}, status=404)

    def _resolve_diff_target(self, file_param: str) -> str:
        """Resolve a file path or filename to an absolute path for diff/SCA."""
        if not file_param:
            return ""
        if os.path.isabs(file_param) and os.path.isfile(file_param):
            return file_param
        if os.path.isfile(file_param):
            return os.path.abspath(file_param)
        clean = os.path.basename(file_param)
        candidates = [
            os.path.join(PUBLIC_DIR, clean),
            os.path.join(UPLOADS_DIR, clean),
            os.path.join(SAMPLES_DIR, clean),
            os.path.join(PUBLIC_DIR, "alfagift_analysis.json")
        ]
        for c in candidates:
            if os.path.isfile(c):
                return c
        return ""

    def _resolve_apk_file(self, file_name: str) -> str:
        """Resolve an APK/AAB/IPA filename in uploads/ or samples/, falling back to base.apk or sample-debug.apk."""
        candidates = []
        if file_name:
            candidates.append(os.path.join(UPLOADS_DIR, file_name))
            candidates.append(os.path.join(SAMPLES_DIR, file_name))
            if file_name.endswith(".ipa"):
                candidates.append(os.path.join(SAMPLES_DIR, "sample-ios.ipa"))
        candidates.append(os.path.join(UPLOADS_DIR, "base.apk"))
        candidates.append(os.path.join(SAMPLES_DIR, "sample-debug.apk"))
        candidates.append(os.path.join(SAMPLES_DIR, "sample-ios.ipa"))
        for c in candidates:
            if os.path.isfile(c):
                return c
        return ""

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def _send_json(self, data, status=200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Clean logging
        sys.stderr.write(f"[ToolKitDev API] {self.address_string()} - {format % args}\n")


def run():
    server_address = ("0.0.0.0", PORT)
    httpd = HTTPServer(server_address, ToolKitDevHandler)
    print(f"🚀 ToolKitDev AI Server running at http://localhost:{PORT}")
    print(f"📁 Public root: {PUBLIC_DIR}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        httpd.server_close()


if __name__ == "__main__":
    run()

