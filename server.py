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
import sys
import json
import cgi
import tempfile
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Import engine modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from engine.apk_analyzer import ApkAnalyzer
from engine.correlation_graph import CorrelationGraphEngine
from engine.mcp_hub import McpHub
from engine.context_qa import ContextQaEngine
from engine.auth_manager import AuthManager

PORT = int(os.environ.get("PORT", 8080))
PUBLIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public")
UPLOADS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
SAMPLES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")

os.makedirs(UPLOADS_DIR, exist_ok=True)

# Initialize engines
graph_engine = CorrelationGraphEngine(default_target="budisusanto911")
mcp_hub = McpHub()
qa_engine = ContextQaEngine()
auth_manager = AuthManager()


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
            sample_apk = os.path.join(SAMPLES_DIR, "sample-debug.apk")
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
                        analyzer = ApkAnalyzer(dest_path)
                        result = analyzer.analyze()
                        self._send_json(result)
                    except Exception as e:
                        self._send_json({"error": f"Failed to analyze APK: {str(e)}"}, status=500)
                else:
                    self._send_json({"error": "No 'apk' file provided in form data"}, status=400)
            else:
                self._send_json({"error": "Invalid Content-Type, expected multipart/form-data"}, status=400)
        else:
            self._send_json({"error": "Not Found"}, status=404)

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

