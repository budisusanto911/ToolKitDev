"""
ToolKitDev - Authentication & Session Manager
Provides user authentication, registration, demo account sign-in,
OAuth account linking with MCP Hub, and PBKDF2-HMAC-SHA256 password security.
"""

import os
import json
import time
import uuid
import hashlib
import secrets
from typing import Dict, Any, Optional

USERS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "users_auth.json")


class AuthManager:
    def __init__(self):
        self.users: Dict[str, Dict[str, Any]] = {}
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self._init_default_users()
        self._load_persisted_users()

    def _hash_password(self, password: str, salt: Optional[str] = None) -> Dict[str, str]:
        if not salt:
            salt = secrets.token_hex(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
        return {"salt": salt, "hash": dk.hex()}

    def _verify_password(self, password: str, salt: str, expected_hash: str) -> bool:
        calc = self._hash_password(password, salt)
        return secrets.compare_digest(calc["hash"], expected_hash)

    def _init_default_users(self):
        demo_pw = self._hash_password("Admin123!")
        admin_pw = self._hash_password("ToolKitDev2026!")

        self.users = {
            "budi.susanto@alfagift.id": {
                "id": "usr_budi_01",
                "name": "Budi Susanto",
                "email": "budi.susanto@alfagift.id",
                "username": "budisusanto911",
                "role": "Lead Security & Mobile Architect",
                "avatar": "https://avatars.githubusercontent.com/u/583231?v=4",
                "auth_provider": "local+github",
                "salt": demo_pw["salt"],
                "password_hash": demo_pw["hash"],
                "created_at": "2026-01-15T08:00:00Z"
            },
            "admin@toolkitdev.ai": {
                "id": "usr_admin_02",
                "name": "ToolKitDev Admin",
                "email": "admin@toolkitdev.ai",
                "username": "toolkitdev-admin",
                "role": "Platform Administrator",
                "avatar": "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=120&auto=format&fit=crop&q=80",
                "auth_provider": "local",
                "salt": admin_pw["salt"],
                "password_hash": admin_pw["hash"],
                "created_at": "2026-01-01T00:00:00Z"
            }
        }

    def _load_persisted_users(self):
        if os.path.exists(USERS_FILE):
            try:
                with open(USERS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    saved_users = data.get("users", {})
                    saved_sessions = data.get("sessions", {})
                    for email, u in saved_users.items():
                        self.users[email.lower()] = u
                    self.sessions.update(saved_sessions)
            except Exception as e:
                print(f"[AuthManager] Error loading {USERS_FILE}: {e}")

    def _save_persisted_users(self):
        try:
            with open(USERS_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "users": self.users,
                    "sessions": self.sessions
                }, f, indent=2)
        except Exception as e:
            print(f"[AuthManager] Error saving {USERS_FILE}: {e}")

    def _sanitize_user(self, user: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": user.get("id"),
            "name": user.get("name"),
            "email": user.get("email"),
            "username": user.get("username"),
            "role": user.get("role", "Developer & Security Analyst"),
            "avatar": user.get("avatar"),
            "auth_provider": user.get("auth_provider", "local")
        }

    def _create_session(self, user: Dict[str, Any]) -> Dict[str, Any]:
        token = f"tkd_sess_{secrets.token_urlsafe(24)}"
        sanitized = self._sanitize_user(user)
        self.sessions[token] = {
            "token": token,
            "user": sanitized,
            "created_at": int(time.time())
        }
        self._save_persisted_users()
        return {
            "success": True,
            "token": token,
            "user": sanitized
        }

    def login(self, identifier: str, password: str) -> Dict[str, Any]:
        ident = (identifier or "").strip().lower()
        if not ident or not password:
            return {"success": False, "error": "Email dan password wajib diisi."}

        # Match by email or username
        matched_user = self.users.get(ident)
        if not matched_user:
            for u in self.users.values():
                if u.get("username", "").lower() == ident:
                    matched_user = u
                    break

        if not matched_user:
            return {"success": False, "error": "Akun tidak ditemukan. Periksa kembali email Anda atau gunakan Akun Demo."}

        if not self._verify_password(password, matched_user["salt"], matched_user["password_hash"]):
            return {"success": False, "error": "Password yang Anda masukkan tidak sesuai."}

        return self._create_session(matched_user)

    def register(self, name: str, email: str, password: str) -> Dict[str, Any]:
        clean_name = (name or "").strip()
        clean_email = (email or "").strip().lower()

        if not clean_name:
            return {"success": False, "error": "Nama lengkap wajib diisi."}
        if not clean_email or "@" not in clean_email:
            return {"success": False, "error": "Format alamat email tidak valid."}
        if not password or len(password) < 8:
            return {"success": False, "error": "Password minimal harus terdiri dari 8 karakter."}

        if clean_email in self.users:
            return {"success": False, "error": "Alamat email sudah terdaftar. Silakan langsung masuk (Sign In)."}

        pw_data = self._hash_password(password)
        username = clean_email.split("@")[0]
        avatar_seed = urllib.parse_quote(clean_name)
        new_user = {
            "id": f"usr_{uuid.uuid4().hex[:8]}",
            "name": clean_name,
            "email": clean_email,
            "username": username,
            "role": "Security & Software Engineer",
            "avatar": f"https://ui-avatars.com/api/?name={avatar_seed}&background=2563eb&color=fff&bold=true",
            "auth_provider": "local",
            "salt": pw_data["salt"],
            "password_hash": pw_data["hash"],
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        self.users[clean_email] = new_user
        return self._create_session(new_user)

    def login_demo(self) -> Dict[str, Any]:
        demo_user = self.users.get("budi.susanto@alfagift.id")
        if not demo_user:
            self._init_default_users()
            demo_user = self.users["budi.susanto@alfagift.id"]
        return self._create_session(demo_user)

    def login_oauth(self, provider: str, mcp_status: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        prov = (provider or "github").lower()
        connectors = (mcp_status or {}).get("connectors", {})

        if prov == "github":
            gh = connectors.get("github", {})
            username = gh.get("auth_user") or "budisusanto911"
            name = gh.get("auth_name") or "Budi Susanto"
            avatar = gh.get("auth_avatar") or "https://avatars.githubusercontent.com/u/583231?v=4"
            email = f"{username}@users.noreply.github.com"
            role = "GitHub OAuth Verified Architect"
        elif prov in ("google", "google_docs"):
            gd = connectors.get("google_docs", {})
            email = gd.get("auth_user") or "budi.susanto@alfagift.id"
            name = "Budi Susanto (Google Workspace)"
            username = email.split("@")[0]
            avatar = gd.get("auth_avatar") or "https://ui-avatars.com/api/?name=Budi+Susanto&background=059669&color=fff&bold=true"
            role = "Google Workspace Verified Lead"
        else:
            return {"success": False, "error": f"Provider OAuth '{provider}' tidak didukung."}

        oauth_user = {
            "id": f"usr_oauth_{prov}_{username}",
            "name": name,
            "email": email,
            "username": username,
            "role": role,
            "avatar": avatar,
            "auth_provider": f"oauth_{prov}"
        }
        return self._create_session(oauth_user)

    def get_session(self, token: str) -> Optional[Dict[str, Any]]:
        clean_tok = (token or "").replace("Bearer ", "").strip()
        if not clean_tok:
            return None
        return self.sessions.get(clean_tok)

    def logout(self, token: str) -> Dict[str, Any]:
        clean_tok = (token or "").replace("Bearer ", "").strip()
        if clean_tok in self.sessions:
            del self.sessions[clean_tok]
            self._save_persisted_users()
        return {"success": True}


def urllib_parse_quote(text: str) -> str:
    from urllib.parse import quote
    return quote(text)

