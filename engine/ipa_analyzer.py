#!/usr/bin/env python3
"""
ToolKitDev - iOS (.ipa / .zip) Teardown & Security Inspector
Deconstructs iOS IPA packages and ZIP archives (Payload/*.app/, *.app/, *.xcarchive.zip,
or nested *.ipa), parses Info.plist & embedded.mobileprovision entitlements, audits bundled
X.509 SSL pinning certificates, inspects Mach-O binary security flags (PIE, ARC, Stack Canaries,
FairPlay CryptID, Weak Crypto, Anti-Jailbreak coverage), and generates actionable issue
suggestions & copy-pasteable Xcode/Swift remediations.
"""

import os
import io
import re
import struct
import zipfile
import plistlib
import tempfile
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple


class IpaAnalyzer:
    def __init__(self, ipa_path: str):
        self.ipa_path = ipa_path
        self.filename = os.path.basename(ipa_path)
        self.filesize = os.path.getsize(ipa_path) if os.path.isfile(ipa_path) else 0

        # Discovered structures
        self.archive_format: str = "IPA"
        self.app_dir_name: str = ""
        self.info_plist: Dict[str, Any] = {}
        self.provision_data: Dict[str, Any] = {}
        self.entitlements: Dict[str, Any] = {}
        self.executable_name: str = ""
        self.executable_bytes: bytes = b""
        self.embedded_frameworks: List[str] = []
        self.app_extensions: List[str] = []
        self.bundled_certs: List[Dict[str, Any]] = []
        self.env_config_files: List[Dict[str, Any]] = []
        self.staging_endpoints: List[str] = []
        self.weak_crypto_hits: List[str] = []
        self.jailbreak_checks: List[str] = []
        self.ssl_pinning_indicators: List[str] = []
        self.has_privacy_manifest: bool = False
        self.parse_warnings: List[str] = []
        # Extended pentest-derived static findings telemetry (additive)
        self.plist_credential_keys: List[Dict[str, Any]] = []
        self.debug_network_tools: List[str] = []
        self.dev_build_paths: List[str] = []
        self.blowfish_indicators: List[str] = []
        self.google_geocode_indicators: List[str] = []
        self.cdn_pinning_indicators: List[str] = []
        self.userdefaults_token_indicators: List[str] = []
        self.keychain_indicators: List[str] = []
        self.webview_auth_indicators: List[str] = []
        self.urlcache_indicators: List[str] = []
        self.background_audio_indicators: List[str] = []
        self.facebook_tokens: List[str] = []

    def _locate_app_dir(self, namelist: List[str]) -> str:
        """Locate the main iOS .app bundle directory inside an IPA, ZIP, or .xcarchive.zip."""
        # 1. Standard IPA: Payload/<App>.app/
        for name in namelist:
            if name.startswith("Payload/") and name.endswith(".app/") and name.count("/") == 2:
                return name

        # 2. Nested Payload/<App>.app/ anywhere (e.g. wrapper folder inside ZIP)
        for name in namelist:
            m = re.search(r"^(.*Payload/[^/]+\.app/)", name)
            if m and not name.startswith("__MACOSX/"):
                return m.group(1)

        # 3. Xcode archive: *.xcarchive/Products/Applications/<App>.app/
        for name in namelist:
            m = re.search(r"^(.*Products/Applications/[^/]+\.app/)", name)
            if m and not name.startswith("__MACOSX/"):
                return m.group(1)

        # 4. Direct <App>.app/ inside ZIP (exclude PlugIns/*.appex and __MACOSX)
        candidates = []
        for name in namelist:
            if name.startswith("__MACOSX/"):
                continue
            m = re.search(r"^(.*?[^/]+\.app/)", name)
            if m:
                cand = m.group(1)
                if "/Frameworks/" not in cand and "/PlugIns/" not in cand:
                    candidates.append(cand)
        if candidates:
            # Prefer shallowest .app/ directory
            candidates.sort(key=lambda c: (c.count("/"), len(c)))
            return candidates[0]

        return ""

    def _open_ios_archive(self) -> Tuple[zipfile.ZipFile, Optional[str]]:
        """
        Open .ipa or .zip archive. If the .zip wraps a nested .ipa file, extract the nested
        .ipa to a temporary file and return (ZipFile, temp_path_to_cleanup).
        """
        if not zipfile.is_zipfile(self.ipa_path):
            raise ValueError(
                f"File '{self.filename}' bukan arsip ZIP/IPA yang valid (header ZIP rusak atau format tidak didukung). "
                "Pastikan file adalah .ipa atau .zip hasil kompresi Payload/*.app / Xcode Archive."
            )

        z = zipfile.ZipFile(self.ipa_path, "r")
        namelist = z.namelist()
        app_dir = self._locate_app_dir(namelist)
        if app_dir:
            self.app_dir_name = app_dir
            if self.filename.lower().endswith(".zip"):
                self.archive_format = "XCARCHIVE (ZIP)" if "Products/Applications/" in app_dir else "IPA-Compatible ZIP"
            else:
                self.archive_format = "IPA"
            return z, None

        # Check if ZIP wraps a nested .ipa file
        nested_ipas = [
            n for n in namelist
            if n.lower().endswith(".ipa") and not n.startswith("__MACOSX/") and not n.endswith("/")
        ]
        if nested_ipas:
            nested_name = nested_ipas[0]
            tmp_fd, tmp_path = tempfile.mkstemp(suffix=".ipa", prefix="toolkitdev_nested_")
            try:
                with os.fdopen(tmp_fd, "wb") as out_f, z.open(nested_name, "r") as in_f:
                    while True:
                        chunk = in_f.read(1024 * 1024)
                        if not chunk:
                            break
                        out_f.write(chunk)
                z.close()
                nz = zipfile.ZipFile(tmp_path, "r")
                self.app_dir_name = self._locate_app_dir(nz.namelist())
                self.archive_format = f"Nested IPA in ZIP ({os.path.basename(nested_name)})"
                if not self.app_dir_name:
                    nz.close()
                    os.unlink(tmp_path)
                    raise ValueError(
                        f"File .ipa di dalam ZIP ('{nested_name}') tidak memiliki direktori Payload/*.app/ yang valid."
                    )
                return nz, tmp_path
            except Exception:
                z.close()
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                raise

        # Helpful diagnostic when ZIP is not an iOS bundle (e.g., Android APK or source code zip)
        top_entries = sorted(set(n.split("/")[0] for n in namelist if not n.startswith("__MACOSX/")))[:8]
        has_android = "AndroidManifest.xml" in namelist or any(n.endswith(".dex") for n in namelist)
        z.close()
        if has_android:
            raise ValueError(
                f"File '{self.filename}' terdeteksi sebagai paket Android (AndroidManifest.xml / DEX), bukan biner iOS. "
                "Silakan unggah di tab APK Inspector."
            )
        raise ValueError(
            f"Struktur iOS bundle (Payload/*.app/ atau *.app/) tidak ditemukan di dalam '{self.filename}'. "
            f"Isi root arsip: {', '.join(top_entries) or '(kosong)'}. "
            "Saran: pastikan ZIP berisi folder 'Payload/<NamaApp>.app/', '<NamaApp>.app/', file '.ipa', atau '.xcarchive'."
        )

    def analyze(self) -> Dict[str, Any]:
        """Main analysis runner for iOS IPA and ZIP archives."""
        if not os.path.isfile(self.ipa_path):
            raise FileNotFoundError(f"File IPA/ZIP tidak ditemukan: {self.ipa_path}")

        z, temp_nested = self._open_ios_archive()
        try:
            namelist = z.namelist()

            # 1. Parse Info.plist
            self._parse_info_plist(z, namelist)

            # 2. Parse embedded.mobileprovision & Entitlements
            self._parse_mobileprovision(z, namelist)

            # 3. Inventory Frameworks, App Extensions, Privacy Manifest, Certs, Env Configs
            self._inventory_bundle_assets(z, namelist)

            # 4. Extract and inspect Mach-O main binary
            macho_analysis = self._inspect_macho_binary(z, namelist)

            # 5. Scan strings, plists, configs & binary for secrets & endpoints
            secrets, endpoints = self._extract_secrets_and_endpoints(z, namelist)
        finally:
            try:
                z.close()
            except Exception:
                pass
            if temp_nested and os.path.exists(temp_nested):
                try:
                    os.unlink(temp_nested)
                except Exception:
                    pass

        # 6. Evaluate findings, issue suggestions, and security score
        findings, score, posture = self._evaluate_security_posture(macho_analysis, secrets, endpoints)

        # Provisioning expiration status
        is_expired = False
        exp_val = self.provision_data.get("ExpirationDate")
        if isinstance(exp_val, datetime):
            now_dt = datetime.now(timezone.utc) if exp_val.tzinfo else datetime.utcnow()
            is_expired = exp_val < now_dt

        return {
            "platform": "ios",
            "file_info": {
                "name": self.filename,
                "size_bytes": self.filesize,
                "size_mb": round(self.filesize / (1024 * 1024), 2),
                "app_dir": self.app_dir_name,
                "archive_format": self.archive_format,
            },
            "metadata": {
                "app_name": self.info_plist.get("CFBundleDisplayName") or self.info_plist.get("CFBundleName") or "iOS App",
                "bundle_id": self.info_plist.get("CFBundleIdentifier") or "unknown.bundle.id",
                "version_name": str(self.info_plist.get("CFBundleShortVersionString") or "1.0"),
                "build_number": str(self.info_plist.get("CFBundleVersion") or "1"),
                "min_os_version": str(self.info_plist.get("MinimumOSVersion") or "14.0"),
                "sdk_name": str(self.info_plist.get("DTSDKName") or "N/A"),
                "xcode_build": str(self.info_plist.get("DTXcodeBuild") or "N/A"),
                "executable_name": self.executable_name,
                "team_name": self.provision_data.get("TeamName", "Unknown Team"),
                "app_id": self.entitlements.get("application-identifier", "unknown"),
            },
            "security_score": score,
            "security_posture": posture,
            "app_transport_security": self._evaluate_ats(),
            "entitlements": self.entitlements,
            "provisioning": {
                "team_name": self.provision_data.get("TeamName", "N/A"),
                "profile_name": self.provision_data.get("Name", "N/A"),
                "created_date": str(self.provision_data.get("CreationDate", "N/A")),
                "expiration_date": str(self.provision_data.get("ExpirationDate", "N/A")),
                "is_expired": is_expired,
                "aps_environment": str(self.entitlements.get("aps-environment", "N/A")),
            },
            "macho_protections": macho_analysis,
            "bundle_diagnostics": {
                "embedded_frameworks": self.embedded_frameworks,
                "app_extensions": self.app_extensions,
                "bundled_certificates": self.bundled_certs,
                "env_config_files": self.env_config_files,
                "staging_endpoints": self.staging_endpoints,
                "weak_crypto_apis": self.weak_crypto_hits,
                "jailbreak_checks_detected": self.jailbreak_checks,
                "ssl_pinning_indicators": self.ssl_pinning_indicators,
                "file_sharing_enabled": bool(self.info_plist.get("UIFileSharingEnabled", False)),
                "open_documents_in_place": bool(self.info_plist.get("LSSupportsOpeningDocumentsInPlace", False)),
                "has_privacy_manifest": self.has_privacy_manifest,
                "query_schemes": self.info_plist.get("LSApplicationQueriesSchemes", []),
                "warnings": self.parse_warnings,
                "plist_credential_keys": self.plist_credential_keys,
                "debug_network_tools": self.debug_network_tools,
                "dev_build_paths": self.dev_build_paths[:10],
                "blowfish_indicators": self.blowfish_indicators,
                "google_geocode_indicators": self.google_geocode_indicators,
                "cdn_pinning_indicators": self.cdn_pinning_indicators,
                "userdefaults_token_indicators": self.userdefaults_token_indicators,
                "keychain_indicators": self.keychain_indicators,
                "webview_auth_indicators": self.webview_auth_indicators,
                "urlcache_indicators": self.urlcache_indicators,
                "background_audio_indicators": self.background_audio_indicators,
                "facebook_tokens": self.facebook_tokens,
            },
            "url_schemes": self._extract_url_schemes(),
            "privacy_permissions": self._extract_privacy_permissions(),
            "secrets": secrets,
            "endpoints": endpoints,
            "findings": findings,
            "owasp_summary": self._group_owasp(findings),
        }

    def _parse_info_plist(self, z: zipfile.ZipFile, namelist: List[str]):
        plist_path = f"{self.app_dir_name}Info.plist"
        if plist_path in namelist:
            try:
                raw_data = z.read(plist_path)
                self.info_plist = plistlib.loads(raw_data)
                self.executable_name = self.info_plist.get("CFBundleExecutable", "")
            except Exception as e:
                self.info_plist = {"error": f"Failed to parse Info.plist: {e}"}
                self.parse_warnings.append(f"Info.plist gagal di-parse: {e}")
        else:
            self.parse_warnings.append(f"Info.plist tidak ditemukan di '{plist_path}'.")

    def _parse_mobileprovision(self, z: zipfile.ZipFile, namelist: List[str]):
        prov_path = f"{self.app_dir_name}embedded.mobileprovision"
        if prov_path in namelist:
            try:
                raw_bytes = z.read(prov_path)
                start_idx = raw_bytes.find(b"<?xml")
                end_idx = raw_bytes.find(b"</plist>")
                if start_idx != -1 and end_idx != -1:
                    xml_bytes = raw_bytes[start_idx:end_idx + 8]
                    self.provision_data = plistlib.loads(xml_bytes)
                    self.entitlements = self.provision_data.get("Entitlements", {})
            except Exception as e:
                self.provision_data = {}
                self.entitlements = {}
                self.parse_warnings.append(f"embedded.mobileprovision gagal dibaca: {e}")

    def _inspect_x509_cert(self, name: str, data: bytes) -> Optional[Dict[str, Any]]:
        """Inspect bundled .der/.cer/.crt/.pem certificate via openssl for expiration & subject."""
        inform = "PEM" if b"-----BEGIN CERTIFICATE-----" in data else "DER"
        try:
            proc = subprocess.run(
                ["openssl", "x509", "-inform", inform, "-noout", "-subject", "-issuer", "-dates"],
                input=data,
                capture_output=True,
                timeout=5,
            )
            if proc.returncode != 0:
                return None
            out = proc.stdout.decode("utf-8", errors="ignore")
            subject = ""
            not_before = ""
            not_after = ""
            for line in out.splitlines():
                if line.startswith("subject="):
                    subject = line.split("=", 1)[1].strip()
                elif line.startswith("notBefore="):
                    not_before = line.split("=", 1)[1].strip()
                elif line.startswith("notAfter="):
                    not_after = line.split("=", 1)[1].strip()

            is_expired = False
            if not_after:
                try:
                    # OpenSSL date format: "Nov 10 23:59:59 2022 GMT"
                    cleaned = re.sub(r"\s+", " ", not_after.replace("GMT", "").strip())
                    exp_dt = datetime.strptime(cleaned, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                    is_expired = exp_dt < datetime.now(timezone.utc)
                except Exception:
                    pass

            return {
                "file": os.path.basename(name),
                "path": name,
                "subject": subject or "Unknown Subject",
                "not_before": not_before,
                "not_after": not_after,
                "is_expired": is_expired,
            }
        except Exception:
            return None

    def _inventory_bundle_assets(self, z: zipfile.ZipFile, namelist: List[str]):
        """Inspect embedded frameworks, app extensions, certificates, env plists, and PrivacyInfo.xcprivacy."""
        fw_prefix = f"{self.app_dir_name}Frameworks/"
        plugin_prefix = f"{self.app_dir_name}PlugIns/"
        frameworks = set()
        extensions = set()

        for name in namelist:
            if not name.startswith(self.app_dir_name):
                continue
            rel = name[len(self.app_dir_name):]

            if name.startswith(fw_prefix):
                sub = name[len(fw_prefix):].split("/")[0]
                if sub and sub.endswith((".framework", ".dylib")):
                    frameworks.add(sub)
            elif name.startswith(plugin_prefix):
                sub = name[len(plugin_prefix):].split("/")[0]
                if sub and sub.endswith(".appex"):
                    extensions.add(sub)

            if rel == "PrivacyInfo.xcprivacy" or name.endswith("/PrivacyInfo.xcprivacy"):
                self.has_privacy_manifest = True

            # Bundled X.509 certificates (commonly used for SSL pinning)
            if rel.lower().endswith((".der", ".cer", ".crt", ".pem")) and "/" not in rel:
                try:
                    cert_info = self._inspect_x509_cert(name, z.read(name))
                    if cert_info:
                        self.bundled_certs.append(cert_info)
                except Exception:
                    pass

            # Multi-environment Firebase / config plists
            base_low = os.path.basename(name).lower()
            if (
                "googleservice-info" in base_low
                or (rel.endswith(".plist") and any(k in base_low for k in ("staging", "beta", "debug", "dev", "uat", "sandbox")))
            ) and "/" not in rel:
                env_type = "production"
                if any(k in base_low for k in ("debug", "dev")):
                    env_type = "debug"
                elif any(k in base_low for k in ("staging", "stg", "uat")):
                    env_type = "staging"
                elif "beta" in base_low:
                    env_type = "beta"

                entry: Dict[str, Any] = {
                    "file": os.path.basename(name),
                    "path": name,
                    "environment": env_type,
                    "bundle_id": "",
                    "project_id": "",
                    "has_api_key": False,
                }
                try:
                    pl = plistlib.loads(z.read(name))
                    if isinstance(pl, dict):
                        entry["bundle_id"] = str(pl.get("BUNDLE_ID") or "")
                        entry["project_id"] = str(pl.get("PROJECT_ID") or "")
                        entry["has_api_key"] = bool(pl.get("API_KEY"))
                except Exception:
                    pass
                self.env_config_files.append(entry)

            # Scan root-level custom config plists (excluding Info.plist & GoogleService-Info*) for plaintext credential keys (Ref 5.13)
            if rel.endswith(".plist") and "/" not in rel and base_low != "info.plist" and "googleservice-info" not in base_low:
                try:
                    pl = plistlib.loads(z.read(name))
                    if isinstance(pl, dict):
                        cred_key_rx = re.compile(
                            r"(pass|password|secret|apikey|api_key|channelkey|devkey|token|iossec|authuser|paymentuser|paymentpass|privatekey|clientsecret|encryptionkey)",
                            re.IGNORECASE,
                        )
                        for k, v in pl.items():
                            if isinstance(k, str) and cred_key_rx.search(k) and v not in (None, "", False):
                                s_val = str(v)
                                masked = (s_val[:4] + "..." + s_val[-3:]) if len(s_val) > 8 else "***"
                                self.plist_credential_keys.append({
                                    "file": os.path.basename(name),
                                    "key": k,
                                    "masked_value": masked,
                                })
                except Exception:
                    pass

        self.embedded_frameworks = sorted(frameworks)
        self.app_extensions = sorted(extensions)

        # Info.plist checks: Facebook Client Token (5.27) & Background Audio + Audio/Ultrasonic SDK (5.19)
        fb_token = self.info_plist.get("FacebookClientToken")
        fb_app_id = self.info_plist.get("FacebookAppID")
        if fb_token:
            tok_s = str(fb_token)
            masked_fb = tok_s[:6] + "..." + tok_s[-4:] if len(tok_s) > 10 else "***"
            self.facebook_tokens.append(f"FacebookClientToken={masked_fb}")
            if fb_app_id:
                self.facebook_tokens.append(f"FacebookAppID={fb_app_id}")

        bg_modes = self.info_plist.get("UIBackgroundModes", [])
        if isinstance(bg_modes, list) and "audio" in [str(m).lower() for m in bg_modes]:
            self.background_audio_indicators.append("UIBackgroundModes includes 'audio'")
            if self.info_plist.get("NSMicrophoneUsageDescription"):
                self.background_audio_indicators.append("NSMicrophoneUsageDescription present")
            for fw in self.embedded_frameworks:
                if any(tok in fw.lower() for tok in ("tonetag", "soundwave", "ultrasonic", "webrtc", "realtimecall")):
                    self.background_audio_indicators.append(f"Embedded audio SDK: {fw}")

    def _inspect_macho_binary(self, z: zipfile.ZipFile, namelist: List[str]) -> Dict[str, Any]:
        """Inspects Mach-O load commands, protection flags, crypto APIs, jailbreak & pinning footprints."""
        result = {
            "has_pie": False,
            "has_stack_canaries": False,
            "has_arc": False,
            "is_encrypted": False,
            "crypt_id": 0,
            "architectures": [],
            "linked_frameworks": [],
            "binary_size_mb": 0.0,
        }

        exec_path = f"{self.app_dir_name}{self.executable_name}" if self.executable_name else ""
        if not exec_path or exec_path not in namelist:
            for name in namelist:
                if name.startswith(self.app_dir_name):
                    tail = name[len(self.app_dir_name):]
                    if tail and "/" not in tail and "." not in tail:
                        exec_path = name
                        self.executable_name = os.path.basename(name)
                        break

        if not exec_path or exec_path not in namelist:
            self.parse_warnings.append("Biner utama Mach-O tidak ditemukan di dalam .app bundle.")
            return result

        try:
            self.executable_bytes = z.read(exec_path)
            data = self.executable_bytes
            result["binary_size_mb"] = round(len(data) / (1024 * 1024), 2)

            if len(data) >= 32:
                magic = struct.unpack(">I", data[:4])[0]
                magic_le = struct.unpack("<I", data[:4])[0]

                if magic == 0xcafebabe or magic_le == 0xcafebabe:
                    result["architectures"].append("Universal/FAT")
                    # Parse first Mach-O slice inside FAT header if possible
                    nfat = struct.unpack(">I", data[4:8])[0]
                    if 0 < nfat <= 8 and len(data) >= 8 + nfat * 20:
                        slice_off = struct.unpack(">I", data[16:20])[0]
                        if slice_off + 32 <= len(data):
                            smagic_le = struct.unpack("<I", data[slice_off:slice_off + 4])[0]
                            if smagic_le in (0xfeedfacf, 0xfeedface):
                                sflags = struct.unpack("<I", data[slice_off + 24:slice_off + 28])[0]
                                if sflags & 0x00200000:
                                    result["has_pie"] = True
                elif magic == 0xfeedfacf or magic_le == 0xfeedfacf:
                    result["architectures"].append("arm64 / x86_64")
                    flags = struct.unpack("<I", data[24:28])[0] if magic_le == 0xfeedfacf else struct.unpack(">I", data[24:28])[0]
                    if flags & 0x00200000:
                        result["has_pie"] = True
                elif magic == 0xfeedface or magic_le == 0xfeedface:
                    result["architectures"].append("armv7 / 32-bit")
                    flags = struct.unpack("<I", data[24:28])[0] if magic_le == 0xfeedface else struct.unpack(">I", data[24:28])[0]
                    if flags & 0x00200000:
                        result["has_pie"] = True

            # Stack Canaries and ARC symbols
            if b"___stack_chk_fail" in data or b"___stack_chk_guard" in data:
                result["has_stack_canaries"] = True

            if b"_objc_release" in data or b"_objc_retain" in data or b"_objc_storeStrong" in data or b"swift_retain" in data:
                result["has_arc"] = True

            # FairPlay Encryption Info (LC_ENCRYPTION_INFO=0x21, LC_ENCRYPTION_INFO_64=0x2C)
            cryptid_matches = re.findall(b"(\\x2c|\\x21)\\x00\\x00\\x00.{8}(\\x01|\\x00)\\x00\\x00\\x00", data[:65536], re.DOTALL)
            for _, cid in cryptid_matches:
                if cid == b"\x01":
                    result["is_encrypted"] = True
                    result["crypt_id"] = 1
                    break

            # Linked frameworks
            framework_matches = re.findall(rb"([A-Za-z0-9_]+)\.framework", data)
            frameworks = set()
            for fm in framework_matches:
                try:
                    name = fm.decode("utf-8")
                    if 2 < len(name) < 40:
                        frameworks.add(name)
                except Exception:
                    pass
            result["linked_frameworks"] = sorted(frameworks)[:25]

            # Weak Crypto APIs
            weak_patterns = [
                (b"CC_MD5", "CC_MD5 (Weak Hash)"),
                (b"CC_SHA1", "CC_SHA1 (Weak Hash)"),
                (b"kCCAlgorithmDES", "DES Cipher"),
                (b"kCCAlgorithm3DES", "3DES Cipher"),
                (b"kCCAlgorithmRC4", "RC4 Cipher"),
                (b"kCCOptionECBMode", "AES/DES ECB Mode"),
            ]
            self.weak_crypto_hits = [label for sig, label in weak_patterns if sig in data]

            # Jailbreak & Frida Detection Indicators
            jb_patterns = [
                (b"/Applications/Cydia.app", "Cydia.app"),
                (b"MobileSubstrate", "MobileSubstrate"),
                (b"frida-server", "frida-server"),
                (b"IOSSecuritySuite", "IOSSecuritySuite"),
                (b"/var/jb", "Rootless JB (/var/jb)"),
                (b"ElleKit", "ElleKit"),
                (b"Dopamine", "Dopamine"),
                (b"palera1n", "Palera1n"),
                (b"PT_DENY_ATTACH", "PT_DENY_ATTACH"),
            ]
            self.jailbreak_checks = [label for sig, label in jb_patterns if sig in data]

            # SSL Pinning Indicators
            pin_patterns = [
                (b"ServerTrustManager", "Alamofire ServerTrustManager"),
                (b"PinnedCertificatesTrustEvaluator", "PinnedCertificatesTrustEvaluator"),
                (b"PublicKeysTrustEvaluator", "PublicKeysTrustEvaluator"),
                (b"SecTrustEvaluate", "SecTrustEvaluate"),
                (b"AFSecurityPolicy", "AFSecurityPolicy"),
            ]
            self.ssl_pinning_indicators = [label for sig, label in pin_patterns if sig in data]

            # --- Extended Pentest-Derived Static Checks (Additive) ---
            # N1: Network debugging / HTTP inspector tools linked into binary
            debug_net_patterns = [
                (b"Wormholy", "Wormholy"),
                (b"fireWormholy", "fireWormholy"),
                (b"CustomHTTPProtocol", "CustomHTTPProtocol (Wormholy)"),
                (b"FLEXManager", "FLEXManager"),
                (b"FlipperClient", "FlipperClient"),
                (b"NFXHTTPModel", "Netfox (NFX)"),
                (b"BagelController", "Bagel"),
                (b"PulseUI", "PulseUI"),
            ]
            self.debug_network_tools = [label for sig, label in debug_net_patterns if sig in data]

            # 5.37: Developer Xcode local build paths (/Users/<username>/...)
            dev_path_rx = re.compile(rb"/Users/[A-Za-z0-9._-]{2,32}/[A-Za-z0-9._/\- ]{4,140}\.(?:swift|m|mm|h)")
            seen_users = set()
            dev_samples = []
            for m in dev_path_rx.finditer(data):
                path_s = m.group(0).decode("ascii", errors="ignore").strip()
                parts = path_s.split("/")
                if len(parts) >= 3:
                    uname = parts[2]
                    if uname.lower() in ("ec2-user", "runner", "vagrant", "distiller", "circleci"):
                        continue
                    if uname not in seen_users or len(dev_samples) < 5:
                        seen_users.add(uname)
                        if path_s not in dev_samples:
                            dev_samples.append(path_s)
                if len(dev_samples) >= 8:
                    break
            self.dev_build_paths = dev_samples

            # Obs. D: Legacy Blowfish / CryptoSwift cipher
            bf_patterns = [
                (b"Blowfish", "Blowfish"),
                (b"blowfishEncrypt", "blowfishEncrypt"),
                (b"CryptoSwift", "CryptoSwift"),
                (b"kCCAlgorithmBlowfish", "kCCAlgorithmBlowfish"),
            ]
            bf_hits = [label for sig, label in bf_patterns if sig in data]
            if any("Blowfish" in h or "blowfish" in h for h in bf_hits):
                self.blowfish_indicators = bf_hits

            # 5.18 / Obs. B: Direct client-side Google Maps Geocode REST API
            geo_patterns = [
                (b"maps.googleapis.com", "maps.googleapis.com"),
                (b"/maps/api/geocode", "/maps/api/geocode"),
                (b"GoogleMapAPIKey", "GoogleMapAPIKey"),
                (b"GoogleMapsPlacesAPIKey", "GoogleMapsPlacesAPIKey"),
            ]
            geo_hits = [label for sig, label in geo_patterns if sig in data]
            if any("maps.googleapis.com" in h or "geocode" in h for h in geo_hits):
                self.google_geocode_indicators = geo_hits

            # 5.24: Dynamic remote/CDN SSL pinning payload fetch
            cdn_pin_patterns = [
                (b"cdn.takdes.net", "cdn.takdes.net"),
                (b"SSLPublicKeyUrl", "SSLPublicKeyUrl"),
                (b"sslPublicKeyHashes", "sslPublicKeyHashes"),
                (b"SSLPinningManager", "SSLPinningManager"),
            ]
            cdn_hits = [label for sig, label in cdn_pin_patterns if sig in data]
            if len(cdn_hits) >= 2:
                self.cdn_pinning_indicators = cdn_hits

            # Obs. A / 5.30: Plaintext UserDefaults / SwiftyUserDefaults with sensitive session tokens
            ud_libs = [label for sig, label in [(b"SwiftyUserDefaults", "SwiftyUserDefaults"), (b"DefaultsKeys", "DefaultsKeys")] if sig in data]
            ud_tokens = [
                label for sig, label in [
                    (b"tempToken", "tempToken"),
                    (b"streamToken", "streamToken"),
                    (b"zendeskToken", "zendeskToken"),
                    (b"qiscusKey", "qiscusKey"),
                    (b"voip_token", "voip_token"),
                ]
                if sig in data
            ]
            if ud_libs and ud_tokens:
                self.userdefaults_token_indicators = ud_libs + ud_tokens

            # N2: Keychain usage & accessibility hardening audit
            kc_hits = [
                label for sig, label in [
                    (b"SecItemAdd", "SecItemAdd"),
                    (b"KeychainServiceManager", "KeychainServiceManager"),
                    (b"KeychainSwift", "KeychainSwift"),
                    (b"KeychainAccess", "KeychainAccess"),
                ]
                if sig in data
            ]
            if kc_hits:
                self.keychain_indicators = kc_hits

            # Obs. C / Obs. F: WKWebView cookie injection & auth challenge
            wv_hits = [
                label for sig, label in [
                    (b"setAlfagiftWebviewCookies", "setAlfagiftWebviewCookies"),
                    (b"didReceiveAuthenticationChallenge", "didReceiveAuthenticationChallenge"),
                    (b"PaymentAPGViewController", "PaymentAPGViewController"),
                    (b"URLCredential", "URLCredential"),
                ]
                if sig in data
            ]
            if len(wv_hits) >= 2:
                self.webview_auth_indicators = wv_hits

            # 5.31: URLSessionConfiguration.default / URLCache with API delegates
            uc_hits = [
                label for sig, label in [
                    (b"SSLPinningMoyaDelegate", "SSLPinningMoyaDelegate"),
                    (b"defaultSessionConfiguration", "URLSessionConfiguration.default"),
                    (b"URLCache", "URLCache"),
                ]
                if sig in data
            ]
            if len(uc_hits) >= 2 and b"URLCache" in data and b"defaultSessionConfiguration" in data:
                self.urlcache_indicators = uc_hits

            # 5.19: Audio/Ultrasonic recording symbols when background audio mode is enabled
            if self.background_audio_indicators:
                for sig, label in [(b"SoundWaveRecorder", "SoundWaveRecorder"), (b"ttStartRecording", "ttStartRecording")]:
                    if sig in data and label not in self.background_audio_indicators:
                        self.background_audio_indicators.append(label)

        except Exception as e:
            result["error"] = str(e)
            self.parse_warnings.append(f"Gagal membedah Mach-O binary: {e}")

        return result

    def _evaluate_ats(self) -> Dict[str, Any]:
        """Audits App Transport Security (ATS) configuration."""
        ats = self.info_plist.get("NSAppTransportSecurity", {})
        if not isinstance(ats, dict):
            ats = {}
        arbitrary_loads = bool(ats.get("NSAllowsArbitraryLoads", False))
        web_arbitrary = bool(ats.get("NSAllowsArbitraryLoadsInWebContent", False))
        exceptions = ats.get("NSExceptionDomains", {})
        exc_keys = list(exceptions.keys()) if isinstance(exceptions, dict) else []

        return {
            "allows_arbitrary_loads": arbitrary_loads,
            "allows_arbitrary_loads_in_web": web_arbitrary,
            "has_exception_domains": len(exc_keys) > 0,
            "exception_domain_count": len(exc_keys),
            "exception_domains": exc_keys,
            "status": "VULNERABLE" if arbitrary_loads else ("WARNING" if web_arbitrary or exc_keys else "SECURE"),
        }

    def _extract_url_schemes(self) -> List[str]:
        schemes = []
        url_types = self.info_plist.get("CFBundleURLTypes", [])
        if isinstance(url_types, list):
            for item in url_types:
                if isinstance(item, dict):
                    sc_list = item.get("CFBundleURLSchemes", [])
                    if isinstance(sc_list, list):
                        schemes.extend([str(s) for s in sc_list])
        return sorted(set(schemes))

    def _extract_privacy_permissions(self) -> List[Dict[str, str]]:
        perms = []
        for key, val in self.info_plist.items():
            if key.startswith("NS") and "UsageDescription" in key:
                name = key.replace("NS", "").replace("UsageDescription", "")
                perms.append({
                    "permission": key,
                    "category": name,
                    "description": str(val),
                })
        return sorted(perms, key=lambda x: x["permission"])

    def _extract_secrets_and_endpoints(self, z: zipfile.ZipFile, namelist: List[str]) -> Tuple[List[Dict[str, Any]], List[str]]:
        secrets: List[Dict[str, Any]] = []
        seen_secrets = set()
        endpoints = set()
        staging_eps = set()

        secret_regexes = [
            ("Google / Firebase API Key", r"AIza[0-9A-Za-z\-_]{35}"),
            ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}"),
            ("Slack Webhook URL", r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+"),
            ("JSON Web Token (JWT)", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
            ("Generic Private Key Header", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        ]

        ignore_domains = ("apple.com", "w3.org", "schemas.android.com", "example.com", "example.invalid", "ns.adobe.com", "purl.org")

        # Prioritize top-level app configs/plists/json first (never miss GoogleService-Info*.plist!)
        config_files = [
            n for n in namelist
            if n.startswith(self.app_dir_name)
            and n.lower().endswith((".plist", ".json", ".strings", ".xcconfig", ".env"))
            and "/_CodeSignature/" not in n
        ]
        # Sort so root-level plists (GoogleService-Info*, Info.plist, etc.) come first
        config_files.sort(key=lambda p: (p.count("/"), p))

        for name in config_files[:150]:
            try:
                raw = z.read(name)
                if len(raw) > 2 * 1024 * 1024:
                    continue
                content = ""
                # Binary plists start with b"bplist00" — decode them to text values via plistlib!
                if raw.startswith(b"bplist00"):
                    try:
                        pl_obj = plistlib.loads(raw)
                        content = str(pl_obj)
                    except Exception:
                        content = raw.decode("utf-8", errors="ignore")
                else:
                    content = raw.decode("utf-8", errors="ignore")

                for label, pattern in secret_regexes:
                    for match in re.finditer(pattern, content):
                        val = match.group(0)
                        dedup = (label, name, val)
                        if dedup in seen_secrets:
                            continue
                        seen_secrets.add(dedup)
                        masked = val[:6] + "..." + val[-4:] if len(val) > 10 else "***"
                        secrets.append({
                            "type": label,
                            "file": name,
                            "masked_value": masked,
                            "severity": "HIGH",
                        })

                for url in re.findall(r"https?://[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}(?:/[a-zA-Z0-9_\-\./\?=&%]*)?", content):
                    if len(url) < 130 and not any(d in url.lower() for d in ignore_domains):
                        endpoints.add(url)
            except Exception:
                pass

        # Scan full Mach-O binary for clean ASCII HTTPS/HTTP endpoints & staging/beta hosts
        if self.executable_bytes:
            # Extract clean printable URL tokens (avoid binary garbage tail!)
            url_rx = re.compile(rb"https?://[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,10}(?::\d{2,5})?(?:/[a-zA-Z0-9_\-\./\?=&%]*)?")
            staging_host_rx = re.compile(r"^https?://[^/]*(?:^|[.\-])(?:stg|staging|uat|beta|dev|sandbox|internal)(?:[.\-]|$)", re.IGNORECASE)
            noise_hosts = ("developers.google.com", "device-provisioning.googleapis.com", "firebase.google.com", "cloud.google.com", "developer.apple.com", "github.com", "apache.org", "openssl.org", "mozilla.org")

            for m in url_rx.finditer(self.executable_bytes):
                u = m.group(0).decode("ascii", errors="ignore").rstrip("./?&=")
                if len(u) < 10 or len(u) > 120:
                    continue
                low = u.lower()
                if any(d in low for d in ignore_domains):
                    continue
                endpoints.add(u)
                if staging_host_rx.match(u) and not any(nh in low for nh in noise_hosts):
                    staging_eps.add(u)

        self.staging_endpoints = sorted(staging_eps)[:20]
        return secrets[:25], sorted(endpoints)[:40]

    def _evaluate_security_posture(
        self,
        macho: Dict[str, Any],
        secrets: List[Dict[str, Any]],
        endpoints: List[str],
    ) -> Tuple[List[Dict[str, Any]], int, str]:
        findings: List[Dict[str, Any]] = []
        score = 100

        # 1. ATS NSAllowsArbitraryLoads Check
        ats = self.info_plist.get("NSAppTransportSecurity", {})
        if isinstance(ats, dict) and ats.get("NSAllowsArbitraryLoads", False):
            findings.append({
                "id": "IOS-ATS-CLEARTEXT",
                "title": "App Transport Security (ATS) Dinonaktifkan Secara Penuh",
                "severity": "CRITICAL",
                "category": "Network Security (MASVS-NETWORK-1)",
                "affected_items": ["Info.plist -> NSAppTransportSecurity.NSAllowsArbitraryLoads = true"],
                "description": (
                    "Aplikasi mendefinisikan NSAllowsArbitraryLoads=true di Info.plist. Hal ini mematikan proteksi "
                    "enkripsi TLS iOS secara global dan mengizinkan koneksi HTTP plaintext yang rentan penyadapan MITM."
                ),
                "remediation": (
                    "Hapus key NSAllowsArbitraryLoads (atau ubah ke false) di Info.plist, lalu aktifkan TLS 1.2+ "
                    "untuk semua endpoint API. Gunakan NSExceptionDomains hanya bila ada domain legacy sementara."
                ),
                "code_fix": (
                    "<key>NSAppTransportSecurity</key>\n"
                    "<dict>\n"
                    "    <key>NSAllowsArbitraryLoads</key>\n"
                    "    <false/>\n"
                    "</dict>"
                ),
            })
            score -= 25

        # 2. Entitlement get-task-allow / Development Profile
        if self.entitlements.get("get-task-allow", False):
            aps_env = self.entitlements.get("aps-environment", "")
            prof_name = self.provision_data.get("Name", "N/A")
            affected = [f"get-task-allow = true", f"Profile: {prof_name}"]
            if aps_env == "development":
                affected.append("aps-environment = development")
            findings.append({
                "id": "IOS-DEBUG-ATTACH",
                "title": "Aplikasi Debuggable / Menggunakan Provisioning Profile Development (get-task-allow: true)",
                "severity": "CRITICAL",
                "category": "Platform Interaction (MASVS-PLATFORM-2)",
                "affected_items": affected,
                "description": (
                    "Entitlement get-task-allow=true aktif pada build ini. Penyerang atau perangkat yang terhubung via USB "
                    "dapat langsung menempelkan debugger (LLDB / Frida) untuk membaca memori, token sesi, dan membypass autentikasi."
                ),
                "remediation": (
                    "Gunakan App Store / Ad-Hoc / Enterprise Distribution Provisioning Profile untuk build rilis/UAT "
                    "sehingga get-task-allow bernilai false dan aps-environment bernilai production."
                ),
                "code_fix": (
                    "# Xcode Build Settings (Release):\n"
                    "CODE_SIGN_STYLE = Manual\n"
                    "CODE_SIGN_IDENTITY = Apple Distribution\n"
                    "# Verifikasi sebelum rilis:\n"
                    "codesign -d --entitlements :- Payload/*.app | grep get-task-allow"
                ),
            })
            score -= 25

        # 3. Expired Bundled SSL Pinning Certificates (.der/.cer/.pem)
        expired_certs = [c for c in self.bundled_certs if c.get("is_expired")]
        if expired_certs:
            cert_items = [f"{c['file']} (expired: {c['not_after']})" for c in expired_certs]
            findings.append({
                "id": "IOS-EXPIRED-PIN-CERTS",
                "title": f"Terdeteksi {len(expired_certs)} Sertifikat SSL Pinning (.der/.cer) Sudah Kedaluwarsa di Bundle",
                "severity": "CRITICAL",
                "category": "Network Security (MASVS-NETWORK-2)",
                "affected_items": cert_items,
                "description": (
                    "File sertifikat X.509 yang dibundel di dalam .app sudah expired sejak bertahun-tahun lalu. "
                    "Jika dipakai oleh Alamofire ServerTrustManager / PinnedCertificatesTrustEvaluator, pinning berisiko "
                    "gagal (network error) atau fallback menjadi tidak terverifikasi (bypass MITM)."
                ),
                "remediation": (
                    "Hapus semua sertifikat .der lama yang expired dan migrasi SSL Pinning ke Public Key Pinning "
                    "(SPKI SHA-256 / PublicKeysTrustEvaluator) dengan backup pin untuk rotasi sertifikat."
                ),
                "code_fix": (
                    "// Alamofire Public Key Pinning (lebih tahan rotasi cert):\n"
                    "let evaluators: [String: ServerTrustEvaluating] = [\n"
                    "    \"api.alfagift.id\": PublicKeysTrustEvaluator(\n"
                    "        keys: Bundle.main.af.publicKeys,\n"
                    "        performDefaultValidation: true,\n"
                    "        validateHost: true\n"
                    "    )\n"
                    "]\n"
                    "let session = Session(serverTrustManager: ServerTrustManager(evaluators: evaluators))"
                ),
            })
            score -= 15

        # 4. UIFileSharingEnabled / LSSupportsOpeningDocumentsInPlace
        fs_enabled = bool(self.info_plist.get("UIFileSharingEnabled", False))
        open_in_place = bool(self.info_plist.get("LSSupportsOpeningDocumentsInPlace", False))
        if fs_enabled or open_in_place:
            items = []
            if fs_enabled:
                items.append("UIFileSharingEnabled = true")
            if open_in_place:
                items.append("LSSupportsOpeningDocumentsInPlace = true")
            findings.append({
                "id": "IOS-FILE-SHARING",
                "title": "iTunes File Sharing & Akses Direktori Documents Terbuka ke Publik",
                "severity": "HIGH",
                "category": "Data Storage (MASVS-STORAGE-2)",
                "affected_items": items,
                "description": (
                    "Flag UIFileSharingEnabled / LSSupportsOpeningDocumentsInPlace aktif di Info.plist. Seluruh file, "
                    "SQLite/Realm database, log, atau cache di folder Documents/ dapat diakses dan dimodifikasi lewat "
                    "aplikasi Files iOS, Finder, atau iTunes tanpa memerlukan jailbreak."
                ),
                "remediation": (
                    "Set UIFileSharingEnabled dan LSSupportsOpeningDocumentsInPlace ke false di Info.plist jika "
                    "aplikasi tidak memerlukan fitur berbagi dokumen langsung, dan pindahkan file sensitif ke Keychain / Library/Application Support."
                ),
                "code_fix": (
                    "<key>UIFileSharingEnabled</key>\n<false/>\n"
                    "<key>LSSupportsOpeningDocumentsInPlace</key>\n<false/>"
                ),
            })
            score -= 12

        # 5. Multi-Environment Config Leakage (Debug / Staging / Beta plists inside bundle)
        non_prod_configs = [c for c in self.env_config_files if c.get("environment") in ("debug", "staging", "beta")]
        if non_prod_configs:
            findings.append({
                "id": "IOS-ENV-CONFIG-LEAK",
                "title": f"Kebocoran {len(non_prod_configs)} File Konfigurasi Non-Produksi (Debug/Staging/Beta) di Bundle",
                "severity": "HIGH",
                "category": "Storage & Secrets (MASVS-STORAGE-1)",
                "affected_items": [f"{c['file']} ({c['environment']}, bundle={c['bundle_id'] or 'N/A'})" for c in non_prod_configs],
                "description": (
                    "File GoogleService-Info untuk environment Debug, Staging, dan Beta ikut terpaket di dalam "
                    "bundle aplikasi bersama API Key masing-masing. Ini memperluas attack surface ke infrastruktur non-prod."
                ),
                "remediation": (
                    "Pisahkan Copy Bundle Resources per Build Configuration (Debug/Staging/Release) menggunakan "
                    "Xcode Run Script phase sehingga hanya 1 GoogleService-Info.plist sesuai target yang masuk ke IPA."
                ),
                "code_fix": (
                    "# Xcode Build Phase (Run Script):\n"
                    "if [ \"${CONFIGURATION}\" == \"Release\" ]; then\n"
                    "  cp \"${PROJECT_DIR}/Config/Prod/GoogleService-Info.plist\" \"${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.app/GoogleService-Info.plist\"\n"
                    "fi"
                ),
            })
            score -= 10

        # 6. Hardcoded Staging / Beta Endpoints in Mach-O Binary
        if self.staging_endpoints:
            findings.append({
                "id": "IOS-STAGING-ENDPOINTS",
                "title": f"Terdeteksi {len(self.staging_endpoints)} URL Staging / Beta Hardcoded dalam Biner Mach-O",
                "severity": "HIGH",
                "category": "Network & Architecture (MASVS-NETWORK-1)",
                "affected_items": self.staging_endpoints[:8],
                "description": (
                    "Endpoint internal/staging/beta masih tertanam di biner utama. Penyerang dapat memanfaatkan "
                    "server staging yang biasanya memiliki kontrol WAF, rate-limit, atau autentikasi lebih longgar."
                ),
                "remediation": (
                    "Gunakan Xcode .xcconfig per environment dan compiler flag #if DEBUG agar URL staging/beta "
                    "tidak terkompilasi ke dalam biner produksi."
                ),
                "code_fix": (
                    "#if DEBUG\n"
                    "let baseURL = \"https://staging-api.example.com\"\n"
                    "#else\n"
                    "let baseURL = \"https://api.alfagift.id\"\n"
                    "#endif"
                ),
            })
            score -= 10

        # 7. Wildcard Entitlements & Debug/Beta App Groups
        wildcard_items = []
        assoc_domains = self.entitlements.get("com.apple.developer.associated-domains")
        if assoc_domains == "*" or (isinstance(assoc_domains, list) and "*" in assoc_domains):
            wildcard_items.append("com.apple.developer.associated-domains = *")
        kc_groups = self.entitlements.get("keychain-access-groups", [])
        if isinstance(kc_groups, list) and any(str(g).endswith(".*") for g in kc_groups):
            wildcard_items.append(f"keychain-access-groups wildcard: {[g for g in kc_groups if str(g).endswith('.*')]}")
        app_groups = self.entitlements.get("com.apple.security.application-groups", [])
        if isinstance(app_groups, list):
            nonprod_groups = [g for g in app_groups if any(k in str(g).lower() for k in ("debug", "beta", "staging", "dev"))]
            if nonprod_groups:
                wildcard_items.append(f"Non-prod App Groups: {', '.join(nonprod_groups)}")
        if wildcard_items:
            findings.append({
                "id": "IOS-WILDCARD-ENTITLEMENTS",
                "title": "Konfigurasi Entitlements Wildcard / App Group Debug Terbawa",
                "severity": "MEDIUM",
                "category": "Platform Security (MASVS-PLATFORM-1)",
                "affected_items": wildcard_items,
                "description": (
                    "Entitlements menggunakan wildcard (*) pada Keychain Access Group / Associated Domains serta "
                    "menyertakan App Group debug/beta, berpotensi membuka akses berbagi keychain/container antar aplikasi."
                ),
                "remediation": (
                    "Spesifikkan domain eksplisit pada Associated Domains (applinks:alfagift.id), batasi "
                    "keychain-access-groups hanya ke bundle ID spesifik, dan hapus App Group debug/beta dari target Release."
                ),
                "code_fix": (
                    "<!-- *.entitlements (Production) -->\n"
                    "<key>keychain-access-groups</key>\n"
                    "<array><string>$(AppIdentifierPrefix)com.alfamart.alfagift</string></array>"
                ),
            })
            score -= 8

        # 8. Weak Cryptography in Mach-O Binary (CC_MD5 / CC_SHA1 / DES / ECB)
        if self.weak_crypto_hits:
            findings.append({
                "id": "IOS-WEAK-CRYPTO",
                "title": f"Penggunaan API Kriptografi Lemah Terdeteksi ({', '.join(self.weak_crypto_hits[:3])})",
                "severity": "MEDIUM",
                "category": "Cryptography (MASVS-CRYPTO-1)",
                "affected_items": self.weak_crypto_hits,
                "description": (
                    "Biner Mach-O masih mereferensikan fungsi hash/cipher usang (CC_MD5 / CC_SHA1 / DES / ECB) "
                    "yang rentan collision attack atau plaintext recovery."
                ),
                "remediation": (
                    "Ganti CC_MD5/CC_SHA1 dengan CryptoKit SHA256/SHA512 dan gunakan AES.GCM untuk enkripsi simetris."
                ),
                "code_fix": (
                    "import CryptoKit\n"
                    "let digest = SHA256.hash(data: Data(input.utf8))\n"
                    "let sealed = try AES.GCM.seal(plaintextData, using: symmetricKey)"
                ),
            })
            score -= 8

        # 9. Mach-O PIE (Position Independent Executable / ASLR)
        if not macho.get("has_pie", True):
            findings.append({
                "id": "IOS-MACHO-NO-PIE",
                "title": "Mach-O Binary Tidak Mengaktifkan Flag PIE (Position Independent Executable)",
                "severity": "HIGH",
                "category": "Code Quality (MASVS-CODE-1)",
                "affected_items": [self.executable_name or "Main Mach-O"],
                "description": "Biner dikompilasi tanpa flag -fPIE / MH_PIE, sehingga ASLR tidak aktif sepenuhnya.",
                "remediation": "Aktifkan 'Generate Position-Dependent Code' = NO di Build Settings Xcode.",
                "code_fix": "GCC_GENERATE_POSITION_DEPENDENT_CODE = NO",
            })
            score -= 20

        # 10. Mach-O Stack Canaries
        if not macho.get("has_stack_canaries", True):
            findings.append({
                "id": "IOS-MACHO-NO-CANARY",
                "title": "Proteksi Stack Canary Tidak Terdeteksi",
                "severity": "HIGH",
                "category": "Code Quality (MASVS-CODE-2)",
                "affected_items": [self.executable_name or "Main Mach-O"],
                "description": "Symbol ___stack_chk_fail tidak ditemukan pada biner aplikasi.",
                "remediation": "Tambahkan flag kompilator '-fstack-protector-all' pada OTHER_CFLAGS di Xcode.",
                "code_fix": "OTHER_CFLAGS = $(inherited) -fstack-protector-all",
            })
            score -= 15

        # 11. Mach-O ARC
        if not macho.get("has_arc", True):
            findings.append({
                "id": "IOS-MACHO-NO-ARC",
                "title": "Automatic Reference Counting (ARC) Tidak Diimplementasikan",
                "severity": "MEDIUM",
                "category": "Memory Safety (MASVS-CODE-3)",
                "affected_items": [self.executable_name or "Main Mach-O"],
                "description": "Biner tidak menggunakan ARC modern, meningkatkan risiko memory corruption.",
                "remediation": "Aktifkan CLANG_ENABLE_OBJC_ARC = YES di Build Settings Xcode.",
                "code_fix": "CLANG_ENABLE_OBJC_ARC = YES",
            })
            score -= 10

        # 12. Rootless Jailbreak & Anti-Debugger Gap Check
        has_modern_jb = any(k in self.jailbreak_checks for k in ("Rootless JB (/var/jb)", "Dopamine", "Palera1n", "ElleKit", "PT_DENY_ATTACH"))
        if self.executable_bytes and not has_modern_jb:
            findings.append({
                "id": "IOS-JAILBREAK-HARDENING-GAP",
                "title": "Proteksi Anti-Jailbreak Rootless (iOS 15–18) & Anti-Debugger (PT_DENY_ATTACH) Belum Lengkap",
                "severity": "MEDIUM",
                "category": "Resilience (MASVS-RESILIENCE-1)",
                "affected_items": [
                    f"Terdeteksi saat ini: {', '.join(self.jailbreak_checks) if self.jailbreak_checks else 'Tidak ada'}",
                    "Belum terdeteksi: /var/jb (Dopamine/Palera1n rootless), ElleKit, PT_DENY_ATTACH / sysctl P_TRACED",
                ],
                "description": (
                    "Pemeriksaan jailbreak klasik (Cydia/MobileSubstrate) saja dapat dibypass pada jailbreak rootless "
                    "modern (Dopamine, Palera1n, ElleKit, Shadow/Choicy) dan Frida/LLDB attach."
                ),
                "remediation": (
                    "Tambahkan pemeriksaan path rootless (/var/jb, /var/lib/dpkg, ElleKit), dyld image scan, "
                    "deteksi port Frida 27042, dan proteksi ptrace(PT_DENY_ATTACH) / sysctl P_TRACED di native Swift/C."
                ),
                "code_fix": (
                    "// Anti-Debugger + Rootless Jailbreak Check (Swift/C):\n"
                    "let rootlessPaths = [\"/var/jb\", \"/var/jb/usr/bin/su\", \"/var/jb/Library/MobileSubstrate/DynamicLibraries\", \"/usr/lib/ellekit.dylib\"]\n"
                    "// Panggil ptrace(PT_DENY_ATTACH, 0, 0, 0) via dlsym pada build #if !DEBUG"
                ),
            })
            score -= 6

        # 13. Hardcoded Secrets / API Keys
        if secrets:
            findings.append({
                "id": "IOS-SECRETS-EXPOSED",
                "title": f"Terdeteksi {len(secrets)} Kredensial / API Key Tersimpan dalam Bundle iOS",
                "severity": "HIGH",
                "category": "Storage & Secrets (MASVS-STORAGE-1)",
                "affected_items": [f"{os.path.basename(s['file'])}: {s['type']} ({s['masked_value']})" for s in secrets[:8]],
                "description": "Ditemukan API Key / kredensial sensitif di dalam file plist/konfigurasi di bundle IPA/ZIP.",
                "remediation": (
                    "Batasi API Key Google/Firebase hanya ke Bundle ID aplikasi di Google Cloud Console, "
                    "hapus plist non-prod, dan simpan token/secret privat di backend proxy atau Apple Keychain."
                ),
                "code_fix": (
                    "# Google Cloud Console -> Credentials -> iOS API Key Restriction:\n"
                    "# Restrict key to iOS Bundle ID: " + str(self.info_plist.get("CFBundleIdentifier") or "com.your.app")
                ),
            })
            score -= 12

        # 14. Provisioning Expiration Check
        exp_val = self.provision_data.get("ExpirationDate")
        if isinstance(exp_val, datetime):
            now_dt = datetime.now(timezone.utc) if exp_val.tzinfo else datetime.utcnow()
            if exp_val < now_dt:
                findings.append({
                    "id": "IOS-PROVISION-EXPIRED",
                    "title": "Provisioning Profile Sudah Kedaluwarsa (Install/Launch Akan Gagal)",
                    "severity": "HIGH",
                    "category": "Build & Distribution",
                    "affected_items": [f"ExpirationDate: {exp_val}"],
                    "description": "embedded.mobileprovision telah melewati tanggal kedaluwarsa sehingga aplikasi akan gagal di-install atau crash saat dibuka.",
                    "remediation": "Regenerate Provisioning Profile baru di Apple Developer Portal dan re-sign IPA.",
                    "code_fix": "fastlane sigh --force && fastlane gym",
                })
                score -= 10

        # =====================================================================
        # Extended Pentest-Derived iOS Security Checks (Additive — Ref 5.13–5.38, Obs. A–H, N1–N2)
        # =====================================================================

        # 15. Plaintext App Config Credentials in Bundled Plist (Ref 5.13 / Obs. E)
        if self.plist_credential_keys:
            findings.append({
                "id": "IOS-PLIST-HARDCODED-CREDS",
                "title": f"Terdeteksi {len(self.plist_credential_keys)} Kredensial / Secret Sensitif Hardcoded di Plist Konfigurasi",
                "severity": "HIGH",
                "category": "Storage & Secrets (MASVS-STORAGE-1)",
                "affected_items": [
                    f"{c['file']} -> {c['key']} ({c['masked_value']})"
                    for c in self.plist_credential_keys[:10]
                ],
                "description": (
                    "File konfigurasi .plist di dalam bundle menyimpan kredensial sensitif secara plaintext "
                    "(seperti basic-auth payment gateway, API key chat/Zendesk, kunci enkripsi statis, atau DevKey). "
                    "Siapa pun yang mengekstrak IPA/ZIP dapat langsung membaca seluruh nilai ini."
                ),
                "remediation": (
                    "Pindahkan autentikasi gateway/payment (seperti Basic-Auth APG) ke backend server, rotasi seluruh "
                    "kredensial yang terekspos, dan jangan menyertakan file config Development di target Release."
                ),
                "code_fix": (
                    "// Hindari menyimpan kredensial Basic-Auth / Secret di client plist.\n"
                    "// Gunakan token sesi jangka pendek yang diterbitkan backend setelah autentikasi user."
                ),
            })
            score -= 12

        # 16. Network Debugging Library Linked in Release Binary (Ref N1 — Wormholy / FLEX / Flipper / Netfox)
        if self.debug_network_tools:
            findings.append({
                "id": "IOS-DEBUG-NET-TOOL-RELEASE",
                "title": f"Library Network Debugger Aktif di Biner ({', '.join(self.debug_network_tools[:3])})",
                "severity": "HIGH",
                "category": "Code Quality & Debugging (MASVS-CODE-4)",
                "affected_items": self.debug_network_tools,
                "description": (
                    "Library inspeksi HTTP seperti Wormholy/FLEX/Flipper/Netfox ikut ter-link di biner. "
                    "Wormholy mendaftarkan CustomHTTPProtocol sejak app launch dan merekam seluruh header (Bearer token) "
                    "serta body request ke memori, bahkan saat flag shake-to-open dimatikan."
                ),
                "remediation": (
                    "Jangan link Wormholy/FLEX/Flipper pada target Release (batasi hanya untuk konfigurasi Debug di Podfile/SPM), "
                    "atau guard registrasi URLProtocol dan observer notifikasi di dalam #if DEBUG."
                ),
                "code_fix": (
                    "# Podfile — hanya link di Debug:\n"
                    "pod 'Wormholy', :configurations => ['Debug']\n"
                    "# Verifikasi CI sebelum rilis (harus 0 hasil):\n"
                    "nm -gU Payload/*.app/AppBinary | grep -i wormholy"
                ),
            })
            score -= 10

        # 17. Sensitive Session Tokens Stored in Plaintext NSUserDefaults / SwiftyUserDefaults (Ref Obs. A / 5.30)
        if self.userdefaults_token_indicators:
            findings.append({
                "id": "IOS-USERDEFAULTS-SENSITIVE-TOKENS",
                "title": "Token Sesi & Kredensial Sensitif Berpotensi Disimpan di NSUserDefaults (Plaintext)",
                "severity": "HIGH",
                "category": "Data Storage (MASVS-STORAGE-1)",
                "affected_items": self.userdefaults_token_indicators,
                "description": (
                    "Terdeteksi penggunaan SwiftyUserDefaults/DefaultsKeys bersamaan dengan key token sensitif "
                    "(tempToken, streamToken, zendeskToken, qiscusKey, voip_token). Data pada NSUserDefaults disimpan "
                    "sebagai file plist plaintext di container aplikasi dan ikut dalam backup perangkat."
                ),
                "remediation": (
                    "Migrasikan seluruh token sesi (token, tempToken, member PII, streamToken, zendeskToken, qiscusKey) "
                    "dari UserDefaults ke iOS Keychain dengan kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, "
                    "dan pastikan logout menghapus seluruh item Keychain secara eksplisit."
                ),
                "code_fix": (
                    "// Simpan token di Keychain, bukan UserDefaults:\n"
                    "let query: [String: Any] = [\n"
                    "    kSecClass as String: kSecClassGenericPassword,\n"
                    "    kSecAttrAccount as String: \"auth_token\",\n"
                    "    kSecValueData as String: Data(token.utf8),\n"
                    "    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly\n"
                    "]\n"
                    "SecItemAdd(query as CFDictionary, nil)"
                ),
            })
            score -= 10

        # 18. Dynamic CDN / Remote SSL Pinning Payload Download Risk (Ref 5.24)
        if self.cdn_pinning_indicators:
            findings.append({
                "id": "IOS-DYNAMIC-CDN-SSL-PINNING",
                "title": "Konfigurasi SSL Pinning Dinamis dari CDN Berisiko Bypass Tanpa Frida",
                "severity": "MEDIUM",
                "category": "Network Security (MASVS-NETWORK-2)",
                "affected_items": self.cdn_pinning_indicators,
                "description": (
                    "Terdeteksi mekanisme unduh pin SSL dinamis dari CDN (misal SSLPinningManager / sslPublicKeyHashes / cdn.takdes.net). "
                    "Jika payload hanya dienkripsi kunci statis dari biner tanpa signature asimetris dan diunduh lewat sesi tanpa pinning "
                    "(terutama saat validasi gagal), penyerang dengan CA terpasang dapat menimpa pin secara langsung (MITM)."
                ),
                "remediation": (
                    "Tandatangani payload pin CDN menggunakan Ed25519/ECDSA (verifikasi public key tertanam di biner), "
                    "jangan menimpa pin lokal saat pinning gagal, gunakan pencocokan domain exact-or-subdomain (bukan contains), "
                    "dan hindari pinning pada root CA publik."
                ),
                "code_fix": (
                    "// Verifikasi tanda tangan kriptografi (CryptoKit Curve25519) sebelum menerima pin baru:\n"
                    "guard signingPublicKey.isValidSignature(signature, for: payloadData) else {\n"
                    "    return // Tolak payload pin tak terverifikasi\n"
                    "}"
                ),
            })
            score -= 8

        # 19. Legacy Blowfish Symmetric Cipher in Binary (Ref Obs. D)
        if self.blowfish_indicators:
            findings.append({
                "id": "IOS-BLOWFISH-HARDCODED-CIPHER",
                "title": "Cipher Legacy Blowfish Terdeteksi pada Biner Mach-O (Rentan Sweet32 / Kunci Statis)",
                "severity": "MEDIUM",
                "category": "Cryptography (MASVS-CRYPTO-1)",
                "affected_items": self.blowfish_indicators,
                "description": (
                    "Aplikasi masih memakai algoritma Blowfish (block size 64-bit, sering menggunakan mode ECB dan kunci statis "
                    "yang dibagi antara iOS & Android) untuk mengenkripsi body request sensitif atau hasil security check."
                ),
                "remediation": (
                    "Migrasi dari Blowfish/ECB ke AES-256-GCM (CryptoKit AES.GCM) dengan key versioning di backend "
                    "dan lakukan rotasi kunci serentak antara iOS, Android, dan server."
                ),
                "code_fix": (
                    "import CryptoKit\n"
                    "let sealedBox = try AES.GCM.seal(payloadData, using: symmetricKey)\n"
                    "let combined = sealedBox.combined // nonce + ciphertext + auth tag"
                ),
            })
            score -= 7

        # 20. Direct Client-Side Google Maps Geocode API & Header Leakage Risk (Ref 5.18 / Obs. B)
        if self.google_geocode_indicators:
            findings.append({
                "id": "IOS-GOOGLE-MAPS-CLIENT-GEOCODE",
                "title": "Panggilan Langsung REST API Google Maps Geocode dari Klien (Risiko Quota Abuse & Header Leak)",
                "severity": "MEDIUM",
                "category": "Network & API Security (MASVS-NETWORK-1)",
                "affected_items": self.google_geocode_indicators,
                "description": (
                    "Aplikasi memanggil endpoint https://maps.googleapis.com/maps/api/geocode langsung dari klien dengan "
                    "API key di dalam biner. Jika memakai defaultHeader(), header Authorization: Bearer <token> dan ID member "
                    "juga berisiko ikut terkirim ke server pihak ketiga (Google)."
                ),
                "remediation": (
                    "Kirim header minimal (tanpa Authorization / member ID) pada request ke maps.googleapis.com, "
                    "batasi API key di GCP Console (atau proksikan geocoding melalui backend Anda sendiri)."
                ),
                "code_fix": (
                    "// SearchLocationAPI / SelectLocationPointAPI:\n"
                    "var headers: [String: String]? {\n"
                    "    return [\"Content-Type\": \"application/json\"] // Jangan pakai defaultHeader() dengan Bearer token!\n"
                    "}"
                ),
            })
            score -= 6

        # 21. WKWebView Cookie Token Injection & Auth Challenge Validation (Ref Obs. C / Obs. F)
        if self.webview_auth_indicators:
            findings.append({
                "id": "IOS-WEBVIEW-COOKIE-AUTH-RISK",
                "title": "Risiko Injeksi Token Cookie WKWebView & Validasi Auth Challenge WebView",
                "severity": "MEDIUM",
                "category": "Platform Interaction (MASVS-PLATFORM-2)",
                "affected_items": self.webview_auth_indicators,
                "description": (
                    "Terdeteksi penanganan cookie WebView dan URLCredential / didReceiveAuthenticationChallenge. "
                    "Menyuntikkan Bearer token sebagai HTTPCookie tanpa allowlist host ketat berisiko membocorkan token ke domain luar; "
                    "membalas semua challenge WebView tanpa memeriksa authenticationMethod dan host berisiko membocorkan kredensial."
                ),
                "remediation": (
                    "Terapkan allowlist domain ketat (exact-or-subdomain) sebelum menyuntikkan cookie token ke WKWebView, "
                    "serta validasi protectionSpace.authenticationMethod == NSURLAuthenticationMethodHTTPBasic dan host target "
                    "sebelum memanggil completionHandler(.useCredential, ...)."
                ),
                "code_fix": (
                    "guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodHTTPBasic,\n"
                    "      challenge.protectionSpace.host == \"apg.alfagift.id\" else {\n"
                    "    completionHandler(.performDefaultHandling, nil)\n"
                    "    return\n"
                    "}"
                ),
            })
            score -= 6

        # 22. Background Audio Mode Combined with Audio/Ultrasonic SDK (Ref 5.19)
        if len(self.background_audio_indicators) >= 2:
            findings.append({
                "id": "IOS-BACKGROUND-AUDIO-SDK",
                "title": "Mode Background Audio Aktif Bersamaan dengan SDK Perekaman Audio / Ultrasonik",
                "severity": "MEDIUM",
                "category": "Privacy & Permissions (MASVS-PLATFORM-1)",
                "affected_items": self.background_audio_indicators,
                "description": (
                    "Info.plist mengaktifkan UIBackgroundModes='audio' bersamaan dengan izin mikrofon dan SDK audio/ultrasonik "
                    "(seperti ToneTag / SoundWaveRecorder). Jika perekaman tidak dihentikan otomatis saat keluar layar atau "
                    "app masuk background, mikrofon dapat terus merekam di latar belakang."
                ),
                "remediation": (
                    "Hentikan sesi perekaman audio (stopRecording) secara otomatis pada viewWillDisappear dan "
                    "UIApplication.didEnterBackgroundNotification, serta audit apakah UIBackgroundModes 'audio' benar-benar dibutuhkan."
                ),
                "code_fix": (
                    "NotificationCenter.default.addObserver(\n"
                    "    forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: .main\n"
                    ") { _ in SoundWaveRecorder.shared.stopRecording() }"
                ),
            })
            score -= 5

        # 23. Keychain Accessibility Attribute Audit (Ref N2)
        if self.keychain_indicators:
            findings.append({
                "id": "IOS-KEYCHAIN-ACCESSIBILITY-AUDIT",
                "title": "Audit Atribut Keamanan Keychain (kSecAttrAccessibleThisDeviceOnly & Pembersihan Saat Logout)",
                "severity": "MEDIUM",
                "category": "Data Storage (MASVS-STORAGE-1)",
                "affected_items": self.keychain_indicators,
                "description": (
                    "Aplikasi menggunakan Keychain (SecItemAdd / KeychainServiceManager). Jika item Keychain tidak secara eksplisit "
                    "menyetel kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly (atau WhenUnlockedThisDeviceOnly), iOS memakai default "
                    "kSecAttrAccessibleWhenUnlocked yang ikut tersalin pada backup terenkripsi ke perangkat lain."
                ),
                "remediation": (
                    "Pastikan seluruh operasi SecItemAdd/SecItemUpdate menetapkan kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly "
                    "untuk token, deviceId, hasil securityCheck, dan pin SSL, serta hapus seluruh item Keychain sensitif saat logout."
                ),
                "code_fix": (
                    "query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly\n"
                    "// Saat logout: pastikan SecItemDelete dipanggil untuk semua key sesi & token."
                ),
            })
            score -= 4

        # 24. URLSessionConfiguration.default / URLCache Caching Risk for Authenticated APIs (Ref 5.31)
        if self.urlcache_indicators:
            findings.append({
                "id": "IOS-URLCACHE-AUTH-HARDENING",
                "title": "Hardening URLCache pada Sesi API Terautentikasi (URLSessionConfiguration.default)",
                "severity": "LOW",
                "category": "Data Storage (MASVS-STORAGE-2)",
                "affected_items": self.urlcache_indicators,
                "description": (
                    "Sesi jaringan API menggunakan URLSessionConfiguration.default yang terhubung ke URLCache.shared (Cache.db). "
                    "Respons GET yang cacheable beserta header Authorization: Bearer dapat tersimpan ke disk Cache.db secara plaintext."
                ),
                "remediation": (
                    "Setel configuration.urlCache = nil dan configuration.requestCachePolicy = .reloadIgnoringLocalCacheData "
                    "(atau gunakan .ephemeral) untuk seluruh sesi API yang membawa token autentikasi."
                ),
                "code_fix": (
                    "let config = URLSessionConfiguration.default\n"
                    "config.urlCache = nil\n"
                    "config.requestCachePolicy = .reloadIgnoringLocalCacheData"
                ),
            })
            score -= 3

        # 25. Facebook Client Token Hardcoded in Info.plist (Ref 5.27)
        if self.facebook_tokens:
            findings.append({
                "id": "IOS-FACEBOOK-CLIENT-TOKEN",
                "title": "Facebook Client Token & App ID Tertanam di Info.plist",
                "severity": "LOW",
                "category": "Storage & Secrets (MASVS-STORAGE-1)",
                "affected_items": self.facebook_tokens,
                "description": (
                    "FacebookClientToken dan FacebookAppID tersimpan di Info.plist. Meskipun client token bersifat publik "
                    "by design untuk SDK Facebook, penyalahgunaan dapat terjadi bila pembatasan di Meta Developer Console longgar."
                ),
                "remediation": (
                    "Aktifkan pembatasan Bundle ID, Require App Secret Proof untuk panggilan Graph API server-side, "
                    "dan audit izin SDK di Meta Developer Console."
                ),
                "code_fix": "# Meta Developer Console -> Settings -> Advanced -> Require App Secret = ON",
            })
            score -= 2

        # 26. Developer Xcode Local Build Paths & Username Disclosure (Ref 5.37)
        if self.dev_build_paths:
            findings.append({
                "id": "IOS-DEV-PATH-DISCLOSURE",
                "title": f"Kebocoran Path Build Lokal Xcode & Username Developer di Biner ({len(self.dev_build_paths)}+ path)",
                "severity": "LOW",
                "category": "Code Quality & Build Hygiene (MASVS-CODE-4)",
                "affected_items": self.dev_build_paths[:5],
                "description": (
                    "Literal #file / #filePath yang terkompilasi ke dalam biner membocorkan struktur direktori lokal dan "
                    "username mesin developer (/Users/...). Ini juga menandakan build dikompilasi di mesin lokal, bukan CI bersih."
                ),
                "remediation": (
                    "Bangun artefak rilis di runner CI/CD dengan path netral, aktifkan STRIP_INSTALLED_PRODUCT=YES, "
                    "dan tambahkan -file-prefix-map / -debug-prefix-map pada OTHER_SWIFT_FLAGS & OTHER_CFLAGS."
                ),
                "code_fix": (
                    "# Xcode Build Settings (Release):\n"
                    "OTHER_SWIFT_FLAGS = $(inherited) -Xfrontend -debug-prefix-map -Xfrontend $(SRCROOT)=.\n"
                    "STRIP_INSTALLED_PRODUCT = YES"
                ),
            })
            score -= 2

        # 27. FairPlay Encryption (CryptID=0) Build-Type Diagnostic (Ref 5.25)
        if self.executable_bytes and macho.get("binary_size_mb", 0) > 0.5 and not macho.get("is_encrypted", False):
            findings.append({
                "id": "IOS-BINARY-UNENCRYPTED-NOTE",
                "title": "Biner Mach-O Tidak Terenkripsi FairPlay (CryptID = 0 — Build Non-AppStore / Dev / Ad-Hoc)",
                "severity": "LOW",
                "category": "Build & Distribution (MASVS-RESILIENCE-3)",
                "affected_items": [f"{self.executable_name}: crypt_id=0 (unencrypted Mach-O)"],
                "description": (
                    "Biner utama memiliki CryptID = 0 (tidak terenkripsi FairPlay DRM). Ini normal untuk IPA hasil export "
                    "Development/Ad-Hoc sebelum masuk App Store (Apple otomatis menerapkan FairPlay saat distribusi App Store), "
                    "namun memudahkan reverse-engineering bila file build uji tersebar ke publik."
                ),
                "remediation": (
                    "Batasi distribusi IPA uji (Development/Ad-Hoc) hanya ke perangkat internal/TestFlight dan pastikan "
                    "rilis produksi didistribusikan melalui App Store (CryptID = 1)."
                ),
                "code_fix": "# Verifikasi FairPlay pada IPA App Store:\notool -l Payload/*.app/AppBinary | grep -A 4 LC_ENCRYPTION_INFO",
            })
            score -= 2

        score = max(5, min(100, score))

        if score >= 80:
            posture = "GOOD"
        elif score >= 50:
            posture = "MODERATE"
        else:
            posture = "CRITICAL RISK"

        return findings, score, posture

    def _group_owasp(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.get("severity", "LOW")
            if sev in counts:
                counts[sev] += 1
        return counts
