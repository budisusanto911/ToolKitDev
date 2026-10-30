#!/usr/bin/env python3
"""
ToolKitDev - iOS (.ipa) Teardown & Security Inspector
Deconstructs iOS IPA packages, parses Info.plist & embedded.mobileprovision entitlements,
inspects Mach-O binary security flags (PIE, ARC, Stack Canaries, FairPlay CryptID),
and performs deep static secrets and API endpoint auditing.
"""

import os
import io
import re
import math
import struct
import zipfile
import plistlib
from typing import Dict, Any, List, Optional, Tuple


class IpaAnalyzer:
    def __init__(self, ipa_path: str):
        self.ipa_path = ipa_path
        self.filename = os.path.basename(ipa_path)
        self.filesize = os.path.getsize(ipa_path) if os.path.isfile(ipa_path) else 0

        # Discovered structures
        self.app_dir_name: str = ""
        self.info_plist: Dict[str, Any] = {}
        self.provision_data: Dict[str, Any] = {}
        self.entitlements: Dict[str, Any] = {}
        self.executable_name: str = ""
        self.executable_bytes: bytes = b""

    def analyze(self) -> Dict[str, Any]:
        """Main analysis runner for iOS IPA packages."""
        if not os.path.isfile(self.ipa_path):
            raise FileNotFoundError(f"File IPA tidak ditemukan: {self.ipa_path}")

        with zipfile.ZipFile(self.ipa_path, "r") as z:
            namelist = z.namelist()

            # Locate Payload/*.app folder
            for name in namelist:
                if name.startswith("Payload/") and name.endswith(".app/"):
                    self.app_dir_name = name
                    break

            if not self.app_dir_name:
                # Fallback search
                for name in namelist:
                    if ".app/" in name:
                        self.app_dir_name = name[:name.index(".app/") + 5]
                        break

            # 1. Parse Info.plist
            self._parse_info_plist(z)

            # 2. Parse embedded.mobileprovision & Entitlements
            self._parse_mobileprovision(z)

            # 3. Extract and inspect Mach-O main binary
            macho_analysis = self._inspect_macho_binary(z)

            # 4. Scan strings for secrets & endpoints
            secrets, endpoints = self._extract_secrets_and_endpoints(z)

        # 5. Evaluate findings and security score
        findings, score, posture = self._evaluate_security_posture(macho_analysis, secrets, endpoints)

        return {
            "platform": "ios",
            "file_info": {
                "name": self.filename,
                "size_bytes": self.filesize,
                "size_mb": round(self.filesize / (1024 * 1024), 2),
                "app_dir": self.app_dir_name
            },
            "metadata": {
                "app_name": self.info_plist.get("CFBundleDisplayName") or self.info_plist.get("CFBundleName") or "iOS App",
                "bundle_id": self.info_plist.get("CFBundleIdentifier") or "unknown.bundle.id",
                "version_name": str(self.info_plist.get("CFBundleShortVersionString") or "1.0"),
                "build_number": str(self.info_plist.get("CFBundleVersion") or "1"),
                "min_os_version": str(self.info_plist.get("MinimumOSVersion") or "14.0"),
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
                "is_expired": False,
            },
            "macho_protections": macho_analysis,
            "url_schemes": self._extract_url_schemes(),
            "privacy_permissions": self._extract_privacy_permissions(),
            "secrets": secrets,
            "endpoints": endpoints,
            "findings": findings,
            "owasp_summary": self._group_owasp(findings)
        }

    def _parse_info_plist(self, z: zipfile.ZipFile):
        plist_path = f"{self.app_dir_name}Info.plist"
        if plist_path in z.namelist():
            try:
                raw_data = z.read(plist_path)
                self.info_plist = plistlib.loads(raw_data)
                self.executable_name = self.info_plist.get("CFBundleExecutable", "")
            except Exception as e:
                self.info_plist = {"error": f"Failed to parse Info.plist: {e}"}

    def _parse_mobileprovision(self, z: zipfile.ZipFile):
        prov_path = f"{self.app_dir_name}embedded.mobileprovision"
        if prov_path in z.namelist():
            try:
                raw_bytes = z.read(prov_path)
                # embedded.mobileprovision is a signed CMS container holding an XML plist
                # Find <?xml and </plist> tags
                start_idx = raw_bytes.find(b"<?xml")
                end_idx = raw_bytes.find(b"</plist>")
                if start_idx != -1 and end_idx != -1:
                    xml_bytes = raw_bytes[start_idx:end_idx + 8]
                    self.provision_data = plistlib.loads(xml_bytes)
                    self.entitlements = self.provision_data.get("Entitlements", {})
            except Exception:
                self.provision_data = {}
                self.entitlements = {}

    def _inspect_macho_binary(self, z: zipfile.ZipFile) -> Dict[str, Any]:
        """Inspects Mach-O load commands, protection flags, and symbol footprints."""
        result = {
            "has_pie": False,
            "has_stack_canaries": False,
            "has_arc": False,
            "is_encrypted": False,
            "crypt_id": 0,
            "architectures": [],
            "linked_frameworks": []
        }

        exec_path = f"{self.app_dir_name}{self.executable_name}" if self.executable_name else ""
        if not exec_path or exec_path not in z.namelist():
            # Try to find file without extension in app_dir
            for name in z.namelist():
                if name.startswith(self.app_dir_name) and "/" not in name[len(self.app_dir_name):] and "." not in name[len(self.app_dir_name):]:
                    exec_path = name
                    self.executable_name = os.path.basename(name)
                    break

        if not exec_path or exec_path not in z.namelist():
            return result

        try:
            self.executable_bytes = z.read(exec_path)
            data = self.executable_bytes

            # Check Mach-O Header Magic
            # 0xfeedface = 32-bit, 0xfeedfacf = 64-bit, 0xcafebabe = Fat/Universal
            if len(data) >= 32:
                magic = struct.unpack(">I", data[:4])[0]
                magic_le = struct.unpack("<I", data[:4])[0]

                if magic == 0xcafebabe or magic_le == 0xcafebabe:
                    result["architectures"].append("Universal/FAT")
                elif magic == 0xfeedfacf or magic_le == 0xfeedfacf:
                    result["architectures"].append("arm64 / x86_64")
                    # Check MH_PIE flag (0x00200000) at offset 24 (flags)
                    flags = struct.unpack("<I", data[24:28])[0] if magic_le == 0xfeedfacf else struct.unpack(">I", data[24:28])[0]
                    if flags & 0x00200000:
                        result["has_pie"] = True
                elif magic == 0xfeedface or magic_le == 0xfeedface:
                    result["architectures"].append("armv7 / 32-bit")
                    flags = struct.unpack("<I", data[24:28])[0] if magic_le == 0xfeedface else struct.unpack(">I", data[24:28])[0]
                    if flags & 0x00200000:
                        result["has_pie"] = True

            # Scan binary strings for Stack Canaries and ARC symbols
            if b"___stack_chk_fail" in data or b"___stack_chk_guard" in data:
                result["has_stack_canaries"] = True

            if b"_objc_release" in data or b"_objc_retain" in data or b"_objc_storeStrong" in data:
                result["has_arc"] = True

            # Check Encryption Info (FairPlay CryptID)
            # LC_ENCRYPTION_INFO = 0x21, LC_ENCRYPTION_INFO_64 = 0x2C
            # Search byte signature for cryptid
            cryptid_matches = re.findall(b"(\\x2c|\\x21)\\x00\\x00\\x00.{8}(\\x01|\\x00)\\x00\\x00\\x00", data[:65536], re.DOTALL)
            for cmd, cid in cryptid_matches:
                if cid == b"\x01":
                    result["is_encrypted"] = True
                    result["crypt_id"] = 1
                    break

            # Find linked frameworks
            framework_matches = re.findall(rb"([A-Za-z0-9_]+)\.framework", data)
            frameworks = set()
            for fm in framework_matches:
                try:
                    name = fm.decode("utf-8")
                    if len(name) > 2 and len(name) < 40:
                        frameworks.add(name)
                except Exception:
                    pass
            result["linked_frameworks"] = sorted(list(frameworks))[:15]

        except Exception as e:
            result["error"] = str(e)

        return result

    def _evaluate_ats(self) -> Dict[str, Any]:
        """Audits App Transport Security (ATS) configuration."""
        ats = self.info_plist.get("NSAppTransportSecurity", {})
        arbitrary_loads = ats.get("NSAllowsArbitraryLoads", False)
        web_arbitrary = ats.get("NSAllowsArbitraryLoadsInWebContent", False)
        exceptions = ats.get("NSExceptionDomains", {})

        return {
            "allows_arbitrary_loads": arbitrary_loads,
            "allows_arbitrary_loads_in_web": web_arbitrary,
            "has_exception_domains": len(exceptions) > 0,
            "exception_domain_count": len(exceptions),
            "exception_domains": list(exceptions.keys()) if isinstance(exceptions, dict) else [],
            "status": "VULNERABLE" if arbitrary_loads else ("WARNING" if web_arbitrary or exceptions else "SECURE")
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
        return sorted(list(set(schemes)))

    def _extract_privacy_permissions(self) -> List[Dict[str, str]]:
        perms = []
        for key, val in self.info_plist.items():
            if key.startswith("NS") and "UsageDescription" in key:
                name = key.replace("NS", "").replace("UsageDescription", "")
                perms.append({
                    "permission": key,
                    "category": name,
                    "description": str(val)
                })
        return perms

    def _extract_secrets_and_endpoints(self, z: zipfile.ZipFile) -> Tuple[List[Dict[str, Any]], List[str]]:
        secrets = []
        endpoints = set()

        secret_regexes = [
            ("Google / Firebase API Key", r"AIza[0-9A-Za-z\-_]{35}"),
            ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}"),
            ("Slack Webhook URL", r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+"),
            ("JSON Web Token (JWT)", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
            ("Generic Private Key Header", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")
        ]

        # Scan text files and binary chunks
        scanned_files = 0
        for name in z.namelist():
            if scanned_files > 40:
                break
            if name.endswith(".plist") or name.endswith(".json") or name.endswith(".strings") or name.endswith(".bundle"):
                try:
                    content = z.read(name).decode("utf-8", errors="ignore")
                    scanned_files += 1

                    # Scan for secrets
                    for label, pattern in secret_regexes:
                        for match in re.finditer(pattern, content):
                            val = match.group(0)
                            masked = val[:6] + "..." + val[-4:] if len(val) > 10 else "***"
                            secrets.append({
                                "type": label,
                                "file": name,
                                "masked_value": masked,
                                "severity": "HIGH"
                            })

                    # Scan for endpoints
                    url_matches = re.findall(r"https?://[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}(?:/[^\s\"'<>]*)?", content)
                    for url in url_matches:
                        if len(url) < 120 and "apple.com" not in url and "w3.org" not in url:
                            endpoints.add(url)
                except Exception:
                    pass

        # Also search executable bytes for URLs if available
        if self.executable_bytes:
            bin_text = self.executable_bytes[:1000000].decode("latin-1", errors="ignore")
            url_matches = re.findall(r"https://[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}(?:/[a-zA-Z0-9_\-\./\?=]*)?", bin_text)
            for url in url_matches[:25]:
                if len(url) < 100 and "apple.com" not in url:
                    endpoints.add(url)

        return secrets[:15], sorted(list(endpoints))[:30]

    def _evaluate_security_posture(
        self,
        macho: Dict[str, Any],
        secrets: List[Dict[str, Any]],
        endpoints: List[str]
    ) -> Tuple[List[Dict[str, Any]], int, str]:
        findings = []
        score = 100

        # 1. ATS NSAllowsArbitraryLoads Check
        ats = self.info_plist.get("NSAppTransportSecurity", {})
        if ats.get("NSAllowsArbitraryLoads", False):
            findings.append({
                "id": "IOS-ATS-CLEARTEXT",
                "title": "App Transport Security (ATS) Dinonaktifkan Secara Penuh",
                "severity": "CRITICAL",
                "category": "Network Security (MASVS-NETWORK-1)",
                "description": "Aplikasi mendefinisikan NSAllowsArbitraryLoads=true di Info.plist. Hal ini mematikan proteksi enkripsi TLS iOS dan mengizinkan transmisi data melalui HTTP plaintext yang rentan penyadapan Man-In-The-Middle (MITM).",
                "remediation": "Hapus flag NSAllowsArbitraryLoads atau batasi hanya pada domain legacy spesifik di bawah NSExceptionDomains."
            })
            score -= 30

        # 2. Entitlement get-task-allow (Debuggable in Production)
        if self.entitlements.get("get-task-allow", False):
            findings.append({
                "id": "IOS-DEBUG-ATTACH",
                "title": "Aplikasi Debuggable di Lingkungan Produksi (get-task-allow: true)",
                "severity": "CRITICAL",
                "category": "Platform Interaction (MASVS-PLATFORM-2)",
                "description": "Entitlement get-task-allow aktif memungkinkan penyerang menempelkan debugger (LLDB, Frida) ke proses aplikasi untuk membaca memori runtime dan membongkar logika autentikasi.",
                "remediation": "Pastikan build profile menggunakan distribution/production provisioning profile dengan get-task-allow diset false."
            })
            score -= 25

        # 3. Mach-O PIE (Position Independent Executable / ASLR)
        if not macho.get("has_pie", True):
            findings.append({
                "id": "IOS-MACHO-NO-PIE",
                "title": "Mach-O Binary Tidak Mengaktifkan Flag PIE (Position Independent Executable)",
                "severity": "HIGH",
                "category": "Code Quality (MASVS-CODE-1)",
                "description": "Biner dikompilasi tanpa flag -fPIE / MH_PIE, sehingga Address Space Layout Randomization (ASLR) tidak aktif sepenuhnya pada ruang memori aplikasi.",
                "remediation": "Aktifkan 'Generate Position-Dependent Code' = NO di Build Settings Xcode."
            })
            score -= 20

        # 4. Mach-O Stack Canaries
        if not macho.get("has_stack_canaries", True):
            findings.append({
                "id": "IOS-MACHO-NO-CANARY",
                "title": "Proteksi Stack Canary Tidak Terdeteksi",
                "severity": "HIGH",
                "category": "Code Quality (MASVS-CODE-2)",
                "description": "Symbol ___stack_chk_fail tidak ditemukan pada biner aplikasi, menandakan buffer overflow protection tidak aktif.",
                "remediation": "Tambahkan flag kompilator '-fstack-protector-all' pada compiler flags Xcode."
            })
            score -= 15

        # 5. Mach-O ARC
        if not macho.get("has_arc", True):
            findings.append({
                "id": "IOS-MACHO-NO-ARC",
                "title": "Automatic Reference Counting (ARC) Tidak Diimplementasikan",
                "severity": "MEDIUM",
                "category": "Memory Safety (MASVS-CODE-3)",
                "description": "Biner tidak menggunakan ARC modern, meningkatkan risiko kerentanan manajemen memori use-after-free atau double-free.",
                "remediation": "Aktifkan 'Objective-C Automatic Reference Counting' (CLANG_ENABLE_OBJC_ARC = YES) di Xcode."
            })
            score -= 10

        # 6. Hardcoded Secrets
        if secrets:
            findings.append({
                "id": "IOS-SECRETS-EXPOSED",
                "title": f"Terdeteksi {len(secrets)} Kredensial / Secret Kritis Tersimpan dalam File IPA",
                "severity": "HIGH",
                "category": "Storage & Secrets (MASVS-STORAGE-1)",
                "description": f"Ditemukan string sensitif (API Keys, JWT, dsb.) di dalam biner atau aset IPA.",
                "remediation": "Pindahkan API Key ke backend proxy server atau enkripsi menggunakan Apple Keychain."
            })
            score -= 15

        # Bound score between 0 and 100
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

