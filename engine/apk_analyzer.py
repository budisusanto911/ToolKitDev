"""
ToolKitDev - APK Teardown & Security Inspector Engine
Performs comprehensive static analysis on Android APK/AAB binaries:
- Manifest security flags (debuggable, allowBackup, cleartextTraffic)
- Exported components (activities, services, receivers, providers)
- Sensitive & third-party debug component exposure (MoEDebuggerActivity, Payment/Binding)
- Network Security Config & Cleartext Staging Domain Audit
- Cryptographic Audit (Blowfish, Insecure ECB mode, static keys/IVs)
- Biometric Authentication Implementation (CryptoObject verification)
- Anti-Tamper, Root, Frida & Emulator Defense Verification
- Secret & Credential Scanning (Google Maps, Firebase, tokens, JSON configs)
- Backend Endpoint & Actuator Exposure Hunter
- Binary size breakdown & signature certificate audit
- Dynamic Security Score computation (0-100)
"""

import os
import re
import json
import zipfile
import subprocess
from typing import Dict, Any, List, Set, Tuple

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CALENDAR": "Access user's calendar data",
    "android.permission.WRITE_CALENDAR": "Modify user's calendar data",
    "android.permission.CAMERA": "Access camera device",
    "android.permission.READ_CONTACTS": "Access user's contacts list",
    "android.permission.WRITE_CONTACTS": "Modify user's contacts list",
    "android.permission.GET_ACCOUNTS": "Access device accounts list",
    "android.permission.ACCESS_FINE_LOCATION": "Access precise GPS location",
    "android.permission.ACCESS_COARSE_LOCATION": "Access approximate network location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "Access location in background",
    "android.permission.RECORD_AUDIO": "Record audio through microphone",
    "android.permission.READ_PHONE_STATE": "Read phone status, IMEI, and network state",
    "android.permission.CALL_PHONE": "Initiate phone calls without user confirmation",
    "android.permission.READ_CALL_LOG": "Read call history",
    "android.permission.WRITE_CALL_LOG": "Modify call history",
    "android.permission.ADD_VOICEMAIL": "Access voicemail system",
    "android.permission.USE_SIP": "Use SIP service",
    "android.permission.BODY_SENSORS": "Access biometric sensors (heart rate, etc.)",
    "android.permission.SEND_SMS": "Send SMS messages (potential carrier cost)",
    "android.permission.RECEIVE_SMS": "Intercept incoming SMS messages",
    "android.permission.READ_SMS": "Read SMS inbox (high risk for OTP leakage)",
    "android.permission.RECEIVE_WAP_PUSH": "Receive WAP push messages",
    "android.permission.RECEIVE_MMS": "Monitor incoming MMS messages",
    "android.permission.READ_EXTERNAL_STORAGE": "Read files on external storage",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Write files to external storage",
    "android.permission.READ_MEDIA_IMAGES": "Access photos and images",
    "android.permission.READ_MEDIA_VIDEO": "Access video files",
    "android.permission.READ_MEDIA_AUDIO": "Access audio files",
    "android.permission.POST_NOTIFICATIONS": "Display push notifications",
    "android.permission.BLUETOOTH_CONNECT": "Connect to paired Bluetooth devices",
    "android.permission.BLUETOOTH_SCAN": "Scan for nearby Bluetooth devices",
}

SECRET_PATTERNS = [
    ("Google API Key / Firebase", re.compile(rb"AIza[0-9A-Za-z\\-_]{35}")),
    ("AWS Access Key ID", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("GitHub Token", re.compile(rb"gh[pous]_[0-9A-Za-z]{36}")),
    ("Slack Webhook / Token", re.compile(rb"xox[baprs]-[0-9A-Za-z\\-_]{10,48}")),
    ("JWT Token", re.compile(rb"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Private Key Header", re.compile(rb"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("Generic Bearer Secret", re.compile(rb"bearer [a-zA-Z0-9_\-\.]{24,}", re.IGNORECASE)),
]


class ApkAnalyzer:
    def __init__(self, apk_path: str):
        self.apk_path = os.path.abspath(apk_path)
        if not os.path.isfile(self.apk_path):
            raise FileNotFoundError(f"APK/AAB file not found: {self.apk_path}")
        self.is_aab = self.apk_path.lower().endswith(".aab")
        self._cached_dex_bytes: List[bytes] = []

    def _get_dex_bytes(self) -> List[bytes]:
        """Load and cache DEX file bytes from APK/AAB archive."""
        if not self._cached_dex_bytes:
            try:
                with zipfile.ZipFile(self.apk_path, "r") as z:
                    for name in z.namelist():
                        if name.endswith(".dex"):
                            self._cached_dex_bytes.append(z.read(name))
            except Exception:
                pass
        return self._cached_dex_bytes

    def analyze(self) -> Dict[str, Any]:
        """Run full static analysis suite on the APK/AAB binary."""
        file_size = os.path.getsize(self.apk_path)
        badging = self._parse_badging()
        manifest_tree = self._parse_manifest_tree()
        zip_breakdown = self._analyze_zip_contents()
        secrets = self._scan_secrets()
        cert_info = self._audit_signature()

        # Advanced Security Audits
        crypto_audit = self._audit_crypto()
        net_sec_audit = self._audit_network_security_config()
        sensitive_comps = self._audit_sensitive_exported_components(manifest_tree)
        biometric_audit = self._audit_biometric_auth()
        anti_tamper_audit = self._audit_anti_tamper()
        endpoint_audit = self._audit_endpoints()

        # Compute Security Score & Findings
        findings, security_score = self._compute_security_score(
            badging, manifest_tree, secrets, cert_info,
            crypto_audit, net_sec_audit, sensitive_comps,
            biometric_audit, anti_tamper_audit, endpoint_audit
        )
        
        qa_metrics = self._evaluate_qa_metrics(badging, zip_breakdown)

        return {
            "file_info": {
                "file_name": os.path.basename(self.apk_path),
                "file_size": file_size,
                "file_size_formatted": self._format_size(file_size),
                "path": self.apk_path,
                "format": "AAB" if self.is_aab else "APK"
            },
            "metadata": badging,
            "manifest_security": manifest_tree,
            "permissions": self._categorize_permissions(badging.get("permissions", [])),
            "size_breakdown": zip_breakdown,
            "secrets_found": secrets,
            "signature": cert_info,
            "crypto_audit": crypto_audit,
            "network_security_audit": net_sec_audit,
            "sensitive_components": sensitive_comps,
            "biometric_audit": biometric_audit,
            "anti_tamper_audit": anti_tamper_audit,
            "endpoint_audit": endpoint_audit,
            "security_score": security_score,
            "findings": findings,
            "qa_metrics": qa_metrics
        }

    def _parse_badging(self) -> Dict[str, Any]:
        """Parse badging information via aapt or fallback to zip archive introspection."""
        meta = {
            "package_name": "unknown",
            "version_code": "unknown",
            "version_name": "unknown",
            "compile_sdk": "unknown",
            "min_sdk": "unknown",
            "target_sdk": "unknown",
            "app_label": "Unknown Application",
            "permissions": []
        }
        
        # 1. Try aapt if standard APK
        if not self.is_aab:
            try:
                cmd = ["aapt", "dump", "badging", self.apk_path]
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=15).decode("utf-8", errors="replace")
                
                pkg_match = re.search(r"package:\s+name='([^']+)'(?:\s+versionCode='([^']+)')?(?:\s+versionName='([^']+)')?", output)
                if pkg_match:
                    meta["package_name"] = pkg_match.group(1) or "unknown"
                    meta["version_code"] = pkg_match.group(2) or "unknown"
                    meta["version_name"] = pkg_match.group(3) or "unknown"

                min_match = re.search(r"sdkVersion:'([^']+)'", output)
                if min_match:
                    meta["min_sdk"] = min_match.group(1)

                target_match = re.search(r"targetSdkVersion:'([^']+)'", output)
                if target_match:
                    meta["target_sdk"] = target_match.group(1)

                compile_match = re.search(r"compileSdkVersion='([^']+)'", output)
                if compile_match:
                    meta["compile_sdk"] = compile_match.group(1)

                label_match = re.search(r"application-label(?:-[a-zA-Z0-9]+)?:'([^']+)'", output)
                if label_match:
                    meta["app_label"] = label_match.group(1)

                perms = re.findall(r"uses-permission:\s+name='([^']+)'", output)
                meta["permissions"] = sorted(list(set(perms)))
                if meta["package_name"] != "unknown":
                    return meta
            except Exception:
                pass

        # 2. Fallback / AAB parser using raw manifest inspection
        try:
            with zipfile.ZipFile(self.apk_path, "r") as z:
                manifest_path = "base/manifest/AndroidManifest.xml" if self.is_aab else "AndroidManifest.xml"
                if manifest_path in z.namelist():
                    raw = z.read(manifest_path)
                    
                    pkg_m = re.search(rb"package[\x00-\x20\"=]+([a-zA-Z0-9_\.]{4,})", raw)
                    if pkg_m:
                        meta["package_name"] = pkg_m.group(1).decode("utf-8", errors="ignore")
                    
                    ver_code_m = re.search(rb"versionCode[\x00-\x20\"=]+([0-9]{1,10})", raw)
                    if ver_code_m:
                        meta["version_code"] = ver_code_m.group(1).decode("utf-8", errors="ignore")

                    ver_name_m = re.search(rb"versionName[\x00-\x20\"=]+([0-9a-zA-Z\.\-_]{1,30})", raw)
                    if ver_name_m:
                        meta["version_name"] = ver_name_m.group(1).decode("utf-8", errors="ignore")

                    min_sdk_m = re.search(rb"minSdkVersion[\x00-\x20\"=]+([0-9]{1,3})", raw)
                    if min_sdk_m:
                        meta["min_sdk"] = min_sdk_m.group(1).decode("utf-8", errors="ignore")

                    target_sdk_m = re.search(rb"targetSdkVersion[\x00-\x20\"=]+([0-9]{1,3})", raw)
                    if target_sdk_m:
                        meta["target_sdk"] = target_sdk_m.group(1).decode("utf-8", errors="ignore")

                    perms = re.findall(rb"android\.permission\.[A-Z0-9_]+", raw)
                    if perms:
                        meta["permissions"] = sorted(list(set([p.decode("utf-8", errors="ignore") for p in perms])))

                    if meta["package_name"] != "unknown":
                        parts = meta["package_name"].split(".")
                        meta["app_label"] = parts[-1].capitalize() if parts else "Android App"
        except Exception as e:
            meta["error"] = str(e)

        return meta

    def _parse_manifest_tree(self) -> Dict[str, Any]:
        """Parse AndroidManifest.xml xmltree to check security attributes and exported components."""
        info = {
            "debuggable": False,
            "allow_backup": True,
            "uses_cleartext_traffic": False,
            "exported_activities": [],
            "exported_services": [],
            "exported_receivers": [],
            "exported_providers": [],
            "total_components": 0,
            "total_exported": 0
        }
        
        # 1. Try aapt xmltree if standard APK
        if not self.is_aab:
            try:
                cmd = ["aapt", "dump", "xmltree", self.apk_path, "AndroidManifest.xml"]
                lines = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=15).decode("utf-8", errors="replace").splitlines()
                
                current_tag = None
                current_name = None
                current_exported = False
                current_permission = None

                for line in lines:
                    stripped = line.strip()
                    if "E: application" in stripped:
                        current_tag = "application"
                    elif "E: activity" in stripped:
                        current_tag = "activity"
                        current_name = None
                        current_exported = False
                        current_permission = None
                        info["total_components"] += 1
                    elif "E: service" in stripped:
                        current_tag = "service"
                        current_name = None
                        current_exported = False
                        current_permission = None
                        info["total_components"] += 1
                    elif "E: receiver" in stripped:
                        current_tag = "receiver"
                        current_name = None
                        current_exported = False
                        current_permission = None
                        info["total_components"] += 1
                    elif "E: provider" in stripped:
                        current_tag = "provider"
                        current_name = None
                        current_exported = False
                        current_permission = None
                        info["total_components"] += 1

                    # Application flags
                    if "A: android:debuggable" in stripped:
                        if "0xffffffff" in stripped or "true" in stripped:
                            info["debuggable"] = True
                    if "A: android:allowBackup" in stripped:
                        if "0x0" in stripped or "false" in stripped:
                            info["allow_backup"] = False
                        elif "0xffffffff" in stripped or "true" in stripped:
                            info["allow_backup"] = True
                    if "A: android:usesCleartextTraffic" in stripped:
                        if "0xffffffff" in stripped or "true" in stripped:
                            info["uses_cleartext_traffic"] = True

                    # Component details
                    if "A: android:name" in stripped:
                        match = re.search(r'="([^"]+)"', stripped) or re.search(r'\(Raw:\s*"([^"]+)"\)', stripped)
                        if match:
                            current_name = match.group(1)
                    if "A: android:exported" in stripped:
                        if "0xffffffff" in stripped or "true" in stripped:
                            current_exported = True
                    if "A: android:permission" in stripped:
                        match = re.search(r'="([^"]+)"', stripped)
                        if match:
                            current_permission = match.group(1)

                    # Save exported components
                    if current_tag in ("activity", "service", "receiver", "provider") and current_exported and current_name:
                        item = {"name": current_name, "permission_protected": bool(current_permission), "permission": current_permission}
                        if current_tag == "activity" and item not in info["exported_activities"]:
                            info["exported_activities"].append(item)
                        elif current_tag == "service" and item not in info["exported_services"]:
                            info["exported_services"].append(item)
                        elif current_tag == "receiver" and item not in info["exported_receivers"]:
                            info["exported_receivers"].append(item)
                        elif current_tag == "provider" and item not in info["exported_providers"]:
                            info["exported_providers"].append(item)

                info["total_exported"] = (
                    len(info["exported_activities"]) +
                    len(info["exported_services"]) +
                    len(info["exported_receivers"]) +
                    len(info["exported_providers"])
                )
                if info["total_components"] > 0:
                    return info
            except Exception:
                pass

        # 2. Fallback / AAB parser: Inspect manifest bytes directly
        try:
            with zipfile.ZipFile(self.apk_path, "r") as z:
                manifest_path = "base/manifest/AndroidManifest.xml" if self.is_aab else "AndroidManifest.xml"
                if manifest_path in z.namelist():
                    raw = z.read(manifest_path)
                    
                    if b"debuggable" in raw and (b"true" in raw or b"\xff\xff\xff\xff" in raw):
                        info["debuggable"] = True
                    if b"allowBackup" in raw and b"false" in raw:
                        info["allow_backup"] = False
                    if b"usesCleartextTraffic" in raw and (b"true" in raw or b"\xff\xff\xff\xff" in raw):
                        info["uses_cleartext_traffic"] = True

                    # Extract activities
                    act_matches = re.findall(rb"([a-zA-Z0-9_\.]*(?:Activity|Service|Receiver|Provider))", raw)
                    seen_acts = set()
                    for act_b in act_matches:
                        raw_str = act_b.decode("utf-8", errors="ignore")
                        act_name = re.sub(r"^[^a-zA-Z]+", "", raw_str)
                        act_name = re.sub(r"^[a-zA-Z](?=(?:com|id|io|org|net)\.)", "", act_name)
                        if len(act_name) > 6 and act_name not in seen_acts:
                            seen_acts.add(act_name)
                            info["total_components"] += 1
                            # Check if activity is exported or sensitive
                            is_exported = False
                            if b"exported" in raw:
                                is_exported = True
                            
                            item = {"name": act_name, "permission_protected": False, "permission": None}
                            if "Activity" in act_name:
                                info["exported_activities"].append(item)
                            elif "Service" in act_name:
                                info["exported_services"].append(item)
                            elif "Receiver" in act_name:
                                info["exported_receivers"].append(item)

                    info["total_exported"] = len(info["exported_activities"]) + len(info["exported_services"])
        except Exception as e:
            info["error"] = str(e)

        return info

    def _audit_crypto(self) -> Dict[str, Any]:
        """
        Cryptographic Audit:
        Checks for Blowfish, ECB mode, DES, RC4, and static hardcoded SecretKeySpec/IV.
        Relates to findings #5, #14, #22.
        """
        dex_bytes = self._get_dex_bytes()
        results = {
            "has_weak_crypto": False,
            "has_blowfish": False,
            "has_insecure_ecb": False,
            "has_deprecated_ciphers": False,
            "has_static_keys": False,
            "algorithms": [],
            "evidence": []
        }

        all_dex = b"".join(dex_bytes)

        # 1. Blowfish check
        if re.search(rb"Blowfish", all_dex, re.IGNORECASE):
            results["has_weak_crypto"] = True
            results["has_blowfish"] = True
            results["algorithms"].append("Blowfish")
            results["evidence"].append("Cipher.getInstance('Blowfish') or Blowfish SecretKeySpec found in bytecode")

        # 2. ECB Mode check
        if re.search(rb"(?:AES|DES|Blowfish)/ECB", all_dex, re.IGNORECASE):
            results["has_weak_crypto"] = True
            results["has_insecure_ecb"] = True
            results["algorithms"].append("ECB Mode")
            results["evidence"].append("Insecure Electronic Codebook (ECB) cipher mode detected")

        # 3. Deprecated ciphers (DES, 3DES, RC4)
        if re.search(rb"Cipher\.getInstance\s*\(\s*[\"'](?:DES|DESede|RC4|ARCFOUR)[\"'/]", all_dex, re.IGNORECASE) or \
           re.search(rb"(?:DES|DESede|RC4)/", all_dex):
            results["has_weak_crypto"] = True
            results["has_deprecated_ciphers"] = True
            results["algorithms"].append("DES/RC4")
            results["evidence"].append("Deprecated legacy cipher (DES/3DES/RC4) found")

        # 4. Static Keys & IVs
        if re.search(rb"SecretKeySpec\s*\([^,]+,\s*[\"'](?:Blowfish|DES|AES)[\"']\)", all_dex, re.IGNORECASE) or \
           re.search(rb"IvParameterSpec\s*\(\s*(?:new\s+byte\[\]|new\s+byte\[\d+\])", all_dex):
            results["has_static_keys"] = True
            results["evidence"].append("Static SecretKeySpec or hardcoded IvParameterSpec construction detected")

        return results

    def _audit_network_security_config(self) -> Dict[str, Any]:
        """
        Network Security Config Audit:
        Checks for cleartextTrafficPermitted on staging/internal domains and user cert trust.
        Relates to finding #27.
        """
        audit = {
            "has_config": False,
            "cleartext_domains": [],
            "trusts_user_certs": False,
            "has_pin_set": False,
            "config_file": None
        }

        try:
            with zipfile.ZipFile(self.apk_path, "r") as z:
                # Find network security config file
                target_names = [n for n in z.namelist() if "network_security_config.xml" in n or "network_security" in n]
                if not target_names:
                    target_names = [n for n in z.namelist() if n.startswith("res/xml/") or n.startswith("base/res/xml/")]

                for name in target_names:
                    raw = z.read(name)
                    if b"network-security-config" in raw or b"domain-config" in raw:
                        audit["has_config"] = True
                        audit["config_file"] = name

                        # Check cleartext traffic permitted
                        if b"cleartextTrafficPermitted" in raw and (b"true" in raw or b"\xff\xff\xff\xff" in raw):
                            # Extract domains
                            domain_matches = re.findall(rb"(?:[a-zA-Z0-9_\-]+\.)+[a-zA-Z]{2,}", raw)
                            for dm in domain_matches:
                                d_str = dm.decode("utf-8", errors="ignore").lower()
                                if not d_str.endswith(".xml") and not d_str.endswith(".com/apk") and \
                                   "schema" not in d_str and "android" not in d_str and "w3.org" not in d_str:
                                    if d_str not in audit["cleartext_domains"]:
                                        audit["cleartext_domains"].append(d_str)

                        # Check user certificate trust
                        if b'src="user"' in raw or b"src\x00user" in raw or (b"certificates" in raw and b"user" in raw):
                            audit["trusts_user_certs"] = True

                        # Check pin set
                        if b"pin-set" in raw:
                            audit["has_pin_set"] = True

                        break
        except Exception:
            pass

        return audit

    def _audit_sensitive_exported_components(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sensitive & Third-Party Debug Component Audit:
        Detects exported activities matching debug tools (MoEDebuggerActivity)
        or sensitive business flows (PaymentActivity, OvoBindingActivity).
        Relates to findings #16, #31.
        """
        sensitive = {
            "debug_activities": [],
            "sensitive_activities": [],
            "all_unprotected": []
        }

        exported_acts = manifest.get("exported_activities", [])
        
        debug_pattern = re.compile(r"(MoEDebuggerActivity|Flipper|Chucker|LeakCanary|DebugActivity|TestActivity|DevActivity)", re.IGNORECASE)
        business_pattern = re.compile(r".*(?:Payment|Checkout|Ovo|Dana|Gopay|Shopee|Binding|Wallet|Pin|Otp|Auth|Transaction|Transfer).*Activity", re.IGNORECASE)

        for act in exported_acts:
            name = act.get("name", "")
            if not act.get("permission_protected", False):
                sensitive["all_unprotected"].append(name)
                if debug_pattern.search(name):
                    sensitive["debug_activities"].append(name)
                elif business_pattern.search(name):
                    sensitive["sensitive_activities"].append(name)

        return sensitive

    def _audit_biometric_auth(self) -> Dict[str, Any]:
        """
        Biometric Security Audit:
        Checks if BiometricPrompt is called without CryptoObject (client-side boolean bypass).
        Relates to finding #15.
        """
        dex_bytes = self._get_dex_bytes()
        all_dex = b"".join(dex_bytes)

        has_biometric = bool(re.search(rb"BiometricPrompt", all_dex))
        has_crypto_obj = bool(re.search(rb"BiometricPrompt\$CryptoObject|CryptoObject", all_dex))
        prompt_only_call = bool(re.search(rb"authenticate\([^)]*PromptInfo[^)]*\)(?!.*CryptoObject)", all_dex))

        is_weak = has_biometric and (not has_crypto_obj or prompt_only_call)

        return {
            "biometric_implemented": has_biometric,
            "crypto_object_used": has_crypto_obj,
            "is_weak": is_weak,
            "description": "BiometricPrompt used without CryptoObject wrapper" if is_weak else "Secure or not implemented"
        }

    def _audit_anti_tamper(self) -> Dict[str, Any]:
        """
        Anti-Tampering, Root, & Frida Detection Audit:
        Checks for RootBeer, su binary check, Frida ports, and emulator checks.
        Relates to finding #24.
        """
        dex_bytes = self._get_dex_bytes()
        all_dex = b"".join(dex_bytes)

        root_sigs = [b"RootBeer", b"com/scottyab/rootbeer", b"/system/bin/su", b"/system/xbin/su", b"/sbin/su", b"which su", b"test-keys"]
        frida_sigs = [b"27042", b"frida-server", b"frida-agent", b"gumjs", b"libfrida", b"/proc/net/tcp"]
        emu_sigs = [b"goldfish", b"qemu", b"sdk_gphone", b"vbox86p"]

        has_root = any(sig in all_dex for sig in root_sigs)
        has_frida = any(sig in all_dex for sig in frida_sigs)
        has_emu = any(sig in all_dex for sig in emu_sigs)

        overall = has_root or has_frida or has_emu

        return {
            "root_detection": has_root,
            "frida_detection": has_frida,
            "emulator_detection": has_emu,
            "overall_protected": overall
        }

    def _audit_endpoints(self) -> Dict[str, Any]:
        """
        Endpoint Hunter:
        Detects Spring Boot Actuator paths, staging/dev domains, and IDOR patterns.
        Relates to findings #20, #32.
        """
        dex_bytes = self._get_dex_bytes()
        all_dex = b"".join(dex_bytes)

        actuator_matches = re.findall(rb"https?://[a-zA-Z0-9_\-\.]+(?::[0-9]+)?/actuator(?:/[a-zA-Z0-9_\-]+)?", all_dex, re.IGNORECASE)
        staging_matches = re.findall(rb"https?://(?:[a-zA-Z0-9_\-]+\.)*(?:staging|stg|uat|dev|sandbox|internal)\.[a-zA-Z0-9_\-\.]+", all_dex, re.IGNORECASE)
        idor_matches = re.findall(rb"https?://[^\s\"\'<>]+(?:/api/v[0-9]+/(?:user|member|account|cart|wallet)/[0-9]+|\?(?:user_?id|member_?id|account_?id)=[0-9]+)", all_dex, re.IGNORECASE)

        return {
            "actuator_endpoints": list(set([m.decode("utf-8", errors="ignore") for m in actuator_matches])),
            "staging_hosts": list(set([m.decode("utf-8", errors="ignore") for m in staging_matches])),
            "idor_patterns": list(set([m.decode("utf-8", errors="ignore") for m in idor_matches]))
        }

    def _categorize_permissions(self, perms: List[str]) -> Dict[str, Any]:
        """Categorize permissions into Dangerous, Normal, and System/Signature."""
        dangerous = []
        normal = []

        for p in perms:
            if p in DANGEROUS_PERMISSIONS:
                dangerous.append({
                    "name": p,
                    "description": DANGEROUS_PERMISSIONS[p],
                    "risk": "HIGH"
                })
            else:
                normal.append({
                    "name": p,
                    "risk": "LOW"
                })

        return {
            "total_count": len(perms),
            "dangerous_count": len(dangerous),
            "normal_count": len(normal),
            "dangerous_list": dangerous,
            "normal_list": normal
        }

    def _analyze_zip_contents(self) -> Dict[str, Any]:
        """Calculate breakdown of binary size by file categories."""
        breakdown = {
            "dex_size": 0,
            "dex_files_count": 0,
            "native_libs_size": 0,
            "native_libs_by_arch": {},
            "resources_size": 0,
            "assets_size": 0,
            "other_size": 0,
            "total_uncompressed": 0
        }

        try:
            with zipfile.ZipFile(self.apk_path, "r") as z:
                for member in z.infolist():
                    name = member.filename
                    size = member.file_size
                    breakdown["total_uncompressed"] += size

                    if name.endswith(".dex"):
                        breakdown["dex_size"] += size
                        breakdown["dex_files_count"] += 1
                    elif "lib/" in name:
                        breakdown["native_libs_size"] += size
                        parts = name.split("lib/")
                        if len(parts) >= 2:
                            arch_part = parts[1].split("/")[0]
                            breakdown["native_libs_by_arch"][arch_part] = breakdown["native_libs_by_arch"].get(arch_part, 0) + size
                    elif name.startswith("res/") or name.startswith("base/res/") or name.endswith("resources.arsc"):
                        breakdown["resources_size"] += size
                    elif "assets/" in name:
                        breakdown["assets_size"] += size
                    else:
                        breakdown["other_size"] += size

            # Formatted readable sizes
            breakdown["dex_size_fmt"] = self._format_size(breakdown["dex_size"])
            breakdown["native_libs_size_fmt"] = self._format_size(breakdown["native_libs_size"])
            breakdown["resources_size_fmt"] = self._format_size(breakdown["resources_size"])
            breakdown["assets_size_fmt"] = self._format_size(breakdown["assets_size"])
            breakdown["other_size_fmt"] = self._format_size(breakdown["other_size"])
            breakdown["total_uncompressed_fmt"] = self._format_size(breakdown["total_uncompressed"])

        except Exception as e:
            breakdown["error"] = str(e)

        return breakdown

    def _scan_secrets(self) -> List[Dict[str, str]]:
        """Scan bytecode, resources, and JS bundles for hardcoded secrets, keys, and tokens."""
        detected = []
        seen = set()

        try:
            with zipfile.ZipFile(self.apk_path, "r") as z:
                scan_targets = [
                    n for n in z.namelist()
                    if n.endswith(".dex") or n.endswith("resources.arsc") or
                       "assets/" in n or n.endswith(".json") or n.endswith(".bundle") or n.endswith(".js")
                ]
                for target in scan_targets[:25]:
                    content = z.read(target)
                    for label, pattern in SECRET_PATTERNS:
                        matches = pattern.findall(content)
                        for m in matches:
                            val_str = m.decode("utf-8", errors="ignore").strip()
                            masked = val_str[:4] + "*" * (len(val_str) - 8) + val_str[-4:] if len(val_str) > 10 else "****"
                            key_id = f"{label}:{masked}"
                            if key_id not in seen:
                                seen.add(key_id)
                                detected.append({
                                    "type": label,
                                    "masked_value": masked,
                                    "file_source": target,
                                    "severity": "CRITICAL"
                                })
                    
                    # Residual Debug Package in JSON files check
                    if target.endswith(".json"):
                        if b"\"package_name\":" in content and b".debug\"" in content:
                            key_id = f"DebugPackage:{target}"
                            if key_id not in seen:
                                seen.add(key_id)
                                detected.append({
                                    "type": "Registered Debug Package in JSON",
                                    "masked_value": "com.*.debug in config",
                                    "file_source": target,
                                    "severity": "HIGH"
                                })
        except Exception:
            pass

        return detected

    def _audit_signature(self) -> Dict[str, Any]:
        """Check APK signature scheme and whether signed with debug certificate."""
        sig = {
            "is_signed": True,
            "is_debug_signed": False,
            "issuer": "Unknown",
            "subject": "Unknown",
            "fingerprint_sha256": "N/A"
        }
        try:
            cmd = ["keytool", "-printcert", "-jarfile", self.apk_path]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=10).decode("utf-8", errors="replace")
            
            if "CN=Android Debug" in output or "OU=Android" in output:
                sig["is_debug_signed"] = True

            issuer_m = re.search(r"Issuer:\s*(.+)", output)
            if issuer_m:
                sig["issuer"] = issuer_m.group(1).strip()

            subject_m = re.search(r"Owner:\s*(.+)", output)
            if subject_m:
                sig["subject"] = subject_m.group(1).strip()

            sha256_m = re.search(r"SHA256:\s*([0-9A-Fa-f:]+)", output)
            if sha256_m:
                sig["fingerprint_sha256"] = sha256_m.group(1).strip()

        except Exception:
            sig["is_signed"] = not self.is_aab

        return sig

    def _compute_security_score(
        self, badging: Dict, manifest: Dict, secrets: List, cert: Dict,
        crypto_audit: Dict = None, net_sec_audit: Dict = None,
        sensitive_comps: Dict = None, biometric_audit: Dict = None,
        anti_tamper_audit: Dict = None, endpoint_audit: Dict = None
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Calculate score from 0 to 100 based on weighted vulnerability severity across all audit modules."""
        score = 100
        findings = []

        # 1. Debuggable check (Critical)
        if manifest.get("debuggable", False):
            deduct = 30
            score -= deduct
            findings.append({
                "severity": "CRITICAL",
                "title": "Application is Marked as Debuggable",
                "deduction": deduct,
                "description": "android:debuggable is true. Attackers can attach a debugger, dump memory, or inject code via ADB without root."
            })

        # 2. Debug Signature (Critical)
        if cert.get("is_debug_signed", False):
            deduct = 20
            score -= deduct
            findings.append({
                "severity": "CRITICAL",
                "title": "Signed with Android Debug Certificate",
                "deduction": deduct,
                "description": "The APK is signed with the well-known insecure Android debug keystore. It should never be released to production."
            })

        # 3. Cleartext Traffic Allowed in Manifest (High)
        if manifest.get("uses_cleartext_traffic", False):
            deduct = 15
            score -= deduct
            findings.append({
                "severity": "HIGH",
                "title": "Cleartext HTTP Traffic Allowed Globally",
                "deduction": deduct,
                "description": "android:usesCleartextTraffic is true. Network traffic can be intercepted via Man-In-The-Middle (MITM) attacks."
            })

        # 4. Cleartext Traffic Allowed for Specific/Staging Domains (#27)
        if net_sec_audit and net_sec_audit.get("cleartext_domains"):
            domains = net_sec_audit["cleartext_domains"]
            deduct = 15
            score -= deduct
            findings.append({
                "severity": "HIGH",
                "title": f"Cleartext Traffic Allowed for {len(domains)} Staging/Target Domains",
                "deduction": deduct,
                "description": f"Network Security Config permits insecure HTTP traffic to: {', '.join(domains[:5])}. MITM attackers on the same network can intercept sensitive credentials and tokens."
            })

        # 5. User Certificates Trusted in Network Config
        if net_sec_audit and net_sec_audit.get("trusts_user_certs"):
            deduct = 15
            score -= deduct
            findings.append({
                "severity": "HIGH",
                "title": "Network Security Config Trusts User-Installed CA Certificates",
                "deduction": deduct,
                "description": "Application configures <certificates src=\"user\"/> in trust-anchors. Attackers or testers can install a custom root certificate on Android 7+ to inspect TLS traffic without root."
            })

        # 6. Exported Third-Party Debug Activity (#31)
        if sensitive_comps and sensitive_comps.get("debug_activities"):
            acts = sensitive_comps["debug_activities"]
            deduct = 20
            score -= deduct
            findings.append({
                "severity": "CRITICAL",
                "title": f"Exported Third-Party Debug Activity ({', '.join(acts[:2])})",
                "deduction": deduct,
                "description": f"Found exported debug activities left in production binary: {', '.join(acts)}. Activities like MoEngage MoEDebuggerActivity or Flipper/Chucker leak internal diagnostic logs and allow unauthorized intent dispatching."
            })

        # 7. Unauthenticated Access to Sensitive Activities (#16)
        if sensitive_comps and sensitive_comps.get("sensitive_activities"):
            acts = sensitive_comps["sensitive_activities"]
            deduct = 20
            score -= deduct
            findings.append({
                "severity": "CRITICAL",
                "title": f"Unauthenticated Access to Sensitive Activities ({', '.join(acts[:2])})",
                "deduction": deduct,
                "description": f"Sensitive payment/wallet/auth activities are exported without permission protection: {', '.join(acts[:4])}. Malicious third-party apps can trigger these screens directly to bypass login or KYC verification."
            })

        # 8. Weak Cryptography: Blowfish / Insecure ECB Mode (#5, #14, #22)
        if crypto_audit and crypto_audit.get("has_weak_crypto"):
            algos = ", ".join(crypto_audit.get("algorithms", ["Blowfish/ECB"]))
            deduct = 20
            score -= deduct
            findings.append({
                "severity": "CRITICAL",
                "title": f"Weak Cryptography: Insecure Cipher ({algos})",
                "deduction": deduct,
                "description": f"Detected legacy or insecure cryptographic implementations: {algos}. Electronic Codebook (ECB) mode preserves plaintext patterns, and Blowfish/DES are considered broken for modern high-assurance mobile applications."
            })

        # 9. Static Hardcoded Cryptographic Key / IV (#14)
        if crypto_audit and crypto_audit.get("has_static_keys"):
            deduct = 15
            score -= deduct
            findings.append({
                "severity": "HIGH",
                "title": "Static Hardcoded Encryption Key / IV Detected",
                "deduction": deduct,
                "description": "Bytecode contains static SecretKeySpec or hardcoded IvParameterSpec definitions. Static keys can be easily extracted using Frida or decompiler tools to forge certificates and decrypt encrypted API payloads."
            })

        # 10. Weak Biometric Authentication Without CryptoObject (#15)
        if biometric_audit and biometric_audit.get("is_weak"):
            deduct = 15
            score -= deduct
            findings.append({
                "severity": "HIGH",
                "title": "Weak Biometric Auth Without CryptoObject",
                "deduction": deduct,
                "description": "BiometricPrompt is invoked without wrapping cryptographic operations inside a CryptoObject. Authentication validity relies exclusively on a client-side boolean callback (onAuthenticationSucceeded), which can be bypassed via a 1-line Frida hook."
            })

        # 11. Missing Anti-Tamper, Root & Frida Detection (#24)
        if anti_tamper_audit and not anti_tamper_audit.get("overall_protected"):
            deduct = 10
            score -= deduct
            findings.append({
                "severity": "MEDIUM",
                "title": "Missing Root, Frida, & Anti-Tamper Protections",
                "deduction": deduct,
                "description": "The application lacks basic client-side defense mechanisms: no RootBeer/su detection, Frida dynamic hooking detection (port 27042), or emulator detection was detected in bytecode."
            })

        # 12. Exposed Spring Boot Actuator / Staging Endpoints (#20, #32)
        if endpoint_audit and (endpoint_audit.get("actuator_endpoints") or endpoint_audit.get("staging_hosts")):
            endpoints = (endpoint_audit.get("actuator_endpoints", []) + endpoint_audit.get("staging_hosts", []))[:3]
            deduct = 15
            score -= deduct
            findings.append({
                "severity": "HIGH",
                "title": "Hardcoded Spring Boot Actuator / Staging Endpoints",
                "deduction": deduct,
                "description": f"Detected hardcoded staging hosts or actuator paths in binary: {', '.join(endpoints)}. Actuator endpoints may leak sensitive server configuration, environment secrets, and heap dumps."
            })

        # 13. Hardcoded Secrets (Critical) (#3, #18, #19, #30)
        if secrets:
            deduct = min(25, len(secrets) * 15)
            score -= deduct
            findings.append({
                "severity": "CRITICAL",
                "title": f"{len(secrets)} Hardcoded Secrets / Tokens Detected",
                "deduction": deduct,
                "description": f"Detected potential Google/Firebase API keys, AWS credentials, or authentication tokens hardcoded in application binary or asset bundles."
            })

        # 14. Allow Backup (Medium)
        if manifest.get("allow_backup", True):
            deduct = 10
            score -= deduct
            findings.append({
                "severity": "MEDIUM",
                "title": "Application Backup Enabled",
                "deduction": deduct,
                "description": "android:allowBackup is enabled. App data (including databases and shared preferences) can be extracted via ADB backup."
            })

        # 15. General Exported Components (High/Medium)
        unprotected_exported = [
            comp for comp in (manifest.get("exported_activities", []) +
                              manifest.get("exported_services", []) +
                              manifest.get("exported_receivers", []) +
                              manifest.get("exported_providers", []))
            if not comp.get("permission_protected", False)
        ]
        # Only deduct if sensitive comps haven't already heavily penalized
        if len(unprotected_exported) > 3 and not (sensitive_comps and sensitive_comps.get("debug_activities")):
            deduct = min(15, len(unprotected_exported) * 2)
            score -= deduct
            findings.append({
                "severity": "HIGH",
                "title": f"{len(unprotected_exported)} Exported Components Without Permissions",
                "deduction": deduct,
                "description": f"Found {len(unprotected_exported)} activities, services, or receivers exported to all other apps on device without custom permission protection."
            })

        # 16. Dangerous Permissions
        dangerous_perms = [p for p in badging.get("permissions", []) if p in DANGEROUS_PERMISSIONS]
        if len(dangerous_perms) > 5:
            deduct = min(15, (len(dangerous_perms) - 5) * 2)
            score -= deduct
            findings.append({
                "severity": "LOW",
                "title": f"High Number of Dangerous Permissions ({len(dangerous_perms)})",
                "deduction": deduct,
                "description": "Requesting numerous high-privilege Android runtime permissions increases attack surface and may trigger Google Play reviews."
            })

        # Clamp between 0 and 100
        final_score = max(0, min(100, score))
        return findings, final_score

    def _evaluate_qa_metrics(self, badging: Dict, zip_info: Dict) -> Dict[str, Any]:
        """Generate QA health & compliance report."""
        target_sdk = badging.get("target_sdk", "0")
        try:
            target_sdk_int = int(target_sdk)
        except ValueError:
            target_sdk_int = 0

        play_store_compliant = target_sdk_int >= 34

        return {
            "google_play_target_sdk_compliant": play_store_compliant,
            "target_sdk_evaluation": "Modern / Compliant" if play_store_compliant else f"Outdated (API {target_sdk} < 34)",
            "dex_multi_dex_active": zip_info.get("dex_files_count", 1) > 1,
            "has_native_binaries": zip_info.get("native_libs_size", 0) > 0,
            "architecture_support": list(zip_info.get("native_libs_by_arch", {}).keys()) or ["Architecture Independent (Java/Kotlin DEX only)"]
        }

    @staticmethod
    def _format_size(bytes_num: int) -> str:
        """Format bytes to human readable string (KB, MB)."""
        if bytes_num < 1024:
            return f"{bytes_num} B"
        elif bytes_num < 1024 * 1024:
            return f"{bytes_num / 1024:.2f} KB"
        else:
            return f"{bytes_num / (1024 * 1024):.2f} MB"


if __name__ == "__main__":
    import sys
    test_path = sys.argv[1] if len(sys.argv) > 1 else "samples/sample-debug.apk"
    if os.path.exists(test_path):
        analyzer = ApkAnalyzer(test_path)
        result = analyzer.analyze()
        print(f"App Label: {result['metadata']['app_label']}")
        print(f"Package: {result['metadata']['package_name']}")
        print(f"Security Score: {result['security_score']}/100")
        print(f"Findings: {len(result['findings'])}")
        for f in result['findings']:
            print(f"  [{f['severity']}] - {f['title']} (-{f['deduction']} pts)")
    else:
        print("Please provide a valid APK path")
