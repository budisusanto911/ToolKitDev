#!/usr/bin/env python3
"""
ToolKitDev - Third-Party SDK & Dependency CVE Scanner (Software Composition Analysis - SCA)
Scans Android APK/AAB DEX bytecode, assets, and metadata for 3rd-party library footprints,
identifies SDK versions, and checks against CVE vulnerability advisories.
"""

import os
import json
import re
import zipfile
from typing import Dict, Any, List, Optional


class ScaScanner:
    def __init__(self, apk_path: str, signatures_file: Optional[str] = None):
        self.apk_path = apk_path
        if not signatures_file:
            signatures_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sdk_signatures.json")
        self.signatures_file = signatures_file
        self.sdk_db = self._load_signatures()
        self._cached_dex_bytes: List[bytes] = []

    def _load_signatures(self) -> List[Dict[str, Any]]:
        try:
            with open(self.signatures_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("sdks", [])
        except Exception:
            return []

    def _get_dex_and_string_blobs(self) -> List[bytes]:
        if self._cached_dex_bytes:
            return self._cached_dex_bytes

        blobs = []
        try:
            with zipfile.ZipFile(self.apk_path, "r") as z:
                for name in z.namelist():
                    # Check DEX files and metadata files
                    if name.endswith(".dex") or name.startswith("META-INF/") or name.endswith(".pom") or name.endswith(".version"):
                        try:
                            blobs.append(z.read(name))
                        except Exception:
                            pass
        except Exception:
            pass

        self._cached_dex_bytes = blobs
        return blobs

    def scan(self) -> Dict[str, Any]:
        """Perform full SCA scan against the APK/AAB binary."""
        blobs = self._get_dex_and_string_blobs()
        if not blobs:
            return {
                "total_detected": 0,
                "vulnerable_count": 0,
                "outdated_count": 0,
                "categories": {},
                "sdks": []
            }

        detected_sdks = []
        vulnerable_count = 0
        outdated_count = 0
        categories_map = {}

        for sdk in self.sdk_db:
            matched = False
            matched_signature = ""

            # 1. Match signatures across blobs
            for sig in sdk.get("signatures", []):
                sig_bytes = sig.encode("utf-8")
                sig_slash = sig.replace(".", "/").encode("utf-8")
                for blob in blobs:
                    if sig_bytes in blob or sig_slash in blob:
                        matched = True
                        matched_signature = sig
                        break
                if matched:
                    break

            if not matched:
                continue

            # 2. Extract version
            detected_version = sdk.get("default_detected_version", "1.0.0")
            for pattern in sdk.get("version_patterns", []):
                try:
                    pat_compiled = re.compile(pattern.encode("utf-8"), re.IGNORECASE)
                    for blob in blobs:
                        m = pat_compiled.search(blob)
                        if m:
                            detected_version = m.group(1).decode("utf-8", errors="ignore")
                            break
                except Exception:
                    pass

            # 3. Check for CVE matches
            matched_cves = []
            for cve in sdk.get("cves", []):
                aff = cve.get("affected_versions", "")
                is_affected = False
                if aff.startswith("<"):
                    target_ver = aff.replace("<", "").strip()
                    if self._version_less_than(detected_version, target_ver):
                        is_affected = True
                elif aff.startswith("<="):
                    target_ver = aff.replace("<=", "").strip()
                    if self._version_less_or_equal(detected_version, target_ver):
                        is_affected = True
                else:
                    is_affected = True

                if is_affected:
                    matched_cves.append(cve)

            is_vulnerable = len(matched_cves) > 0
            if is_vulnerable:
                vulnerable_count += 1

            # Check if outdated compared to latest_safe_version
            latest_safe = sdk.get("latest_safe_version", "")
            is_outdated = False
            if latest_safe and self._version_less_than(detected_version, latest_safe):
                is_outdated = True
                outdated_count += 1

            cat = sdk.get("category", "General Library")
            categories_map[cat] = categories_map.get(cat, 0) + 1

            detected_sdks.append({
                "id": sdk.get("id"),
                "name": sdk.get("name"),
                "category": cat,
                "matched_signature": matched_signature,
                "detected_version": detected_version,
                "latest_safe_version": latest_safe,
                "is_vulnerable": is_vulnerable,
                "is_outdated": is_outdated,
                "license": sdk.get("license", "Unknown"),
                "website": sdk.get("website", ""),
                "cves": matched_cves,
                "remediation": matched_cves[0].get("remediation") if matched_cves else f"Perbarui dependensi {sdk.get('name')} ke versi terbaru {latest_safe}."
            })

        # Sort: vulnerable first, then outdated, then name
        detected_sdks.sort(key=lambda s: (not s["is_vulnerable"], not s["is_outdated"], s["name"]))

        return {
            "total_detected": len(detected_sdks),
            "vulnerable_count": vulnerable_count,
            "outdated_count": outdated_count,
            "clean_count": len(detected_sdks) - vulnerable_count,
            "categories": categories_map,
            "sdks": detected_sdks
        }

    def _parse_version_tuple(self, v_str: str) -> List[int]:
        # Extract digits: '4.9.0' -> [4, 9, 0]
        parts = re.findall(r"\d+", str(v_str))
        return [int(p) for p in parts] if parts else [0]

    def _version_less_than(self, v1: str, v2: str) -> bool:
        t1 = self._parse_version_tuple(v1)
        t2 = self._parse_version_tuple(v2)
        # Pad to equal length
        max_len = max(len(t1), len(t2))
        t1 += [0] * (max_len - len(t1))
        t2 += [0] * (max_len - len(t2))
        return t1 < t2

    def _version_less_or_equal(self, v1: str, v2: str) -> bool:
        t1 = self._parse_version_tuple(v1)
        t2 = self._parse_version_tuple(v2)
        max_len = max(len(t1), len(t2))
        t1 += [0] * (max_len - len(t1))
        t2 += [0] * (max_len - len(t2))
        return t1 <= t2


if __name__ == "__main__":
    import sys
    test_file = sys.argv[1] if len(sys.argv) > 1 else "uploads/base.apk"
    scanner = ScaScanner(test_file)
    res = scanner.scan()
    print(f"SCA Scan Result for {test_file}:")
    print(f"Total Detected: {res['total_detected']} SDKs | Vulnerable: {res['vulnerable_count']} | Outdated: {res['outdated_count']}")
    for s in res['sdks']:
        cve_str = f" [CVE: {', '.join([c['cve_id'] for c in s['cves']])}]" if s['is_vulnerable'] else " [CLEAN]"
        print(f"- {s['name']} v{s['detected_version']} ({s['category']}){cve_str}")

