#!/usr/bin/env python3
"""
ToolKitDev - APK Diff & Version Comparator Engine (Delta Security Audit)
Compares two APK/AAB versions (e.g. Old Release v1.0 vs New Release v1.1)
to detect security regressions, newly introduced attack surfaces, resolved vulnerabilities,
and permission changes.
"""

import os
import json
from typing import Dict, Any, List, Optional

from engine.apk_analyzer import ApkAnalyzer
from engine.sca_scanner import ScaScanner


class ApkComparator:
    def __init__(self, base_target: Any, target_target: Any):
        """
        base_target & target_target can be either:
        - string file path (e.g. 'uploads/sample-debug.apk')
        - dictionary containing existing analysis result
        """
        self.base_data = self._resolve_data(base_target)
        self.target_data = self._resolve_data(target_target)

    def _resolve_data(self, target: Any) -> Dict[str, Any]:
        if isinstance(target, dict):
            return target
        if isinstance(target, str):
            # Check if JSON file
            if target.endswith(".json") and os.path.isfile(target):
                try:
                    with open(target, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    pass
            # Or APK/AAB binary
            if os.path.isfile(target):
                analyzer = ApkAnalyzer(target)
                data = analyzer.analyze()
                # Run SCA if not present
                if "sca_analysis" not in data:
                    try:
                        sca = ScaScanner(target)
                        data["sca_analysis"] = sca.scan()
                    except Exception:
                        pass
                return data
        return {}

    def compare(self) -> Dict[str, Any]:
        """Perform comprehensive delta security comparison."""
        base_meta = self.base_data.get("metadata", {})
        target_meta = self.target_data.get("metadata", {})
        base_file = self.base_data.get("file_info", {})
        target_file = self.target_data.get("file_info", {})

        # 1. Scores & Risk Delta
        base_score = self.base_data.get("security_score", 0)
        target_score = self.target_data.get("security_score", 0)
        delta_score = target_score - base_score

        if delta_score > 0:
            verdict_status = "IMPROVED"
            verdict_badge = f"+{delta_score} PTS (MENINGKAT)"
            verdict_color = "#16a34a"
        elif delta_score < 0:
            verdict_status = "DEGRADED"
            verdict_badge = f"{delta_score} PTS (REGRESI KEAMANAN)"
            verdict_color = "#dc2626"
        else:
            verdict_status = "STABLE"
            verdict_badge = "±0 PTS (STABIL)"
            verdict_color = "#64748b"

        # 2. Permissions Delta
        base_perms = set(base_meta.get("permissions", []))
        target_perms = set(target_meta.get("permissions", []))
        
        def extract_perm_names(lst):
            res = set()
            for x in lst or []:
                if isinstance(x, dict):
                    res.add(x.get("name") or x.get("permission", ""))
                elif isinstance(x, str):
                    res.add(x)
            return {p for p in res if p}

        base_dang_list = extract_perm_names(self.base_data.get("permissions", {}).get("dangerous_list", []))
        target_dang_list = extract_perm_names(self.target_data.get("permissions", {}).get("dangerous_list", []))

        added_perms = []
        for p in sorted(target_perms - base_perms):
            is_dang = (p in target_dang_list) or any(d in p for d in ("LOCATION", "CAMERA", "STORAGE", "CONTACTS", "PHONE", "SMS", "AUDIO"))
            added_perms.append({"permission": p, "is_dangerous": is_dang})

        removed_perms = []
        for p in sorted(base_perms - target_perms):
            was_dang = (p in base_dang_list) or any(d in p for d in ("LOCATION", "CAMERA", "STORAGE", "CONTACTS", "PHONE", "SMS", "AUDIO"))
            removed_perms.append({"permission": p, "was_dangerous": was_dang})

        retained_perms = sorted(base_perms.intersection(target_perms))

        # 3. Exported Components Delta
        base_manifest = self.base_data.get("manifest_security", {})
        target_manifest = self.target_data.get("manifest_security", {})

        def extract_comp_names(comp_list):
            res = set()
            for c in comp_list or []:
                if isinstance(c, dict):
                    res.add(c.get("name", ""))
                elif isinstance(c, str):
                    res.add(c)
            return {x for x in res if x}

        base_exp_acts = extract_comp_names(base_manifest.get("exported_activities", []))
        target_exp_acts = extract_comp_names(target_manifest.get("exported_activities", []))
        
        base_exp_srvs = extract_comp_names(base_manifest.get("exported_services", []))
        target_exp_srvs = extract_comp_names(target_manifest.get("exported_services", []))

        base_exp_rcvs = extract_comp_names(base_manifest.get("exported_receivers", []))
        target_exp_rcvs = extract_comp_names(target_manifest.get("exported_receivers", []))

        base_exp_prvs = extract_comp_names(base_manifest.get("exported_providers", []))
        target_exp_prvs = extract_comp_names(target_manifest.get("exported_providers", []))

        newly_exposed_components = []
        for a in (target_exp_acts - base_exp_acts): newly_exposed_components.append({"type": "Activity", "name": a})
        for s in (target_exp_srvs - base_exp_srvs): newly_exposed_components.append({"type": "Service", "name": s})
        for r in (target_exp_rcvs - base_exp_rcvs): newly_exposed_components.append({"type": "Receiver", "name": r})
        for p in (target_exp_prvs - base_exp_prvs): newly_exposed_components.append({"type": "Provider", "name": p})

        secured_components = []
        for a in (base_exp_acts - target_exp_acts): secured_components.append({"type": "Activity", "name": a})
        for s in (base_exp_srvs - target_exp_srvs): secured_components.append({"type": "Service", "name": s})
        for r in (base_exp_rcvs - target_exp_rcvs): secured_components.append({"type": "Receiver", "name": r})
        for p in (base_exp_prvs - target_exp_prvs): secured_components.append({"type": "Provider", "name": p})

        # 4. Findings & Vulnerabilities Delta
        base_findings = self.base_data.get("findings", [])
        target_findings = self.target_data.get("findings", [])

        base_f_map = {f.get("title", ""): f for f in base_findings}
        target_f_map = {f.get("title", ""): f for f in target_findings}

        resolved_findings = [f for t, f in base_f_map.items() if t not in target_f_map]
        new_regressed_findings = [f for t, f in target_f_map.items() if t not in base_f_map]
        persistent_findings = [f for t, f in target_f_map.items() if t in base_f_map]

        # 5. Endpoints & API Routes Delta
        base_telemetry = self.base_data.get("frida_dataflow_telemetry", {})
        target_telemetry = self.target_data.get("frida_dataflow_telemetry", {})

        def get_endpoints_set(telem):
            eps = {}
            for item in telem.get("endpoints_inventory", []):
                ep_url = item.get("endpoint") or item.get("url_route") or ""
                if ep_url:
                    eps[ep_url] = item
            return eps

        base_eps = get_endpoints_set(base_telemetry)
        target_eps = get_endpoints_set(target_telemetry)

        newly_added_endpoints = [target_eps[u] for u in (target_eps.keys() - base_eps.keys())]
        removed_endpoints = [base_eps[u] for u in (base_eps.keys() - target_eps.keys())]

        # 6. Metadata Comparison
        base_size_mb = base_file.get("size_mb") or round(base_file.get("size", 0) / (1024*1024), 2)
        target_size_mb = target_file.get("size_mb") or round(target_file.get("size", 0) / (1024*1024), 2)
        size_delta_mb = round(target_size_mb - base_size_mb, 2)

        base_label = base_meta.get("app_label") or base_file.get("name") or "Base Release"
        target_label = target_meta.get("app_label") or target_file.get("name") or "Target Update"

        # 7. Executive Narrative Assessment
        if verdict_status == "IMPROVED":
            summary_narrative = (
                f"Pembaruan rilis **{target_label}** menunjukkan tren keamanan positif dengan peningkatan skor **+{delta_score} poin**. "
                f"Terdapat {len(resolved_findings)} celah keamanan yang berhasil diselesaikan. "
                f"{f'Sebanyak {len(new_regressed_findings)} temuan baru teridentifikasi dan disarankan untuk dievaluasi.' if new_regressed_findings else 'Tidak ada regresi celah baru yang diperkenalkan.'}"
            )
        elif verdict_status == "DEGRADED":
            summary_narrative = (
                f"⚠️ **PERINGATAN REGRESI KEAMANAN:** Versi **{target_label}** mengalami penurunan skor sebesar **{delta_score} poin** dibandingkan versi sebelumnya. "
                f"Terdeteksi {len(new_regressed_findings)} celah keamanan baru dan {len(newly_exposed_components)} komponen yang baru diekspos ke publik (`exported=true`). "
                f"Disarankan menahan rilis ke production hingga celah baru diperbaiki."
            )
        else:
            summary_narrative = (
                f"Postur keamanan aplikasi pada versi **{target_label}** relatif stabil dibandingkan versi basis. "
                f"Skor keamanan tetap di level {target_score}/100 dengan {len(persistent_findings)} temuan yang masih bertahan."
            )

        return {
            "summary": {
                "base_app_name": base_label,
                "target_app_name": target_label,
                "base_package": base_meta.get("package_name", "unknown"),
                "target_package": target_meta.get("package_name", "unknown"),
                "base_version": f"{base_meta.get('version_name', '1.0')} ({base_meta.get('version_code', '1')})",
                "target_version": f"{target_meta.get('version_name', '1.0')} ({target_meta.get('version_code', '1')})",
                "base_score": base_score,
                "target_score": target_score,
                "delta_score": delta_score,
                "verdict_status": verdict_status,
                "verdict_badge": verdict_badge,
                "verdict_color": verdict_color,
                "summary_narrative": summary_narrative,
                "base_size_mb": base_size_mb,
                "target_size_mb": target_size_mb,
                "size_delta_mb": size_delta_mb,
                "base_target_sdk": base_meta.get("target_sdk", "unknown"),
                "target_target_sdk": target_meta.get("target_sdk", "unknown"),
                "base_min_sdk": base_meta.get("min_sdk", "unknown"),
                "target_min_sdk": target_meta.get("min_sdk", "unknown"),
            },
            "permissions_delta": {
                "added_count": len(added_perms),
                "removed_count": len(removed_perms),
                "dangerous_added_count": sum(1 for p in added_perms if p["is_dangerous"]),
                "dangerous_removed_count": sum(1 for p in removed_perms if p["was_dangerous"]),
                "added": added_perms,
                "removed": removed_perms,
                "retained_count": len(retained_perms)
            },
            "components_delta": {
                "newly_exposed_count": len(newly_exposed_components),
                "secured_count": len(secured_components),
                "newly_exposed": newly_exposed_components,
                "secured": secured_components,
                "total_exported_base": len(base_exp_acts) + len(base_exp_srvs) + len(base_exp_rcvs) + len(base_exp_prvs),
                "total_exported_target": len(target_exp_acts) + len(target_exp_srvs) + len(target_exp_rcvs) + len(target_exp_prvs)
            },
            "findings_delta": {
                "resolved_count": len(resolved_findings),
                "regressed_count": len(new_regressed_findings),
                "persistent_count": len(persistent_findings),
                "resolved": resolved_findings,
                "regressed": new_regressed_findings,
                "persistent": persistent_findings
            },
            "endpoints_delta": {
                "new_count": len(newly_added_endpoints),
                "removed_count": len(removed_endpoints),
                "new_endpoints": newly_added_endpoints,
                "removed_endpoints": removed_endpoints
            }
        }
