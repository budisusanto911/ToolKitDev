# engine/threat_modeling.py
"""
Threat Modeling Engine for Phase 5.

This module provides a high‑level, defensive‑only engine that:
1. Maps findings (e.g., from APK analysis, SCA, or static analysis) to STRIDE categories.
2. Associates each finding with relevant MITRE ATT&CK Mobile technique IDs.
3. Calculates inherent risk and residual risk scores using a simple CVSS‑like formula.
4. Emits a JSON report that can be consumed by the UI or exported as SARIF.

The implementation purposefully avoids generating exploit code or payloads – it is a *risk assessment* tool.
"""

import json
import datetime
from typing import Dict, List, Any

# Simple STRIDE mapping – extend as needed.
_STRIDE_MAP = {
    "Spoofing": ["T1418"],
    "Tampering": ["T1456"],
    "Repudiation": ["T1478"],
    "Information Disclosure": ["T1406"],
    "Denial of Service": ["T1499"],
    "Elevation of Privilege": ["T1405"],
}

# Example severity weights (0‑10) – can be tuned.
_SEVERITY_WEIGHT = {
    "low": 3,
    "medium": 6,
    "high": 9,
    "critical": 10,
}

class ThreatModelingEngine:
    """Core engine for translating security findings into a threat model.

    The engine is deliberately *read‑only* – it does not modify any files.
    It receives a list of findings where each finding is a dict with at least:
        - ``id``: unique identifier
        - ``description``
        - ``severity``: one of ``low``, ``medium``, ``high``, ``critical``
        - ``component``: e.g. ``"apk"``, ``"dependency"``
    The engine returns a dict containing:
        * ``stride_mapping`` – STRIDE categories and ATT&CK IDs
        * ``risk_scores`` – inherent and residual risk per finding
        * ``summary`` – aggregated risk scores
    """

    def __init__(self, findings: List[Dict[str, Any]]):
        self.findings = findings
        self.report: Dict[str, Any] = {}

    def _map_to_stride(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map a single finding to one or more STRIDE categories.

        The mapping is heuristic – it looks for keywords in the description.
        """
        description = finding.get("description", "").lower()
        matched = []
        for stride, techniques in _STRIDE_MAP.items():
            if stride.lower() in description:
                matched.append({"stride": stride, "techniques": techniques})
        # Fallback: if no keyword matched, assign to "Information Disclosure" as a generic category.
        if not matched:
            matched.append({"stride": "Information Disclosure", "techniques": _STRIDE_MAP["Information Disclosure"]})
        return matched

    def _calc_risk(self, severity: str, mitigated: bool = False) -> Dict[str, float]:
        """Calculate inherent and residual risk.

        * Inherent risk = weight(severity) * 1.0
        * Residual risk = weight(severity) * (0.5 if mitigated else 1.0)
        """
        base = _SEVERITY_WEIGHT.get(severity.lower(), 5)
        inherent = float(base)
        residual = inherent * (0.5 if mitigated else 1.0)
        return {"inherent": inherent, "residual": residual}

    def generate_report(self) -> Dict[str, Any]:
        """Public entry point – builds the full threat‑model report.
        """
        stride_mapping = {}
        risk_scores = {}
        total_inherent = 0.0
        total_residual = 0.0

        for f in self.findings:
            fid = f.get("id")
            severity = f.get("severity", "medium")
            mitigated = f.get("mitigated", False)
            # 1️⃣ STRIDE mapping
            mapping = self._map_to_stride(f)
            stride_mapping[fid] = mapping
            # 2️⃣ Risk calculation
            scores = self._calc_risk(severity, mitigated)
            risk_scores[fid] = scores
            total_inherent += scores["inherent"]
            total_residual += scores["residual"]

        self.report = {
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "findings_count": len(self.findings),
            "stride_mapping": stride_mapping,
            "risk_scores": risk_scores,
            "summary": {
                "total_inherent_risk": total_inherent,
                "total_residual_risk": total_residual,
                "risk_reduction_percent": (1 - total_residual / total_inherent) * 100 if total_inherent else 0,
            },
        }
        return self.report

    def to_json(self, indent: int = 2) -> str:
        """Serialize the report to a JSON string.
        """
        if not self.report:
            self.generate_report()
        return json.dumps(self.report, indent=indent)

# Example usage (for quick manual testing, not executed in production):
# if __name__ == "__main__":
#     sample_findings = [
#         {"id": "F001", "description": "Exported activity allows spoofing of intents", "severity": "high", "component": "apk"},
#         {"id": "F002", "description": "Clear‑text HTTP traffic leads to information disclosure", "severity": "medium", "component": "network"},
#     ]
#     engine = ThreatModelingEngine(sample_findings)
#     print(engine.to_json())

