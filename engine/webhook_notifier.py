# engine/webhook_notifier.py
"""
Webhook Notifier Engine – Phase 5 (defensive).

Provides utilities to format notifications for:
* Slack (Block Kit JSON)
* Discord (Embed JSON)
* Jira (Issue creation payload)
* SARIF (Static Analysis Results Interchange Format) v2.1.0

All functions return plain ``dict`` objects that can be ``json.dumps``‑ed and sent
via an HTTP ``POST`` to the respective service endpoint.  No HTTP requests are
performed here – the ``server.py`` endpoint will handle transmission.
"""

import datetime
import json
from typing import Dict, Any, List

# ---------------------------------------------------------------------------
# Helper – common fields
# ---------------------------------------------------------------------------

def _timestamp() -> str:
    """ISO‑8601 UTC timestamp used in SARIF and other payloads."""
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

# ---------------------------------------------------------------------------
# Slack Block Kit formatter
# ---------------------------------------------------------------------------

def format_slack(message: str, severity: str = "info", title: str | None = None) -> Dict[str, Any]:
    """Return a Slack *Block Kit* payload.

    Parameters
    ----------
    message: str
        Human‑readable description of the finding or event.
    severity: str, optional
        One of ``info``, ``warning``, ``danger`` – maps to a colour accent.
    title: str, optional
        Short title displayed above the message block.
    """
    colour_map = {"info": "#2EB67D", "warning": "#ECB22E", "danger": "#E01E5A"}
    colour = colour_map.get(severity.lower(), "#2EB67D")
    blocks: List[Dict[str, Any]] = []
    if title:
        blocks.append({"type": "header", "text": {"type": "plain_text", "text": title, "emoji": True}})
    blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": message}})
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": f"Generated at {_timestamp()}"}]})
    return {"blocks": blocks, "attachments": [{"color": colour}]}

# ---------------------------------------------------------------------------
# Discord embed formatter
# ---------------------------------------------------------------------------

def format_discord(message: str, severity: str = "info", title: str | None = None) -> Dict[str, Any]:
    """Return a Discord *embed* payload.

    The payload matches the JSON schema accepted by Discord webhook ``POST``.
    """
    colour_map = {"info": 0x2EB67D, "warning": 0xECB22E, "danger": 0xE01E5A}
    colour = colour_map.get(severity.lower(), 0x2EB67D)
    embed: Dict[str, Any] = {"description": message, "timestamp": _timestamp(), "color": colour}
    if title:
        embed["title"] = title
    return {"embeds": [embed]}

# ---------------------------------------------------------------------------
# Jira issue creation payload
# ---------------------------------------------------------------------------

def format_jira(summary: str, description: str, project_key: str = "TKD", issue_type: str = "Task") -> Dict[str, Any]:
    """Return a payload compatible with Jira's ``/rest/api/2/issue`` endpoint.

    Only the minimal required fields are populated – callers can extend the
    dictionary with additional fields (labels, components, etc.) before sending.
    """
    return {
        "fields": {
            "project": {"key": project_key},
            "summary": summary,
            "description": description,
            "issuetype": {"name": issue_type},
        }
    }

# ---------------------------------------------------------------------------
# SARIF generator
# ---------------------------------------------------------------------------

def generate_sarif(analysis: Dict[str, Any], tool_name: str = "ToolKitDev", tool_version: str = "2.0") -> Dict[str, Any]:
    """Create a SARIF 2.1.0 report from an analysis dictionary.

    The ``analysis`` dict is expected to contain a ``findings`` key whose value is
    a list of findings where each finding has at minimum:
        - ``id`` (string)
        - ``title`` (string)
        - ``description`` (string)
        - ``severity`` (one of ``LOW``, ``MEDIUM``, ``HIGH``, ``CRITICAL``)
        - ``location`` (optional dict with ``uri`` and ``region``)
    The function produces a SARIF structure conforming to the official schema.
    """
    runs: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []
    for f in analysis.get("findings", []):
        severity = f.get("severity", "LOW").upper()
        level = {
            "LOW": "note",
            "MEDIUM": "warning",
            "HIGH": "error",
            "CRITICAL": "error",
        }.get(severity, "note")
        result: Dict[str, Any] = {
            "ruleId": f.get("id", "unknown"),
            "level": level,
            "message": {"text": f.get("title", "")},
            "locations": [],
        }
        loc = f.get("location")
        if isinstance(loc, dict):
            physical = {
                "artifactLocation": {"uri": loc.get("uri", "")},
                "region": loc.get("region", {}),
            }
            result["locations"].append({"physicalLocation": physical})
        results.append(result)
    runs.append({
        "tool": {"driver": {"name": tool_name, "version": tool_version, "informationUri": "https://github.com/budisusanto911/ToolKitDev"}},
        "results": results,
        "invocations": [{"executionSuccessful": True, "startTimeUtc": _timestamp()}],
    })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": runs}

# ---------------------------------------------------------------------------
# Public façade – convenience wrapper
# ---------------------------------------------------------------------------

def format_notification(platform: str, **kwargs: Any) -> Dict[str, Any]:
    """Dispatch to the appropriate formatter based on ``platform``.

    ``platform`` can be ``"slack"``, ``"discord"``, ``"jira"`` or ``"sarif"``.
    Unknown platforms raise ``ValueError``.
    """
    platform = platform.lower()
    if platform == "slack":
        return format_slack(**kwargs)
    if platform == "discord":
        return format_discord(**kwargs)
    if platform == "jira":
        return format_jira(**kwargs)
    if platform == "sarif":
        return generate_sarif(**kwargs)
    raise ValueError(f"Unsupported platform: {platform}")

# End of file

