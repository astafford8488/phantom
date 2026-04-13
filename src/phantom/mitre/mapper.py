"""MITRE ATT&CK mapper — coverage analysis and gap identification.

Provides:
    - Technique-to-tactic mapping
    - Coverage heatmap generation
    - Gap analysis and recommendations
    - Detection coverage scoring
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from phantom.utils.logging import get_logger

logger = get_logger("mitre")


# MITRE ATT&CK Enterprise Tactics (v14)
TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# High-priority techniques per tactic (subset for demonstration)
# Maps technique ID → (name, tactic, priority)
TECHNIQUE_CATALOG: dict[str, tuple[str, str, str]] = {
    # Initial Access
    "T1566": ("Phishing", "Initial Access", "high"),
    "T1566.001": ("Spearphishing Attachment", "Initial Access", "high"),
    "T1566.002": ("Spearphishing Link", "Initial Access", "high"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access", "critical"),
    "T1078": ("Valid Accounts", "Initial Access", "critical"),
    "T1133": ("External Remote Services", "Initial Access", "high"),
    "T1199": ("Trusted Relationship", "Initial Access", "medium"),
    # Execution
    "T1059": ("Command and Scripting Interpreter", "Execution", "critical"),
    "T1059.001": ("PowerShell", "Execution", "critical"),
    "T1059.003": ("Windows Command Shell", "Execution", "high"),
    "T1059.005": ("Visual Basic", "Execution", "high"),
    "T1059.006": ("Python", "Execution", "medium"),
    "T1059.007": ("JavaScript", "Execution", "medium"),
    "T1204": ("User Execution", "Execution", "high"),
    "T1204.001": ("Malicious Link", "Execution", "high"),
    "T1204.002": ("Malicious File", "Execution", "high"),
    "T1203": ("Exploitation for Client Execution", "Execution", "high"),
    # Persistence
    "T1547": ("Boot or Logon Autostart Execution", "Persistence", "critical"),
    "T1547.001": ("Registry Run Keys", "Persistence", "critical"),
    "T1053": ("Scheduled Task/Job", "Persistence", "high"),
    "T1053.005": ("Scheduled Task", "Persistence", "high"),
    "T1136": ("Create Account", "Persistence", "high"),
    "T1136.001": ("Local Account", "Persistence", "high"),
    "T1543": ("Create or Modify System Process", "Persistence", "high"),
    "T1098": ("Account Manipulation", "Persistence", "high"),
    # Privilege Escalation
    "T1548": ("Abuse Elevation Control Mechanism", "Privilege Escalation", "high"),
    "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation", "critical"),
    "T1055": ("Process Injection", "Privilege Escalation", "critical"),
    # Defense Evasion
    "T1562": ("Impair Defenses", "Defense Evasion", "critical"),
    "T1562.001": ("Disable or Modify Tools", "Defense Evasion", "critical"),
    "T1070": ("Indicator Removal", "Defense Evasion", "high"),
    "T1070.001": ("Clear Windows Event Logs", "Defense Evasion", "high"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion", "high"),
    "T1036": ("Masquerading", "Defense Evasion", "high"),
    "T1218": ("System Binary Proxy Execution", "Defense Evasion", "high"),
    # Credential Access
    "T1003": ("OS Credential Dumping", "Credential Access", "critical"),
    "T1003.001": ("LSASS Memory", "Credential Access", "critical"),
    "T1110": ("Brute Force", "Credential Access", "high"),
    "T1110.003": ("Password Spraying", "Credential Access", "high"),
    "T1555": ("Credentials from Password Stores", "Credential Access", "high"),
    "T1552": ("Unsecured Credentials", "Credential Access", "medium"),
    # Discovery
    "T1087": ("Account Discovery", "Discovery", "medium"),
    "T1082": ("System Information Discovery", "Discovery", "low"),
    "T1083": ("File and Directory Discovery", "Discovery", "low"),
    "T1016": ("System Network Configuration Discovery", "Discovery", "medium"),
    "T1049": ("System Network Connections Discovery", "Discovery", "medium"),
    "T1069": ("Permission Groups Discovery", "Discovery", "medium"),
    # Lateral Movement
    "T1021": ("Remote Services", "Lateral Movement", "high"),
    "T1021.001": ("Remote Desktop Protocol", "Lateral Movement", "high"),
    "T1021.002": ("SMB/Windows Admin Shares", "Lateral Movement", "high"),
    "T1021.006": ("Windows Remote Management", "Lateral Movement", "high"),
    "T1570": ("Lateral Tool Transfer", "Lateral Movement", "high"),
    # Collection
    "T1560": ("Archive Collected Data", "Collection", "medium"),
    "T1005": ("Data from Local System", "Collection", "medium"),
    "T1114": ("Email Collection", "Collection", "high"),
    # Command and Control
    "T1071": ("Application Layer Protocol", "Command and Control", "high"),
    "T1071.001": ("Web Protocols", "Command and Control", "high"),
    "T1105": ("Ingress Tool Transfer", "Command and Control", "high"),
    "T1573": ("Encrypted Channel", "Command and Control", "medium"),
    "T1572": ("Protocol Tunneling", "Command and Control", "high"),
    # Exfiltration
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration", "critical"),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration", "high"),
    "T1567": ("Exfiltration Over Web Service", "Exfiltration", "high"),
    # Impact
    "T1486": ("Data Encrypted for Impact", "Impact", "critical"),
    "T1490": ("Inhibit System Recovery", "Impact", "critical"),
    "T1489": ("Service Stop", "Impact", "high"),
    "T1529": ("System Shutdown/Reboot", "Impact", "medium"),
}


@dataclass
class CoverageGap:
    """A gap in MITRE ATT&CK coverage."""

    technique_id: str
    technique_name: str
    tactic: str
    priority: str
    recommendation: str


class MitreMapper:
    """MITRE ATT&CK mapping and coverage analysis engine."""

    def __init__(self) -> None:
        self._covered: set[str] = set()

    def map_technique(self, technique_id: str) -> dict[str, str] | None:
        """Look up a technique by ID."""
        tech_id = technique_id.upper()
        if tech_id in TECHNIQUE_CATALOG:
            name, tactic, priority = TECHNIQUE_CATALOG[tech_id]
            return {
                "id": tech_id,
                "name": name,
                "tactic": tactic,
                "priority": priority,
            }
        return None

    def coverage_report(self, detected_techniques: list[str]) -> dict[str, Any]:
        """Generate a MITRE ATT&CK coverage report.

        Args:
            detected_techniques: List of technique IDs covered by detections.

        Returns:
            Coverage report with per-tactic breakdown and gap analysis.
        """
        self._covered = {t.upper() for t in detected_techniques}

        total = len(TECHNIQUE_CATALOG)
        covered = sum(1 for t in self._covered if t in TECHNIQUE_CATALOG)

        # Per-tactic coverage
        tactic_coverage: dict[str, dict[str, int]] = {}
        for tactic in TACTICS:
            tactic_techs = {
                tid for tid, (_, t, _) in TECHNIQUE_CATALOG.items()
                if t == tactic
            }
            tactic_covered = tactic_techs & self._covered
            tactic_coverage[tactic] = {
                "total": len(tactic_techs),
                "covered": len(tactic_covered),
                "percentage": (len(tactic_covered) / len(tactic_techs) * 100) if tactic_techs else 0,
            }

        # Identify gaps
        gaps = self._identify_gaps()

        # Priority coverage
        priority_stats: dict[str, dict[str, int]] = {}
        for priority in ["critical", "high", "medium", "low"]:
            priority_techs = {
                tid for tid, (_, _, p) in TECHNIQUE_CATALOG.items()
                if p == priority
            }
            priority_covered = priority_techs & self._covered
            priority_stats[priority] = {
                "total": len(priority_techs),
                "covered": len(priority_covered),
                "percentage": (len(priority_covered) / len(priority_techs) * 100) if priority_techs else 0,
            }

        report = {
            "total": total,
            "covered": covered,
            "percentage": (covered / total * 100) if total else 0,
            "by_tactic": tactic_coverage,
            "by_priority": priority_stats,
            "gaps": [
                {
                    "id": g.technique_id,
                    "name": g.technique_name,
                    "tactic": g.tactic,
                    "priority": g.priority,
                    "recommendation": g.recommendation,
                }
                for g in gaps[:20]  # Top 20 gaps
            ],
            "gap_count": len(gaps),
        }

        logger.info(
            "Coverage report generated",
            covered=covered,
            total=total,
            pct=f"{report['percentage']:.1f}%",
            gaps=len(gaps),
        )

        return report

    def _identify_gaps(self) -> list[CoverageGap]:
        """Identify high-priority gaps in coverage."""
        gaps: list[CoverageGap] = []
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        for tech_id, (name, tactic, priority) in TECHNIQUE_CATALOG.items():
            if tech_id not in self._covered:
                gaps.append(CoverageGap(
                    technique_id=tech_id,
                    technique_name=name,
                    tactic=tactic,
                    priority=priority,
                    recommendation=self._recommend(tech_id, name, tactic),
                ))

        # Sort by priority (critical first)
        gaps.sort(key=lambda g: priority_order.get(g.priority, 99))
        return gaps

    @staticmethod
    def _recommend(tech_id: str, name: str, tactic: str) -> str:
        """Generate a detection recommendation for a gap."""
        recommendations: dict[str, str] = {
            "Initial Access": f"Create Sigma rules for {name} ({tech_id}) using network/email log sources",
            "Execution": f"Monitor process creation events for {name} ({tech_id}) patterns",
            "Persistence": f"Create file/registry monitoring rules for {name} ({tech_id})",
            "Privilege Escalation": f"Monitor for {name} ({tech_id}) via process/token events",
            "Defense Evasion": f"Detect {name} ({tech_id}) via process and file integrity monitoring",
            "Credential Access": f"Monitor authentication logs and LSASS access for {name} ({tech_id})",
            "Discovery": f"Baseline normal discovery activity and alert on anomalous {name} ({tech_id})",
            "Lateral Movement": f"Monitor network connections and authentication for {name} ({tech_id})",
            "Collection": f"Monitor file access patterns for {name} ({tech_id})",
            "Command and Control": f"Monitor network traffic for {name} ({tech_id}) patterns",
            "Exfiltration": f"Monitor outbound data transfers for {name} ({tech_id})",
            "Impact": f"Create high-priority alerts for {name} ({tech_id}) indicators",
        }
        return recommendations.get(tactic, f"Create detection rules for {name} ({tech_id})")

    def heatmap_data(self) -> dict[str, list[dict[str, Any]]]:
        """Generate data for MITRE ATT&CK heatmap visualization."""
        heatmap: dict[str, list[dict[str, Any]]] = {}

        for tactic in TACTICS:
            techniques: list[dict[str, Any]] = []
            for tech_id, (name, t, priority) in TECHNIQUE_CATALOG.items():
                if t == tactic:
                    techniques.append({
                        "id": tech_id,
                        "name": name,
                        "covered": tech_id in self._covered,
                        "priority": priority,
                    })
            heatmap[tactic] = sorted(techniques, key=lambda x: x["id"])

        return heatmap

    def get_tactic_for_technique(self, technique_id: str) -> str | None:
        """Get the tactic associated with a technique."""
        tech_id = technique_id.upper()
        if tech_id in TECHNIQUE_CATALOG:
            return TECHNIQUE_CATALOG[tech_id][1]
        return None
