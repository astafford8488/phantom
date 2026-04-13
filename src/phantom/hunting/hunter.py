"""Autonomous threat hunter — LLM-powered hypothesis generation and investigation.

Implements a structured hunting loop:
    1. Generate hypotheses from event context and existing alerts
    2. Execute investigations (queries/correlations) against event data
    3. Evaluate findings and generate follow-up hypotheses
    4. Produce structured hunting reports
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any

from phantom.utils.logging import get_logger

logger = get_logger("hunting")


@dataclass
class HuntHypothesis:
    """A threat hunting hypothesis."""

    id: str
    title: str
    description: str
    mitre_technique: str = ""
    query_logic: str = ""
    priority: str = "medium"  # critical, high, medium, low
    status: str = "pending"  # pending, investigating, confirmed, dismissed


@dataclass
class HuntFinding:
    """A confirmed finding from threat hunting."""

    hypothesis_id: str
    title: str
    description: str
    severity: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    confidence: float = 0.0


# Built-in hunting playbooks (no LLM required)
HUNTING_PLAYBOOKS: list[dict[str, Any]] = [
    {
        "id": "hunt-lateral-movement",
        "title": "Lateral Movement Detection",
        "description": "Hunt for indicators of lateral movement across network segments",
        "technique": "T1021",
        "indicators": {
            "processes": ["psexec", "wmic", "winrm", "smbclient", "net use"],
            "ports": [445, 135, 3389, 5985, 5986, 22],
            "patterns": [r"\\\\[\d\.]+\\", r"net\s+use\s+\\\\"],
        },
    },
    {
        "id": "hunt-persistence",
        "title": "Persistence Mechanism Detection",
        "description": "Hunt for newly established persistence mechanisms",
        "technique": "T1547",
        "indicators": {
            "processes": ["schtasks", "at.exe", "reg add", "sc create", "wmic startup"],
            "paths": [
                r"\\CurrentVersion\\Run",
                r"\\Startup\\",
                r"\\Services\\",
                r"\\Tasks\\",
            ],
            "patterns": [
                r"schtasks\s+/create",
                r"reg\s+add\s+.*\\Run",
                r"sc\s+create",
                r"wmic\s+.*startup",
            ],
        },
    },
    {
        "id": "hunt-credential-access",
        "title": "Credential Access Detection",
        "description": "Hunt for credential harvesting and dumping activity",
        "technique": "T1003",
        "indicators": {
            "processes": ["mimikatz", "procdump", "sekurlsa", "lsass", "gsecdump", "pwdumpx"],
            "patterns": [
                r"sekurlsa::logonpasswords",
                r"procdump.*lsass",
                r"comsvcs\.dll.*MiniDump",
                r"ntdsutil.*\"ac i ntds\"",
            ],
        },
    },
    {
        "id": "hunt-exfiltration",
        "title": "Data Exfiltration Detection",
        "description": "Hunt for indicators of data exfiltration",
        "technique": "T1041",
        "indicators": {
            "processes": ["rclone", "megacmd", "curl", "wget", "ftp", "scp"],
            "ports": [20, 21, 22, 443, 8443, 9443],
            "patterns": [
                r"rclone\s+copy",
                r"curl.*-T\s",
                r"curl.*--upload",
                r"Invoke-WebRequest.*-Method\s+POST",
            ],
        },
    },
    {
        "id": "hunt-defense-evasion",
        "title": "Defense Evasion Detection",
        "description": "Hunt for attempts to disable security tools and evade detection",
        "technique": "T1562",
        "indicators": {
            "processes": ["powershell", "cmd", "wmic", "net stop", "sc stop"],
            "patterns": [
                r"Set-MpPreference\s+-DisableRealtimeMonitoring",
                r"net\s+stop\s+.*(?:security|defender|antivirus)",
                r"sc\s+stop\s+.*(?:security|defender)",
                r"wevtutil\s+cl",
                r"Remove-Item.*\\Logs\\",
            ],
        },
    },
    {
        "id": "hunt-discovery",
        "title": "Internal Reconnaissance Detection",
        "description": "Hunt for system and network discovery activity",
        "technique": "T1087",
        "indicators": {
            "processes": ["net.exe", "whoami", "ipconfig", "systeminfo", "nltest", "dsquery"],
            "patterns": [
                r"net\s+(user|group|localgroup)\s",
                r"nltest\s+/dclist",
                r"dsquery\s+(user|computer|group)",
                r"Get-ADUser",
                r"Get-ADComputer",
                r"whoami\s+/all",
            ],
        },
    },
]


class ThreatHunter:
    """Autonomous threat hunting engine.

    Combines structured playbooks with LLM-generated hypotheses
    for comprehensive threat hunting across security events.
    """

    def __init__(
        self,
        max_hypotheses: int = 10,
        llm_model: str = "claude-sonnet-4-20250514",
        use_llm: bool = False,
    ) -> None:
        self.max_hypotheses = max_hypotheses
        self.llm_model = llm_model
        self.use_llm = use_llm
        self._findings: list[dict[str, Any]] = []
        self._hunt_history: list[HuntHypothesis] = []

    async def hunt(
        self,
        events: list[dict[str, Any]],
        existing_alerts: list[Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute autonomous threat hunting.

        1. Run built-in playbooks against events
        2. Optionally generate LLM hypotheses
        3. Return structured findings
        """
        findings: list[dict[str, Any]] = []
        start = time.time()

        # Stage 1: Execute built-in playbooks
        logger.info("Running hunting playbooks", count=len(HUNTING_PLAYBOOKS))
        for playbook in HUNTING_PLAYBOOKS:
            playbook_findings = self._execute_playbook(playbook, events)
            findings.extend(playbook_findings)

        # Stage 2: Pattern-based hunting
        pattern_findings = self._pattern_hunt(events)
        findings.extend(pattern_findings)

        # Stage 3: Temporal correlation hunting
        temporal_findings = self._temporal_hunt(events)
        findings.extend(temporal_findings)

        # Stage 4: LLM-powered hunting (if enabled)
        if self.use_llm and events:
            try:
                llm_findings = await self._llm_hunt(events, existing_alerts or [])
                findings.extend(llm_findings)
            except Exception as e:
                logger.warning("LLM hunting failed", error=str(e))

        elapsed = time.time() - start
        logger.info(
            "Hunting complete",
            findings=len(findings),
            duration=f"{elapsed:.1f}s",
        )

        self._findings.extend(findings)
        return findings

    def _execute_playbook(
        self, playbook: dict[str, Any], events: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Execute a single hunting playbook against events."""
        findings: list[dict[str, Any]] = []
        indicators = playbook.get("indicators", {})
        matched_events: list[dict[str, Any]] = []

        for event in events:
            matched = False

            # Check process indicators
            process = str(event.get("process_name", "")).lower()
            cmd = str(event.get("command_line", "")).lower()
            combined_cmd = f"{process} {cmd}"

            for proc in indicators.get("processes", []):
                if proc.lower() in combined_cmd:
                    matched = True
                    break

            # Check regex patterns
            if not matched:
                for pattern in indicators.get("patterns", []):
                    if re.search(pattern, combined_cmd, re.IGNORECASE):
                        matched = True
                        break

            # Check path indicators
            if not matched:
                file_path = str(event.get("file_path", "")).lower()
                for path_pattern in indicators.get("paths", []):
                    if re.search(path_pattern, file_path, re.IGNORECASE):
                        matched = True
                        break

            # Check port indicators
            if not matched:
                dst_port = event.get("dst_port")
                if dst_port is not None:
                    try:
                        if int(dst_port) in indicators.get("ports", []):
                            matched = True
                    except (ValueError, TypeError):
                        pass

            if matched:
                matched_events.append(event)

        if matched_events:
            findings.append({
                "type": "playbook",
                "playbook_id": playbook["id"],
                "title": playbook["title"],
                "description": playbook["description"],
                "severity": "high" if len(matched_events) > 3 else "medium",
                "mitre_technique": playbook.get("technique", ""),
                "matched_events": matched_events,
                "event_count": len(matched_events),
                "confidence": min(0.5 + len(matched_events) * 0.1, 0.95),
            })

        return findings

    def _pattern_hunt(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Hunt for suspicious patterns across events."""
        findings: list[dict[str, Any]] = []

        # Hunt 1: PowerShell with encoded commands
        encoded_ps = [
            e for e in events
            if any(x in str(e.get("command_line", "")).lower()
                   for x in ["-enc", "-encodedcommand", "frombase64string"])
        ]
        if encoded_ps:
            findings.append({
                "type": "pattern",
                "title": "Encoded PowerShell Execution",
                "description": "Detected PowerShell execution with encoded commands, commonly used for obfuscation",
                "severity": "high",
                "mitre_technique": "T1059.001",
                "matched_events": encoded_ps,
                "event_count": len(encoded_ps),
                "confidence": 0.85,
            })

        # Hunt 2: Unusual parent-child process relationships
        suspicious_parents = {
            "excel.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"],
            "word.exe": ["cmd.exe", "powershell.exe", "wscript.exe"],
            "outlook.exe": ["cmd.exe", "powershell.exe"],
            "winword.exe": ["cmd.exe", "powershell.exe", "wscript.exe"],
            "iexplore.exe": ["cmd.exe", "powershell.exe"],
        }
        offspring = []
        for event in events:
            parent = str(event.get("parent_process", "")).lower().split("/")[-1].split("\\")[-1]
            child = str(event.get("process_name", "")).lower().split("/")[-1].split("\\")[-1]
            if parent in suspicious_parents and child in suspicious_parents[parent]:
                offspring.append(event)

        if offspring:
            findings.append({
                "type": "pattern",
                "title": "Suspicious Parent-Child Process Relationship",
                "description": "Detected unusual process spawning from Office/browser applications",
                "severity": "high",
                "mitre_technique": "T1204.002",
                "matched_events": offspring,
                "event_count": len(offspring),
                "confidence": 0.9,
            })

        # Hunt 3: Rapid authentication failures
        auth_failures = [
            e for e in events
            if str(e.get("action", "")).lower() in ["logon_failed", "auth_failure", "4625"]
            or str(e.get("event_id", "")) == "4625"
        ]
        if len(auth_failures) >= 5:
            findings.append({
                "type": "pattern",
                "title": "Brute Force / Password Spraying Detected",
                "description": f"Detected {len(auth_failures)} authentication failures indicating potential credential attack",
                "severity": "high",
                "mitre_technique": "T1110",
                "matched_events": auth_failures,
                "event_count": len(auth_failures),
                "confidence": 0.8,
            })

        return findings

    def _temporal_hunt(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Hunt for temporal anomalies — activity bursts, off-hours activity."""
        findings: list[dict[str, Any]] = []

        if len(events) < 3:
            return findings

        # Detect activity bursts (many events from same entity in short window)
        entity_events: dict[str, list[dict[str, Any]]] = {}
        for event in events:
            entity = event.get("username") or event.get("hostname") or "unknown"
            entity_events.setdefault(entity, []).append(event)

        for entity, elist in entity_events.items():
            if len(elist) < 10:
                continue

            timestamps = sorted(
                e.get("timestamp", 0) for e in elist
                if isinstance(e.get("timestamp"), (int, float))
            )
            if len(timestamps) < 2:
                continue

            # Check for bursts: 10+ events in < 60 seconds
            for i in range(len(timestamps) - 9):
                window = timestamps[i + 9] - timestamps[i]
                if 0 < window < 60:
                    findings.append({
                        "type": "temporal",
                        "title": f"Activity Burst from {entity}",
                        "description": f"Detected {len(elist)} events in rapid succession from entity '{entity}'",
                        "severity": "medium",
                        "mitre_technique": "T1059",
                        "matched_events": elist[:20],
                        "event_count": len(elist),
                        "confidence": 0.7,
                    })
                    break

        return findings

    async def _llm_hunt(
        self,
        events: list[dict[str, Any]],
        existing_alerts: list[Any],
    ) -> list[dict[str, Any]]:
        """Generate and execute LLM-powered hunting hypotheses."""
        import anthropic

        # Build context from events
        event_summary = self._summarize_events(events)
        alert_summary = self._summarize_alerts(existing_alerts)

        prompt = f"""You are an expert threat hunter. Analyze the following security event summary
and existing alerts to generate threat hunting hypotheses.

Event Summary:
{event_summary}

Existing Alerts:
{alert_summary}

Generate up to 3 threat hunting hypotheses in this exact JSON format:
[
  {{
    "title": "Hypothesis title",
    "description": "What to look for and why",
    "mitre_technique": "TXXXX",
    "query_fields": ["field1", "field2"],
    "query_values": ["value1", "value2"],
    "severity": "high",
    "confidence": 0.7
  }}
]

Focus on threats NOT already covered by existing alerts. Output ONLY valid JSON."""

        client = anthropic.AsyncAnthropic()
        response = await client.messages.create(
            model=self.llm_model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
            system="You are a threat hunting expert. Return only valid JSON arrays.",
        )

        import json

        findings: list[dict[str, Any]] = []
        try:
            text = response.content[0].text
            text = re.sub(r"^```(?:json)?\n", "", text)
            text = re.sub(r"\n```$", "", text)
            hypotheses = json.loads(text)

            for hyp in hypotheses[:3]:
                # Execute the hypothesis against events
                matched = self._execute_hypothesis(hyp, events)
                if matched:
                    findings.append({
                        "type": "llm_hypothesis",
                        "title": hyp.get("title", "LLM-Generated Finding"),
                        "description": hyp.get("description", ""),
                        "severity": hyp.get("severity", "medium"),
                        "mitre_technique": hyp.get("mitre_technique", ""),
                        "matched_events": matched,
                        "event_count": len(matched),
                        "confidence": hyp.get("confidence", 0.6),
                    })
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            logger.warning("Failed to parse LLM hunting output", error=str(e))

        return findings

    def _execute_hypothesis(
        self, hypothesis: dict[str, Any], events: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Execute a hypothesis query against events."""
        fields = hypothesis.get("query_fields", [])
        values = hypothesis.get("query_values", [])

        if not fields or not values:
            return []

        matched: list[dict[str, Any]] = []
        for event in events:
            for f in fields:
                event_val = str(event.get(f, "")).lower()
                if any(v.lower() in event_val for v in values):
                    matched.append(event)
                    break

        return matched

    @staticmethod
    def _summarize_events(events: list[dict[str, Any]]) -> str:
        """Create a compact summary of events for LLM context."""
        from collections import Counter

        if not events:
            return "No events."

        processes = Counter(str(e.get("process_name", "")) for e in events if e.get("process_name"))
        users = Counter(str(e.get("username", "")) for e in events if e.get("username"))
        hosts = Counter(str(e.get("hostname", "")) for e in events if e.get("hostname"))

        lines = [
            f"Total events: {len(events)}",
            f"Top processes: {dict(processes.most_common(10))}",
            f"Top users: {dict(users.most_common(10))}",
            f"Top hosts: {dict(hosts.most_common(10))}",
        ]
        return "\n".join(lines)

    @staticmethod
    def _summarize_alerts(alerts: list[Any]) -> str:
        """Create a compact summary of existing alerts."""
        if not alerts:
            return "No existing alerts."

        lines = [f"Total alerts: {len(alerts)}"]
        for alert in alerts[:10]:
            name = getattr(alert, "rule_name", str(alert))
            severity = getattr(alert, "severity", "unknown")
            lines.append(f"  - [{severity}] {name}")
        return "\n".join(lines)
