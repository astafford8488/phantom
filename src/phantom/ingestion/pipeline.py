"""Log ingestion pipeline — normalize, enrich, and transform security events.

Supports multiple log formats:
    - Windows Event Log (XML/JSON)
    - Syslog (RFC 5424)
    - JSON (generic structured logs)
    - CEF (Common Event Format)
    - CSV/key-value pair logs
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from phantom.utils.logging import get_logger

logger = get_logger("ingestion")


# Common Event Schema (CES) — internal normalized format
NORMALIZED_FIELDS = {
    "event_id",
    "timestamp",
    "source",
    "category",
    "product",
    "hostname",
    "username",
    "process_name",
    "process_id",
    "parent_process",
    "command_line",
    "file_path",
    "file_hash",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "action",
    "status",
    "severity",
    "message",
    "raw",
}


@dataclass
class PipelineStats:
    """Statistics for a pipeline run."""

    total_input: int = 0
    total_output: int = 0
    dropped: int = 0
    enriched: int = 0
    errors: int = 0
    elapsed_ms: float = 0.0


@dataclass
class LogPipeline:
    """Multi-format log normalization pipeline.

    Transforms heterogeneous security logs into a Common Event Schema
    for uniform processing by detection engines.
    """

    field_mappings: dict[str, str] = field(default_factory=dict)
    enrichment_enabled: bool = True
    drop_empty: bool = True

    def __post_init__(self) -> None:
        # Default field mappings: source field → normalized field
        if not self.field_mappings:
            self.field_mappings = {
                # Windows Event Log mappings
                "EventID": "event_id",
                "TimeCreated": "timestamp",
                "Computer": "hostname",
                "TargetUserName": "username",
                "SubjectUserName": "username",
                "NewProcessName": "process_name",
                "ProcessId": "process_id",
                "ParentProcessName": "parent_process",
                "CommandLine": "command_line",
                "TargetFilename": "file_path",
                "SourceAddress": "src_ip",
                "DestAddress": "dst_ip",
                "SourcePort": "src_port",
                "DestPort": "dst_port",
                "Image": "process_name",
                "ParentImage": "parent_process",
                "User": "username",
                "LogonType": "logon_type",
                # Syslog mappings
                "HOST": "hostname",
                "PROGRAM": "process_name",
                "PID": "process_id",
                "MSG": "message",
                # CEF mappings
                "src": "src_ip",
                "dst": "dst_ip",
                "spt": "src_port",
                "dpt": "dst_port",
                "act": "action",
                "duser": "username",
                "fname": "file_path",
                "msg": "message",
                "deviceHostName": "hostname",
            }

    def normalize(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Normalize a batch of events to Common Event Schema."""
        start = time.time()
        stats = PipelineStats(total_input=len(events))
        normalized: list[dict[str, Any]] = []

        for event in events:
            try:
                result = self._normalize_event(event)
                if result or not self.drop_empty:
                    if self.enrichment_enabled:
                        result = self._enrich(result)
                        stats.enriched += 1
                    normalized.append(result)
                    stats.total_output += 1
                else:
                    stats.dropped += 1
            except Exception as e:
                stats.errors += 1
                logger.warning("Normalization error", error=str(e))

        stats.elapsed_ms = (time.time() - start) * 1000
        logger.info(
            "Pipeline complete",
            input=stats.total_input,
            output=stats.total_output,
            dropped=stats.dropped,
            errors=stats.errors,
            ms=f"{stats.elapsed_ms:.1f}",
        )
        return normalized

    def _normalize_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Normalize a single event."""
        normalized: dict[str, Any] = {}

        # Detect format and parse accordingly
        fmt = self._detect_format(event)

        if fmt == "cef":
            normalized = self._parse_cef(event)
        elif fmt == "syslog":
            normalized = self._parse_syslog(event)
        else:
            # JSON or dict — apply field mappings
            normalized = self._apply_mappings(event)

        # Ensure required fields
        if "event_id" not in normalized:
            normalized["event_id"] = self._generate_event_id(event)
        if "timestamp" not in normalized:
            normalized["timestamp"] = time.time()
        else:
            normalized["timestamp"] = self._parse_timestamp(normalized["timestamp"])

        # Preserve original event
        normalized["raw"] = event

        # Copy through fields that are already normalized
        for key, value in event.items():
            norm_key = key.lower().replace("-", "_").replace(" ", "_")
            if norm_key in NORMALIZED_FIELDS and norm_key not in normalized:
                normalized[norm_key] = value

        return normalized

    def _detect_format(self, event: dict[str, Any]) -> str:
        """Detect the log format of an event."""
        raw = event.get("raw", event.get("message", ""))
        if isinstance(raw, str):
            if raw.startswith("CEF:"):
                return "cef"
            if re.match(r"<\d+>", raw):
                return "syslog"
        if "EventID" in event or "System" in event:
            return "windows"
        return "json"

    def _parse_cef(self, event: dict[str, Any]) -> dict[str, Any]:
        """Parse Common Event Format log."""
        raw = event.get("raw", event.get("message", ""))
        result: dict[str, Any] = {"source": "cef"}

        if not isinstance(raw, str) or not raw.startswith("CEF:"):
            return self._apply_mappings(event)

        # CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        parts = raw.split("|", 7)
        if len(parts) >= 7:
            result["product"] = parts[2]
            result["event_id"] = parts[4]
            result["message"] = parts[5]
            result["severity"] = self._normalize_severity(parts[6])

            # Parse extension key=value pairs
            if len(parts) == 8:
                extensions = self._parse_kv_pairs(parts[7])
                for k, v in extensions.items():
                    mapped = self.field_mappings.get(k, k)
                    result[mapped] = v

        return result

    def _parse_syslog(self, event: dict[str, Any]) -> dict[str, Any]:
        """Parse syslog format."""
        raw = event.get("raw", event.get("message", ""))
        result: dict[str, Any] = {"source": "syslog"}

        if isinstance(raw, str):
            # RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG
            syslog_re = re.compile(
                r"<(\d+)>(\d*)?\s*"
                r"(\S+)\s+"  # timestamp
                r"(\S+)\s+"  # hostname
                r"(\S+)\s+"  # app-name
                r"(?:(\S+)\s+)?"  # procid
                r"(?:(\S+)\s+)?"  # msgid
                r"(.*)"  # message
            )
            match = syslog_re.match(raw)
            if match:
                result["severity"] = self._syslog_severity(int(match.group(1)))
                result["timestamp"] = match.group(3)
                result["hostname"] = match.group(4)
                result["process_name"] = match.group(5)
                if match.group(6) and match.group(6) != "-":
                    result["process_id"] = match.group(6)
                result["message"] = match.group(8)

        # Also apply field mappings for any structured fields
        mapped = self._apply_mappings(event)
        for k, v in mapped.items():
            if k not in result:
                result[k] = v

        return result

    def _apply_mappings(self, event: dict[str, Any]) -> dict[str, Any]:
        """Apply field mappings to normalize field names."""
        result: dict[str, Any] = {}

        for key, value in event.items():
            if key in self.field_mappings:
                result[self.field_mappings[key]] = value
            else:
                result[key] = value

        return result

    def _enrich(self, event: dict[str, Any]) -> dict[str, Any]:
        """Enrich event with derived fields."""
        # Extract process name from full path
        if "process_name" in event and isinstance(event["process_name"], str):
            full_path = event["process_name"]
            if "\\" in full_path or "/" in full_path:
                event["process_path"] = full_path
                event["process_name"] = full_path.replace("\\", "/").split("/")[-1]

        # Flag suspicious command-line patterns
        cmd = str(event.get("command_line", "")).lower()
        if cmd:
            suspicious_patterns = [
                r"-enc\b", r"-encodedcommand\b", r"invoke-expression",
                r"downloadstring", r"invoke-webrequest", r"frombase64",
                r"bypass\b.*executionpolicy", r"hidden\b.*window",
                r"/c\s+.*powershell", r"certutil.*-decode",
                r"bitsadmin.*transfer", r"mshta\b", r"regsvr32\b.*scrobj",
                r"rundll32\b.*javascript", r"wmic\b.*process\b.*call",
            ]
            event["suspicious_cmd"] = any(
                re.search(p, cmd) for p in suspicious_patterns
            )

        # Categorize network connections
        dst_port = event.get("dst_port")
        if dst_port is not None:
            try:
                port = int(dst_port)
                event["service"] = self._port_to_service(port)
            except (ValueError, TypeError):
                pass

        return event

    @staticmethod
    def _generate_event_id(event: dict[str, Any]) -> str:
        """Generate a deterministic event ID from content hash."""
        content = json.dumps(event, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    @staticmethod
    def _parse_timestamp(value: Any) -> float:
        """Parse various timestamp formats to epoch float."""
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            for fmt in [
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S",
                "%b %d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S",
            ]:
                try:
                    dt = datetime.strptime(value, fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt.timestamp()
                except ValueError:
                    continue
        return time.time()

    @staticmethod
    def _normalize_severity(value: str) -> str:
        """Normalize severity strings."""
        value = value.strip().lower()
        mapping = {
            "10": "critical", "9": "critical", "8": "high",
            "7": "high", "6": "medium", "5": "medium",
            "4": "low", "3": "low", "2": "informational",
            "1": "informational", "0": "informational",
            "critical": "critical", "high": "high",
            "medium": "medium", "low": "low",
            "info": "informational", "informational": "informational",
        }
        return mapping.get(value, "medium")

    @staticmethod
    def _syslog_severity(priority: int) -> str:
        """Convert syslog priority to severity string."""
        severity = priority % 8
        if severity <= 2:
            return "critical"
        elif severity == 3:
            return "high"
        elif severity == 4:
            return "medium"
        elif severity == 5:
            return "low"
        return "informational"

    @staticmethod
    def _parse_kv_pairs(text: str) -> dict[str, str]:
        """Parse key=value pairs from a string."""
        result: dict[str, str] = {}
        for match in re.finditer(r"(\w+)=((?:[^\s]|(?<=\\)\s)+)", text):
            result[match.group(1)] = match.group(2)
        return result

    @staticmethod
    def _port_to_service(port: int) -> str:
        """Map common ports to service names."""
        services = {
            22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https",
            445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql",
            1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
            5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
            27017: "mongodb",
        }
        return services.get(port, f"port-{port}")
