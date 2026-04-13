"""Graph-based alert correlation — group related alerts into incidents.

Correlation strategies:
    - Entity overlap (shared users, hosts, IPs, processes)
    - MITRE ATT&CK chain detection (kill-chain sequence recognition)
    - Temporal proximity (alerts within time windows)
    - Severity escalation (low → medium → high patterns)
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from phantom.utils.logging import get_logger

logger = get_logger("correlation")


# MITRE ATT&CK kill-chain phases in order
KILL_CHAIN_PHASES = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

# Map technique prefixes to kill-chain phases
TECHNIQUE_TO_PHASE: dict[str, str] = {
    "T1595": "reconnaissance", "T1592": "reconnaissance",
    "T1583": "resource-development", "T1588": "resource-development",
    "T1566": "initial-access", "T1190": "initial-access",
    "T1078": "initial-access", "T1133": "initial-access",
    "T1059": "execution", "T1204": "execution", "T1203": "execution",
    "T1547": "persistence", "T1053": "persistence", "T1136": "persistence",
    "T1548": "privilege-escalation", "T1068": "privilege-escalation",
    "T1562": "defense-evasion", "T1070": "defense-evasion",
    "T1027": "defense-evasion", "T1036": "defense-evasion",
    "T1003": "credential-access", "T1110": "credential-access",
    "T1555": "credential-access", "T1552": "credential-access",
    "T1087": "discovery", "T1082": "discovery", "T1083": "discovery",
    "T1021": "lateral-movement", "T1570": "lateral-movement",
    "T1560": "collection", "T1005": "collection",
    "T1071": "command-and-control", "T1105": "command-and-control",
    "T1041": "exfiltration", "T1048": "exfiltration",
    "T1486": "impact", "T1490": "impact", "T1489": "impact",
}


@dataclass
class CorrelationEdge:
    """Edge between two correlated alerts."""

    alert_a_id: str
    alert_b_id: str
    correlation_type: str  # entity, temporal, killchain, severity
    weight: float = 0.0
    shared_entities: list[str] = field(default_factory=list)


class AlertCorrelator:
    """Graph-based alert correlation engine.

    Builds a correlation graph from alerts and partitions them
    into incidents using connected components with weighted edges.
    """

    def __init__(
        self,
        entity_weight: float = 0.4,
        temporal_weight: float = 0.2,
        killchain_weight: float = 0.3,
        severity_weight: float = 0.1,
        time_window: float = 3600.0,  # 1 hour
        min_correlation: float = 0.3,
    ) -> None:
        self.entity_weight = entity_weight
        self.temporal_weight = temporal_weight
        self.killchain_weight = killchain_weight
        self.severity_weight = severity_weight
        self.time_window = time_window
        self.min_correlation = min_correlation

    def correlate(self, alerts: list[Any]) -> list[Any]:
        """Correlate alerts into incidents.

        Returns list of Incident objects.
        """
        from phantom.engine import Incident

        if not alerts:
            return []

        n = len(alerts)
        if n == 1:
            inc = Incident(
                incident_id=self._gen_id("inc", alerts[0].rule_id),
                title=alerts[0].rule_name,
                severity=alerts[0].severity,
                alerts=alerts,
                mitre_techniques=alerts[0].mitre_techniques,
                confidence=alerts[0].confidence,
            )
            return [inc]

        # Build correlation matrix
        edges: list[CorrelationEdge] = []
        for i in range(n):
            for j in range(i + 1, n):
                score, edge = self._compute_correlation(alerts[i], alerts[j])
                if score >= self.min_correlation:
                    edges.append(edge)

        # Build adjacency graph
        adj: dict[int, set[int]] = defaultdict(set)
        for edge in edges:
            a_idx = self._find_alert_index(alerts, edge.alert_a_id)
            b_idx = self._find_alert_index(alerts, edge.alert_b_id)
            if a_idx >= 0 and b_idx >= 0:
                adj[a_idx].add(b_idx)
                adj[b_idx].add(a_idx)

        # Find connected components (incidents)
        visited: set[int] = set()
        components: list[list[int]] = []

        for i in range(n):
            if i not in visited:
                component: list[int] = []
                self._dfs(i, adj, visited, component)
                components.append(component)

        # Create incidents from components
        incidents: list[Incident] = []
        for comp in components:
            comp_alerts = [alerts[i] for i in comp]

            # Determine incident severity (highest alert severity)
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
            max_severity = max(comp_alerts, key=lambda a: severity_order.get(a.severity, 0))

            # Collect all MITRE techniques
            all_techniques: list[str] = []
            for a in comp_alerts:
                all_techniques.extend(a.mitre_techniques)
            unique_techniques = list(set(all_techniques))

            # Generate title
            title = self._generate_incident_title(comp_alerts, unique_techniques)

            # Compute confidence
            avg_confidence = sum(a.confidence for a in comp_alerts) / len(comp_alerts)
            chain_bonus = self._killchain_coverage_bonus(unique_techniques)
            confidence = min(avg_confidence + chain_bonus, 1.0)

            incidents.append(Incident(
                incident_id=self._gen_id("inc", "-".join(a.rule_id for a in comp_alerts[:3])),
                title=title,
                severity=max_severity.severity,
                alerts=comp_alerts,
                mitre_techniques=unique_techniques,
                confidence=confidence,
            ))

        logger.info(
            "Correlation complete",
            alerts=n,
            incidents=len(incidents),
            edges=len(edges),
        )
        return incidents

    def _compute_correlation(self, a: Any, b: Any) -> tuple[float, CorrelationEdge]:
        """Compute correlation score between two alerts."""
        score = 0.0
        shared: list[str] = []

        # Entity overlap
        entities_a = self._extract_entities(a)
        entities_b = self._extract_entities(b)
        overlap = entities_a & entities_b
        if overlap:
            entity_score = len(overlap) / max(len(entities_a | entities_b), 1)
            score += self.entity_weight * entity_score
            shared.extend(overlap)

        # Temporal proximity
        time_diff = abs(a.timestamp - b.timestamp)
        if time_diff < self.time_window:
            temporal_score = 1.0 - (time_diff / self.time_window)
            score += self.temporal_weight * temporal_score

        # Kill-chain progression
        phases_a = self._get_phases(a.mitre_techniques)
        phases_b = self._get_phases(b.mitre_techniques)
        if phases_a and phases_b:
            # Check for adjacent kill-chain phases
            for pa in phases_a:
                for pb in phases_b:
                    idx_a = KILL_CHAIN_PHASES.index(pa) if pa in KILL_CHAIN_PHASES else -1
                    idx_b = KILL_CHAIN_PHASES.index(pb) if pb in KILL_CHAIN_PHASES else -1
                    if idx_a >= 0 and idx_b >= 0 and abs(idx_a - idx_b) <= 2:
                        score += self.killchain_weight * (1.0 - abs(idx_a - idx_b) * 0.3)
                        break

        # Severity escalation
        sev_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
        sev_a = sev_map.get(a.severity, 0)
        sev_b = sev_map.get(b.severity, 0)
        if sev_b > sev_a:
            score += self.severity_weight * 0.8

        corr_type = "entity" if shared else "temporal"
        edge = CorrelationEdge(
            alert_a_id=a.rule_id,
            alert_b_id=b.rule_id,
            correlation_type=corr_type,
            weight=score,
            shared_entities=shared,
        )

        return score, edge

    @staticmethod
    def _extract_entities(alert: Any) -> set[str]:
        """Extract entity identifiers from an alert's matched events."""
        entities: set[str] = set()
        for event in alert.matched_events:
            for field in ["username", "hostname", "src_ip", "dst_ip", "process_name"]:
                val = event.get(field)
                if val:
                    entities.add(f"{field}:{val}")
        return entities

    @staticmethod
    def _get_phases(techniques: list[str]) -> list[str]:
        """Map technique IDs to kill-chain phases."""
        phases: list[str] = []
        for tech in techniques:
            base = tech.split(".")[0]
            if base in TECHNIQUE_TO_PHASE:
                phase = TECHNIQUE_TO_PHASE[base]
                if phase not in phases:
                    phases.append(phase)
        return phases

    @staticmethod
    def _dfs(node: int, adj: dict[int, set[int]], visited: set[int], component: list[int]) -> None:
        """Depth-first search for connected components."""
        stack = [node]
        while stack:
            n = stack.pop()
            if n in visited:
                continue
            visited.add(n)
            component.append(n)
            for neighbor in adj.get(n, set()):
                if neighbor not in visited:
                    stack.append(neighbor)

    @staticmethod
    def _find_alert_index(alerts: list[Any], rule_id: str) -> int:
        """Find alert index by rule_id."""
        for i, a in enumerate(alerts):
            if a.rule_id == rule_id:
                return i
        return -1

    def _generate_incident_title(
        self, alerts: list[Any], techniques: list[str]
    ) -> str:
        """Generate a descriptive incident title."""
        phases = self._get_phases(techniques)
        if len(phases) >= 3:
            return f"Multi-Stage Attack: {' → '.join(phases[:4])}"
        elif len(alerts) > 3:
            return f"Correlated Alert Cluster ({len(alerts)} alerts)"
        elif alerts:
            return alerts[0].rule_name
        return "Unknown Incident"

    @staticmethod
    def _killchain_coverage_bonus(techniques: list[str]) -> float:
        """Compute confidence bonus for kill-chain coverage."""
        phases = set()
        for tech in techniques:
            base = tech.split(".")[0]
            if base in TECHNIQUE_TO_PHASE:
                phases.add(TECHNIQUE_TO_PHASE[base])
        # Bonus for covering multiple kill-chain phases
        return min(len(phases) * 0.05, 0.2)

    @staticmethod
    def _gen_id(prefix: str, content: str) -> str:
        """Generate a deterministic ID."""
        return f"{prefix}-{hashlib.md5(content.encode()).hexdigest()[:12]}"
