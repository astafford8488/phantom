"""Core PHANTOM engine — orchestrates detection, hunting, and correlation."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from phantom.detection.sigma_engine import SigmaEngine
from phantom.detection.anomaly import AnomalyDetector
from phantom.hunting.hunter import ThreatHunter
from phantom.correlation.graph import AlertCorrelator
from phantom.mitre.mapper import MitreMapper
from phantom.ingestion.pipeline import LogPipeline
from phantom.utils.logging import get_logger

logger = get_logger("engine")


@dataclass
class DetectionResult:
    """Result from a single detection."""

    rule_id: str
    rule_name: str
    severity: str  # critical, high, medium, low, informational
    source: str  # sigma, anomaly, hunting
    matched_events: list[dict[str, Any]] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    confidence: float = 1.0
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Incident:
    """Correlated group of related alerts."""

    incident_id: str
    title: str
    severity: str
    alerts: list[DetectionResult] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    confidence: float = 0.0
    created_at: float = field(default_factory=time.time)

    @property
    def alert_count(self) -> int:
        return len(self.alerts)


@dataclass
class PhantomReport:
    """Complete detection and hunting report."""

    detections: list[DetectionResult] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)
    hunting_findings: list[dict[str, Any]] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    elapsed_seconds: float = 0.0

    @property
    def total_detections(self) -> int:
        return len(self.detections)

    @property
    def critical_count(self) -> int:
        return sum(1 for d in self.detections if d.severity == "critical")

    @property
    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for d in self.detections:
            counts[d.severity] = counts.get(d.severity, 0) + 1
        return counts

    @property
    def by_source(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for d in self.detections:
            counts[d.source] = counts.get(d.source, 0) + 1
        return counts

    def summary(self) -> str:
        """Human-readable detection summary."""
        lines = [
            f"{'='*70}",
            f"  PHANTOM Detection Report",
            f"{'='*70}",
            f"  Total Detections: {self.total_detections}",
            f"  Incidents:        {len(self.incidents)}",
            f"  Hunting Findings: {len(self.hunting_findings)}",
            f"  Duration:         {self.elapsed_seconds:.1f}s",
            f"{'='*70}",
        ]

        if self.by_severity:
            lines.append("\n  By Severity:")
            for sev in ["critical", "high", "medium", "low", "informational"]:
                if sev in self.by_severity:
                    lines.append(f"    {sev:<15} {self.by_severity[sev]}")

        if self.by_source:
            lines.append("\n  By Source:")
            for src, count in self.by_source.items():
                lines.append(f"    {src:<15} {count}")

        if self.incidents:
            lines.append(f"\n  Incidents ({len(self.incidents)}):")
            for inc in self.incidents:
                lines.append(
                    f"    [{inc.severity.upper()}] {inc.title} "
                    f"({inc.alert_count} alerts, confidence={inc.confidence:.2f})"
                )

        if self.coverage:
            lines.append(f"\n  MITRE ATT&CK Coverage:")
            lines.append(f"    Techniques covered: {self.coverage.get('covered', 0)}")
            lines.append(f"    Total techniques:   {self.coverage.get('total', 0)}")
            pct = self.coverage.get('percentage', 0)
            lines.append(f"    Coverage:           {pct:.1f}%")

        lines.append(f"{'='*70}")
        return "\n".join(lines)


class PhantomEngine:
    """Main detection engineering and threat hunting platform.

    Capabilities:
        1. Rule-Based Detection — Sigma rule execution against log data
        2. Anomaly Detection — ML-based behavioral analysis (Isolation Forest, UEBA)
        3. Autonomous Hunting — LLM-generated hypotheses and automated investigation
        4. Alert Correlation — Graph-based grouping of related alerts into incidents
        5. MITRE ATT&CK Mapping — Coverage analysis and gap identification
        6. LLM Detection Authoring — Natural language → validated Sigma rules
    """

    def __init__(
        self,
        sigma_engine: SigmaEngine | None = None,
        anomaly_detector: AnomalyDetector | None = None,
        hunter: ThreatHunter | None = None,
        correlator: AlertCorrelator | None = None,
        mitre_mapper: MitreMapper | None = None,
        log_pipeline: LogPipeline | None = None,
    ) -> None:
        self.sigma = sigma_engine or SigmaEngine()
        self.anomaly = anomaly_detector or AnomalyDetector()
        self.hunter = hunter or ThreatHunter()
        self.correlator = correlator or AlertCorrelator()
        self.mitre = mitre_mapper or MitreMapper()
        self.pipeline = log_pipeline or LogPipeline()

    async def analyze(
        self,
        events: list[dict[str, Any]],
        run_hunting: bool = True,
    ) -> PhantomReport:
        """Run the full detection pipeline against a set of events.

        Pipeline:
            1. Ingest and normalize events
            2. Execute Sigma rules
            3. Run anomaly detection
            4. (Optional) Autonomous threat hunting
            5. Correlate alerts into incidents
            6. Map to MITRE ATT&CK
        """
        start = time.time()
        report = PhantomReport()

        # Stage 1: Normalize events
        logger.info("Stage 1: Normalizing events", count=len(events))
        normalized = self.pipeline.normalize(events)

        # Stage 2: Sigma rule detection
        logger.info("Stage 2: Running Sigma rules", rules=self.sigma.rule_count)
        sigma_hits = self.sigma.evaluate(normalized)
        report.detections.extend(sigma_hits)
        logger.info("Sigma detections", count=len(sigma_hits))

        # Stage 3: Anomaly detection
        logger.info("Stage 3: Running anomaly detection")
        anomalies = self.anomaly.detect(normalized)
        report.detections.extend(anomalies)
        logger.info("Anomaly detections", count=len(anomalies))

        # Stage 4: Threat hunting
        if run_hunting:
            logger.info("Stage 4: Autonomous threat hunting")
            findings = await self.hunter.hunt(normalized, existing_alerts=report.detections)
            report.hunting_findings = findings

        # Stage 5: Alert correlation
        logger.info("Stage 5: Correlating alerts")
        incidents = self.correlator.correlate(report.detections)
        report.incidents = incidents

        # Stage 6: MITRE mapping
        logger.info("Stage 6: MITRE ATT&CK mapping")
        all_techniques: set[str] = set()
        for d in report.detections:
            all_techniques.update(d.mitre_techniques)
        report.coverage = self.mitre.coverage_report(list(all_techniques))

        report.elapsed_seconds = time.time() - start
        logger.info(
            "Analysis complete",
            detections=report.total_detections,
            incidents=len(report.incidents),
            duration=f"{report.elapsed_seconds:.1f}s",
        )
        return report

    async def generate_rule(self, description: str, model: str = "claude-sonnet-4-20250514") -> str:
        """Generate a Sigma rule from natural language description."""
        return await self.sigma.generate_from_nl(description, model=model)

    def load_rules(self, path: str) -> int:
        """Load Sigma rules from a directory or file."""
        return self.sigma.load_rules(path)
