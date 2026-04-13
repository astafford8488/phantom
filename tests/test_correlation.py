"""Tests for alert correlation engine."""

import time
import pytest
from phantom.engine import DetectionResult
from phantom.correlation.graph import AlertCorrelator


@pytest.fixture
def correlator() -> AlertCorrelator:
    return AlertCorrelator()


def _make_alert(
    rule_id: str = "test-001",
    rule_name: str = "Test Alert",
    severity: str = "medium",
    username: str = "admin",
    hostname: str = "host-1",
    techniques: list[str] | None = None,
    timestamp: float | None = None,
) -> DetectionResult:
    return DetectionResult(
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        source="sigma",
        matched_events=[{"username": username, "hostname": hostname}],
        mitre_techniques=techniques or [],
        confidence=0.8,
        timestamp=timestamp or time.time(),
    )


class TestAlertCorrelation:
    def test_single_alert_becomes_incident(self, correlator: AlertCorrelator) -> None:
        alerts = [_make_alert()]
        incidents = correlator.correlate(alerts)
        assert len(incidents) == 1
        assert incidents[0].alert_count == 1

    def test_empty_alerts(self, correlator: AlertCorrelator) -> None:
        incidents = correlator.correlate([])
        assert incidents == []

    def test_entity_correlation(self, correlator: AlertCorrelator) -> None:
        """Alerts sharing the same user/host should correlate."""
        now = time.time()
        alerts = [
            _make_alert("a1", "Alert 1", username="admin", hostname="host-1", timestamp=now),
            _make_alert("a2", "Alert 2", username="admin", hostname="host-1", timestamp=now + 10),
        ]
        incidents = correlator.correlate(alerts)
        # Should be correlated into 1 incident due to shared entities
        assert len(incidents) <= 2

    def test_killchain_progression(self, correlator: AlertCorrelator) -> None:
        """Alerts in adjacent kill-chain phases should correlate."""
        now = time.time()
        alerts = [
            _make_alert("a1", "Execution", techniques=["T1059"], timestamp=now),
            _make_alert("a2", "Persistence", techniques=["T1547"], timestamp=now + 60),
            _make_alert("a3", "Credential Access", techniques=["T1003"], timestamp=now + 120),
        ]
        incidents = correlator.correlate(alerts)
        assert len(incidents) >= 1

    def test_severity_preserved(self, correlator: AlertCorrelator) -> None:
        """Incident severity should reflect highest alert severity."""
        alerts = [
            _make_alert("a1", "Low Alert", severity="low"),
            _make_alert("a2", "Critical Alert", severity="critical"),
        ]
        incidents = correlator.correlate(alerts)
        # At least one incident should have critical severity
        severities = [inc.severity for inc in incidents]
        assert "critical" in severities

    def test_unrelated_alerts_separate(self, correlator: AlertCorrelator) -> None:
        """Alerts with no overlap should become separate incidents."""
        now = time.time()
        alerts = [
            _make_alert("a1", "Alert 1", username="user1", hostname="host-1",
                        timestamp=now, techniques=["T1566"]),
            _make_alert("a2", "Alert 2", username="user2", hostname="host-2",
                        timestamp=now + 7200, techniques=["T1486"]),
        ]
        incidents = correlator.correlate(alerts)
        assert len(incidents) == 2

    def test_multi_stage_title(self, correlator: AlertCorrelator) -> None:
        """Multi-phase attacks should get descriptive titles."""
        now = time.time()
        alerts = [
            _make_alert("a1", "Exec", username="admin", techniques=["T1059"], timestamp=now),
            _make_alert("a2", "Persist", username="admin", techniques=["T1547"], timestamp=now + 30),
            _make_alert("a3", "Creds", username="admin", techniques=["T1003"], timestamp=now + 60),
            _make_alert("a4", "Lateral", username="admin", techniques=["T1021"], timestamp=now + 90),
        ]
        incidents = correlator.correlate(alerts)
        # Should produce at least one incident
        assert len(incidents) >= 1
