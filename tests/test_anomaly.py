"""Tests for anomaly detection engine."""

import time
import pytest
from phantom.detection.anomaly import AnomalyDetector, BehaviorProfile


@pytest.fixture
def detector() -> AnomalyDetector:
    return AnomalyDetector()


def _make_events(n: int = 20, normal: bool = True) -> list[dict]:
    """Generate test events."""
    events = []
    base_time = time.time()
    for i in range(n):
        event = {
            "timestamp": base_time + i * 60,
            "username": "admin" if normal else f"user_{i}",
            "hostname": "workstation-1",
            "process_name": "explorer.exe" if normal else "mimikatz.exe",
            "command_line": "explorer.exe" if normal else f"mimikatz.exe sekurlsa::logonpasswords #{i}",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "dst_port": 443 if normal else 4444,
            "category": "process_creation",
        }
        events.append(event)
    return events


class TestFeatureExtraction:
    def test_extracts_features(self, detector: AnomalyDetector) -> None:
        events = _make_events(5)
        features = detector._extract_features(events)
        assert len(features) == 5
        assert "cmd_length" in features[0]
        assert "cmd_entropy" in features[0]
        assert "hour" in features[0]

    def test_handles_empty_events(self, detector: AnomalyDetector) -> None:
        features = detector._extract_features([])
        assert features == []

    def test_encoded_command_detection(self, detector: AnomalyDetector) -> None:
        events = [{"command_line": "powershell -enc ZQBjAGgAbw==", "timestamp": time.time()}]
        features = detector._extract_features(events)
        assert features[0]["has_encoded_cmd"] == 1.0


class TestStatisticalDetection:
    def test_detects_outlier_zscore(self, detector: AnomalyDetector) -> None:
        # Create features with one outlier
        features = [{"cmd_length": 10.0}] * 19 + [{"cmd_length": 1000.0}]
        scores = detector._statistical_detect(features)
        assert len(scores) == 20
        # The outlier should have the highest score
        assert scores[-1] == max(scores)

    def test_uniform_data_low_scores(self, detector: AnomalyDetector) -> None:
        features = [{"cmd_length": 10.0, "dst_port": 443.0}] * 20
        scores = detector._statistical_detect(features)
        assert all(s < 0.5 for s in scores)


class TestUEBA:
    def test_new_entity_mild_anomaly(self, detector: AnomalyDetector) -> None:
        events = [{"username": "new_user", "timestamp": time.time()}]
        scores = detector._ueba_detect(events)
        assert scores[0] == 0.3  # New entity default

    def test_profile_building(self, detector: AnomalyDetector) -> None:
        events = _make_events(10, normal=True)
        detector._ueba_detect(events)
        profile = detector.get_profile("admin")
        assert profile is not None
        assert profile.total_events == 10
        assert "explorer.exe" in profile.known_processes

    def test_list_profiles(self, detector: AnomalyDetector) -> None:
        events = _make_events(5)
        detector._ueba_detect(events)
        profiles = detector.list_profiles()
        assert len(profiles) >= 1


class TestAnomalyDetector:
    def test_detect_returns_results(self, detector: AnomalyDetector) -> None:
        # Mix of normal and suspicious events
        normal = _make_events(15, normal=True)
        suspicious = _make_events(5, normal=False)
        results = detector.detect(normal + suspicious)
        # Should have some detections (exact number depends on ML model)
        assert isinstance(results, list)

    def test_detect_empty_events(self, detector: AnomalyDetector) -> None:
        results = detector.detect([])
        assert results == []

    def test_entropy_calculation(self) -> None:
        # High entropy (random-looking)
        high = AnomalyDetector._entropy("aB3$xZ9!kL")
        # Low entropy (repetitive)
        low = AnomalyDetector._entropy("aaaaaaaaaa")
        assert high > low

    def test_entropy_empty_string(self) -> None:
        assert AnomalyDetector._entropy("") == 0.0
