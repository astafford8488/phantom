"""Tests for log ingestion pipeline."""

import time
import pytest
from phantom.ingestion.pipeline import LogPipeline


@pytest.fixture
def pipeline() -> LogPipeline:
    return LogPipeline()


class TestNormalization:
    def test_normalize_json_events(self, pipeline: LogPipeline) -> None:
        events = [
            {"EventID": "4688", "Computer": "DC-01", "CommandLine": "cmd.exe /c whoami"},
            {"EventID": "4624", "Computer": "WS-01", "TargetUserName": "admin"},
        ]
        result = pipeline.normalize(events)
        assert len(result) == 2
        assert result[0].get("hostname") == "DC-01" or result[0].get("Computer") == "DC-01"

    def test_normalize_empty(self, pipeline: LogPipeline) -> None:
        assert pipeline.normalize([]) == []

    def test_event_id_generation(self, pipeline: LogPipeline) -> None:
        events = [{"message": "test event"}]
        result = pipeline.normalize(events)
        assert "event_id" in result[0]
        assert len(result[0]["event_id"]) > 0

    def test_field_mappings_applied(self, pipeline: LogPipeline) -> None:
        events = [{"TargetUserName": "admin", "Computer": "host-1"}]
        result = pipeline.normalize(events)
        assert result[0].get("username") == "admin"
        assert result[0].get("hostname") == "host-1"


class TestCEFParsing:
    def test_parse_cef_event(self, pipeline: LogPipeline) -> None:
        events = [{
            "raw": "CEF:0|Vendor|Product|1.0|100|Test Event|5|src=10.0.0.1 dst=10.0.0.2 dpt=443"
        }]
        result = pipeline.normalize(events)
        assert len(result) == 1
        assert result[0].get("source") == "cef"


class TestEnrichment:
    def test_suspicious_command_flagging(self, pipeline: LogPipeline) -> None:
        events = [{"command_line": "powershell -enc ZQBjAGgAbw=="}]
        result = pipeline.normalize(events)
        assert result[0].get("suspicious_cmd") is True

    def test_normal_command_not_flagged(self, pipeline: LogPipeline) -> None:
        events = [{"command_line": "notepad.exe test.txt"}]
        result = pipeline.normalize(events)
        assert result[0].get("suspicious_cmd") is not True

    def test_port_to_service(self, pipeline: LogPipeline) -> None:
        events = [{"dst_port": 443}]
        result = pipeline.normalize(events)
        assert result[0].get("service") == "https"

    def test_process_path_extraction(self, pipeline: LogPipeline) -> None:
        events = [{"process_name": "C:\\Windows\\System32\\cmd.exe"}]
        result = pipeline.normalize(events)
        assert result[0].get("process_name") == "cmd.exe"


class TestTimestampParsing:
    def test_iso_timestamp(self, pipeline: LogPipeline) -> None:
        ts = LogPipeline._parse_timestamp("2024-01-15T10:30:00Z")
        assert isinstance(ts, float)
        assert ts > 0

    def test_epoch_timestamp(self, pipeline: LogPipeline) -> None:
        now = time.time()
        ts = LogPipeline._parse_timestamp(now)
        assert ts == now

    def test_fallback_timestamp(self, pipeline: LogPipeline) -> None:
        ts = LogPipeline._parse_timestamp("not a timestamp")
        assert isinstance(ts, float)
        assert ts > 0


class TestSeverityNormalization:
    def test_numeric_severity(self) -> None:
        assert LogPipeline._normalize_severity("10") == "critical"
        assert LogPipeline._normalize_severity("5") == "medium"
        assert LogPipeline._normalize_severity("1") == "informational"

    def test_string_severity(self) -> None:
        assert LogPipeline._normalize_severity("high") == "high"
        assert LogPipeline._normalize_severity("info") == "informational"
