"""Tests for MITRE ATT&CK mapper."""

import pytest
from phantom.mitre.mapper import MitreMapper, TECHNIQUE_CATALOG, TACTICS


@pytest.fixture
def mapper() -> MitreMapper:
    return MitreMapper()


class TestTechniqueMapping:
    def test_map_known_technique(self, mapper: MitreMapper) -> None:
        result = mapper.map_technique("T1059")
        assert result is not None
        assert result["name"] == "Command and Scripting Interpreter"
        assert result["tactic"] == "Execution"

    def test_map_subtechnique(self, mapper: MitreMapper) -> None:
        result = mapper.map_technique("T1059.001")
        assert result is not None
        assert result["name"] == "PowerShell"

    def test_map_unknown_technique(self, mapper: MitreMapper) -> None:
        result = mapper.map_technique("T9999")
        assert result is None

    def test_case_insensitive(self, mapper: MitreMapper) -> None:
        result = mapper.map_technique("t1059")
        assert result is not None


class TestCoverageReport:
    def test_empty_coverage(self, mapper: MitreMapper) -> None:
        report = mapper.coverage_report([])
        assert report["covered"] == 0
        assert report["total"] == len(TECHNIQUE_CATALOG)
        assert report["percentage"] == 0.0

    def test_partial_coverage(self, mapper: MitreMapper) -> None:
        techniques = ["T1059", "T1059.001", "T1003", "T1547"]
        report = mapper.coverage_report(techniques)
        assert report["covered"] == 4
        assert report["percentage"] > 0

    def test_by_tactic_breakdown(self, mapper: MitreMapper) -> None:
        report = mapper.coverage_report(["T1059"])
        assert "by_tactic" in report
        assert "Execution" in report["by_tactic"]
        assert report["by_tactic"]["Execution"]["covered"] >= 1

    def test_by_priority_breakdown(self, mapper: MitreMapper) -> None:
        report = mapper.coverage_report(["T1190"])
        assert "by_priority" in report
        assert "critical" in report["by_priority"]

    def test_gaps_identified(self, mapper: MitreMapper) -> None:
        report = mapper.coverage_report(["T1059"])
        assert report["gap_count"] > 0
        assert len(report["gaps"]) > 0

    def test_gaps_prioritized(self, mapper: MitreMapper) -> None:
        report = mapper.coverage_report([])
        gaps = report["gaps"]
        if len(gaps) >= 2:
            priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            assert priority_order.get(gaps[0]["priority"], 99) <= priority_order.get(gaps[1]["priority"], 99)


class TestHeatmap:
    def test_heatmap_structure(self, mapper: MitreMapper) -> None:
        mapper.coverage_report(["T1059"])
        heatmap = mapper.heatmap_data()
        assert len(heatmap) > 0
        for tactic in TACTICS:
            if tactic in heatmap:
                for tech in heatmap[tactic]:
                    assert "id" in tech
                    assert "name" in tech
                    assert "covered" in tech

    def test_heatmap_reflects_coverage(self, mapper: MitreMapper) -> None:
        mapper.coverage_report(["T1059"])
        heatmap = mapper.heatmap_data()
        execution_techs = heatmap.get("Execution", [])
        covered_ids = [t["id"] for t in execution_techs if t["covered"]]
        assert "T1059" in covered_ids


class TestTacticLookup:
    def test_get_tactic(self, mapper: MitreMapper) -> None:
        tactic = mapper.get_tactic_for_technique("T1059")
        assert tactic == "Execution"

    def test_unknown_tactic(self, mapper: MitreMapper) -> None:
        assert mapper.get_tactic_for_technique("T9999") is None
