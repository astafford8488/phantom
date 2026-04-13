"""Tests for Sigma rule engine."""

import pytest
from phantom.detection.sigma_engine import SigmaEngine, SigmaRule


SAMPLE_RULE_YAML = """
title: Suspicious PowerShell Execution
id: test-ps-001
status: experimental
description: Detects encoded PowerShell commands
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '-enc'
            - '-encodedcommand'
    condition: selection
falsepositives:
    - Legitimate admin scripts
level: high
tags:
    - attack.execution
    - attack.t1059.001
"""

RULE_WITH_AND = """
title: Suspicious Service Creation
id: test-svc-001
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'sc create'
    filter:
        username: 'SYSTEM'
    condition: selection and not filter
level: medium
tags:
    - attack.persistence
    - attack.t1543
"""


@pytest.fixture
def engine() -> SigmaEngine:
    return SigmaEngine()


class TestSigmaParser:
    def test_parse_valid_rule(self, engine: SigmaEngine) -> None:
        rule = engine.add_rule_yaml(SAMPLE_RULE_YAML)
        assert rule is not None
        assert rule.id == "test-ps-001"
        assert rule.title == "Suspicious PowerShell Execution"
        assert rule.level == "high"
        assert rule.status == "experimental"

    def test_parse_mitre_techniques(self, engine: SigmaEngine) -> None:
        rule = engine.add_rule_yaml(SAMPLE_RULE_YAML)
        assert rule is not None
        assert "T1059.001" in rule.mitre_techniques

    def test_parse_invalid_yaml(self, engine: SigmaEngine) -> None:
        result = engine.add_rule_yaml("not: [valid: yaml: {{}")
        assert result is None

    def test_parse_non_dict_yaml(self, engine: SigmaEngine) -> None:
        result = engine.add_rule_yaml("- just a list")
        assert result is None

    def test_rule_count(self, engine: SigmaEngine) -> None:
        assert engine.rule_count == 0
        engine.add_rule_yaml(SAMPLE_RULE_YAML)
        assert engine.rule_count == 1


class TestSigmaEvaluation:
    def test_match_contains(self, engine: SigmaEngine) -> None:
        engine.add_rule_yaml(SAMPLE_RULE_YAML)
        events = [
            {"CommandLine": "powershell.exe -enc ZQBjAGgAbw==", "category": "process_creation", "product": "windows"},
            {"CommandLine": "notepad.exe", "category": "process_creation", "product": "windows"},
        ]
        results = engine.evaluate(events)
        assert len(results) == 1
        assert results[0].rule_id == "test-ps-001"

    def test_no_match(self, engine: SigmaEngine) -> None:
        engine.add_rule_yaml(SAMPLE_RULE_YAML)
        events = [{"CommandLine": "notepad.exe", "category": "process_creation", "product": "windows"}]
        results = engine.evaluate(events)
        assert len(results) == 0

    def test_and_not_condition(self, engine: SigmaEngine) -> None:
        engine.add_rule_yaml(RULE_WITH_AND)
        events = [
            {"CommandLine": "sc create malware", "username": "admin", "category": "process_creation", "product": "windows"},
            {"CommandLine": "sc create legit", "username": "SYSTEM", "category": "process_creation", "product": "windows"},
        ]
        results = engine.evaluate(events)
        assert len(results) == 1

    def test_wildcard_matching(self, engine: SigmaEngine) -> None:
        rule_yaml = """
title: Test Wildcard
id: test-wild-001
logsource: {}
detection:
    selection:
        process_name: 'cmd*'
    condition: selection
level: low
"""
        engine.add_rule_yaml(rule_yaml)
        events = [
            {"process_name": "cmd.exe"},
            {"process_name": "notepad.exe"},
        ]
        results = engine.evaluate(events)
        assert len(results) == 1

    def test_or_condition(self, engine: SigmaEngine) -> None:
        rule_yaml = """
title: Test Or
id: test-or-001
logsource: {}
detection:
    selection1:
        process_name: 'cmd.exe'
    selection2:
        process_name: 'powershell.exe'
    condition: selection1 or selection2
level: medium
"""
        engine.add_rule_yaml(rule_yaml)
        events = [
            {"process_name": "cmd.exe"},
            {"process_name": "powershell.exe"},
            {"process_name": "notepad.exe"},
        ]
        results = engine.evaluate(events)
        assert len(results) == 1
        assert len(results[0].matched_events) == 2

    def test_keyword_list(self, engine: SigmaEngine) -> None:
        rule_yaml = """
title: Test Keywords
id: test-kw-001
logsource: {}
detection:
    keywords:
        - mimikatz
        - sekurlsa
    condition: keywords
level: critical
"""
        engine.add_rule_yaml(rule_yaml)
        events = [
            {"message": "Running mimikatz on host"},
            {"message": "Normal activity"},
        ]
        results = engine.evaluate(events)
        assert len(results) == 1


class TestSigmaValidation:
    def test_valid_rule(self, engine: SigmaEngine) -> None:
        valid, errors = engine.validate_rule(SAMPLE_RULE_YAML)
        assert valid is True
        assert errors == []

    def test_missing_title(self, engine: SigmaEngine) -> None:
        yaml_str = """
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"""
        valid, errors = engine.validate_rule(yaml_str)
        assert valid is False
        assert any("title" in e for e in errors)

    def test_missing_condition(self, engine: SigmaEngine) -> None:
        yaml_str = """
title: Missing Condition
logsource:
    category: test
detection:
    selection:
        field: value
"""
        valid, errors = engine.validate_rule(yaml_str)
        assert valid is False
        assert any("condition" in e for e in errors)

    def test_invalid_yaml_syntax(self, engine: SigmaEngine) -> None:
        valid, errors = engine.validate_rule("{{invalid}}")
        assert valid is False


class TestSigmaRuleManagement:
    def test_add_rule_programmatic(self, engine: SigmaEngine) -> None:
        rule = SigmaRule(id="manual-001", title="Manual Rule")
        engine.add_rule(rule)
        assert engine.get_rule("manual-001") is not None

    def test_list_rules(self, engine: SigmaEngine) -> None:
        engine.add_rule_yaml(SAMPLE_RULE_YAML)
        rules = engine.list_rules()
        assert len(rules) == 1
        assert rules[0]["title"] == "Suspicious PowerShell Execution"

    def test_get_nonexistent_rule(self, engine: SigmaEngine) -> None:
        assert engine.get_rule("nonexistent") is None
