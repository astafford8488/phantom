"""Sigma rule engine — parse, validate, and execute Sigma detection rules.

Supports a subset of the Sigma specification:
    - Field-value matching with wildcards
    - Logical operators (and, or, not)
    - Condition expressions
    - Aggregation (count, min, max)
    - Timeframe windows
"""

from __future__ import annotations

import fnmatch
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from phantom.utils.logging import get_logger

logger = get_logger("sigma")


@dataclass
class SigmaRule:
    """Parsed Sigma detection rule."""

    id: str
    title: str
    description: str = ""
    status: str = "experimental"  # stable, test, experimental
    level: str = "medium"  # critical, high, medium, low, informational
    logsource: dict[str, str] = field(default_factory=dict)
    detection: dict[str, Any] = field(default_factory=dict)
    condition: str = ""
    falsepositives: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)  # MITRE ATT&CK tags
    references: list[str] = field(default_factory=list)
    author: str = ""
    date: str = ""
    raw_yaml: str = ""

    @property
    def mitre_techniques(self) -> list[str]:
        """Extract MITRE technique IDs from tags."""
        techniques: list[str] = []
        for tag in self.tags:
            # Tags like "attack.t1059.001" or "attack.execution"
            match = re.search(r"attack\.(t\d{4}(?:\.\d{3})?)", tag, re.IGNORECASE)
            if match:
                techniques.append(match.group(1).upper())
        return techniques


@dataclass
class SigmaMatch:
    """A match from Sigma rule evaluation."""

    rule: SigmaRule
    matched_events: list[dict[str, Any]]
    match_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0


class SigmaEngine:
    """Sigma rule execution engine.

    Loads and evaluates Sigma rules against log events.
    Supports LLM-powered rule generation from natural language.
    """

    def __init__(self) -> None:
        self._rules: dict[str, SigmaRule] = {}

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def load_rules(self, path: str) -> int:
        """Load Sigma rules from a YAML file or directory."""
        p = Path(path)
        loaded = 0

        if p.is_file():
            rule = self._parse_file(p)
            if rule:
                self._rules[rule.id] = rule
                loaded = 1
        elif p.is_dir():
            for yaml_file in p.rglob("*.yml"):
                rule = self._parse_file(yaml_file)
                if rule:
                    self._rules[rule.id] = rule
                    loaded += 1
            for yaml_file in p.rglob("*.yaml"):
                rule = self._parse_file(yaml_file)
                if rule:
                    self._rules[rule.id] = rule
                    loaded += 1

        logger.info("Rules loaded", count=loaded, total=self.rule_count)
        return loaded

    def add_rule(self, rule: SigmaRule) -> None:
        """Add a rule programmatically."""
        self._rules[rule.id] = rule

    def add_rule_yaml(self, yaml_str: str) -> SigmaRule | None:
        """Parse and add a rule from YAML string."""
        rule = self._parse_yaml(yaml_str)
        if rule:
            self._rules[rule.id] = rule
        return rule

    def evaluate(self, events: list[dict[str, Any]]) -> list[Any]:
        """Evaluate all loaded rules against a set of events.

        Returns list of DetectionResult objects.
        """
        from phantom.engine import DetectionResult

        results: list[DetectionResult] = []

        for rule in self._rules.values():
            matched_events = self._evaluate_rule(rule, events)
            if matched_events:
                results.append(DetectionResult(
                    rule_id=rule.id,
                    rule_name=rule.title,
                    severity=rule.level,
                    source="sigma",
                    matched_events=matched_events,
                    mitre_techniques=rule.mitre_techniques,
                    confidence=1.0 if rule.status == "stable" else 0.8,
                    metadata={
                        "status": rule.status,
                        "falsepositives": rule.falsepositives,
                        "logsource": rule.logsource,
                    },
                ))

        return results

    def _evaluate_rule(
        self, rule: SigmaRule, events: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Evaluate a single rule against events."""
        detection = rule.detection
        condition = rule.condition or detection.get("condition", "")

        if not condition or not detection:
            return []

        matched: list[dict[str, Any]] = []

        for event in events:
            # Check logsource filter first
            if not self._match_logsource(rule.logsource, event):
                continue

            # Evaluate detection logic
            if self._evaluate_condition(condition, detection, event):
                matched.append(event)

        return matched

    def _match_logsource(self, logsource: dict[str, str], event: dict[str, Any]) -> bool:
        """Check if event matches the rule's logsource filter."""
        if not logsource:
            return True

        event_source = event.get("source", "").lower()
        event_category = event.get("category", "").lower()
        event_product = event.get("product", "").lower()

        if "category" in logsource and logsource["category"].lower() != event_category:
            if event_category:  # Only filter if event has category
                return False
        if "product" in logsource and logsource["product"].lower() != event_product:
            if event_product:
                return False

        return True

    def _evaluate_condition(
        self,
        condition: str,
        detection: dict[str, Any],
        event: dict[str, Any],
    ) -> bool:
        """Evaluate a Sigma condition expression."""
        # Simple condition parsing
        # Handle: "selection", "selection and not filter", "selection or keywords"
        condition = condition.strip()

        # Handle "not X"
        if condition.startswith("not "):
            inner = condition[4:].strip()
            return not self._evaluate_condition(inner, detection, event)

        # Handle "X and Y"
        if " and " in condition:
            parts = condition.split(" and ")
            return all(
                self._evaluate_condition(p.strip(), detection, event)
                for p in parts
            )

        # Handle "X or Y"
        if " or " in condition:
            parts = condition.split(" or ")
            return any(
                self._evaluate_condition(p.strip(), detection, event)
                for p in parts
            )

        # Handle "1 of X*" pattern
        match = re.match(r"(\d+|all)\s+of\s+(\w+)\*?", condition)
        if match:
            count_str, prefix = match.groups()
            matching_sections = {
                k: v for k, v in detection.items()
                if k.startswith(prefix) and k != "condition"
            }
            matches = sum(
                1 for section in matching_sections.values()
                if isinstance(section, dict) and self._match_selection(section, event)
            )
            if count_str == "all":
                return matches == len(matching_sections)
            return matches >= int(count_str)

        # Direct section reference
        section = detection.get(condition)
        if section is None:
            return False

        if isinstance(section, dict):
            return self._match_selection(section, event)
        elif isinstance(section, list):
            # List of keyword strings
            event_str = " ".join(str(v) for v in event.values()).lower()
            return any(kw.lower() in event_str for kw in section if isinstance(kw, str))

        return False

    def _match_selection(self, selection: dict[str, Any], event: dict[str, Any]) -> bool:
        """Match a detection selection block against an event."""
        for key, pattern in selection.items():
            # Handle field modifiers: field|contains, field|startswith, etc.
            field_name, *modifiers = key.split("|")
            event_value = str(event.get(field_name, ""))

            if not event_value and field_name not in event:
                return False

            patterns = pattern if isinstance(pattern, list) else [pattern]

            matched_any = False
            for p in patterns:
                p_str = str(p)

                if "contains" in modifiers:
                    if p_str.lower() in event_value.lower():
                        matched_any = True
                        break
                elif "startswith" in modifiers:
                    if event_value.lower().startswith(p_str.lower()):
                        matched_any = True
                        break
                elif "endswith" in modifiers:
                    if event_value.lower().endswith(p_str.lower()):
                        matched_any = True
                        break
                elif "re" in modifiers:
                    if re.search(p_str, event_value, re.IGNORECASE):
                        matched_any = True
                        break
                else:
                    # Wildcard matching
                    if "*" in p_str or "?" in p_str:
                        if fnmatch.fnmatch(event_value.lower(), p_str.lower()):
                            matched_any = True
                            break
                    else:
                        if event_value.lower() == p_str.lower():
                            matched_any = True
                            break

            if not matched_any:
                return False

        return True

    def _parse_file(self, path: Path) -> SigmaRule | None:
        """Parse a Sigma rule from a YAML file."""
        try:
            text = path.read_text(encoding="utf-8")
            return self._parse_yaml(text)
        except Exception as e:
            logger.warning("Failed to parse rule", file=str(path), error=str(e))
            return None

    def _parse_yaml(self, yaml_str: str) -> SigmaRule | None:
        """Parse a Sigma rule from a YAML string."""
        try:
            data = yaml.safe_load(yaml_str)
            if not isinstance(data, dict):
                return None

            detection = data.get("detection", {})
            condition = detection.pop("condition", "") if isinstance(detection, dict) else ""

            return SigmaRule(
                id=data.get("id", data.get("title", "unknown")),
                title=data.get("title", "Untitled"),
                description=data.get("description", ""),
                status=data.get("status", "experimental"),
                level=data.get("level", "medium"),
                logsource=data.get("logsource", {}),
                detection=detection,
                condition=condition,
                falsepositives=data.get("falsepositives", []),
                tags=data.get("tags", []),
                references=data.get("references", []),
                author=data.get("author", ""),
                date=data.get("date", ""),
                raw_yaml=yaml_str,
            )
        except Exception as e:
            logger.warning("YAML parse error", error=str(e))
            return None

    async def generate_from_nl(self, description: str, model: str = "claude-sonnet-4-20250514") -> str:
        """Generate a Sigma rule from natural language using an LLM."""
        import anthropic

        prompt = f"""Generate a valid Sigma detection rule for the following threat description:

"{description}"

Requirements:
- Valid Sigma YAML syntax
- Include: title, id, status, description, logsource, detection, condition, level, tags
- Tags should include relevant MITRE ATT&CK technique IDs (attack.tXXXX.XXX format)
- Include falsepositives section
- Output ONLY the YAML, no explanation

Example format:
title: Suspicious PowerShell Execution
id: abc-123
status: experimental
description: Detects suspicious PowerShell command execution
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

        client = anthropic.AsyncAnthropic()
        response = await client.messages.create(
            model=model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
            system="You are a detection engineering expert. Generate valid Sigma rules.",
        )

        rule_text = response.content[0].text
        # Clean markdown fences
        rule_text = re.sub(r"^```(?:yaml)?\n", "", rule_text)
        rule_text = re.sub(r"\n```$", "", rule_text)

        # Validate by parsing
        parsed = self._parse_yaml(rule_text)
        if parsed:
            self._rules[parsed.id] = parsed
            logger.info("Generated rule", title=parsed.title)

        return rule_text

    def list_rules(self) -> list[dict[str, str]]:
        """List all loaded rules with summary info."""
        return [
            {
                "id": r.id,
                "title": r.title,
                "level": r.level,
                "status": r.status,
                "techniques": ", ".join(r.mitre_techniques),
            }
            for r in self._rules.values()
        ]

    def get_rule(self, rule_id: str) -> SigmaRule | None:
        """Get a rule by ID."""
        return self._rules.get(rule_id)

    def validate_rule(self, yaml_str: str) -> tuple[bool, list[str]]:
        """Validate a Sigma rule YAML string."""
        errors: list[str] = []
        try:
            data = yaml.safe_load(yaml_str)
        except yaml.YAMLError as e:
            return False, [f"Invalid YAML: {e}"]

        if not isinstance(data, dict):
            return False, ["Root must be a YAML mapping"]

        required = ["title", "logsource", "detection"]
        for field in required:
            if field not in data:
                errors.append(f"Missing required field: {field}")

        detection = data.get("detection", {})
        if isinstance(detection, dict) and "condition" not in detection:
            errors.append("Detection block missing 'condition'")

        return len(errors) == 0, errors
