"""Tests for autonomous threat hunter."""

import pytest
from phantom.hunting.hunter import ThreatHunter, HUNTING_PLAYBOOKS


@pytest.fixture
def hunter() -> ThreatHunter:
    return ThreatHunter(use_llm=False)


def _lateral_movement_events() -> list[dict]:
    return [
        {"process_name": "psexec.exe", "command_line": "psexec \\\\10.0.0.2 cmd", "hostname": "host-1"},
        {"process_name": "wmic.exe", "command_line": "wmic /node:10.0.0.3 process call create", "hostname": "host-1"},
    ]


def _credential_events() -> list[dict]:
    return [
        {"process_name": "mimikatz.exe", "command_line": "mimikatz sekurlsa::logonpasswords", "hostname": "dc-1"},
        {"process_name": "procdump.exe", "command_line": "procdump -ma lsass.exe", "hostname": "dc-1"},
    ]


class TestPlaybookExecution:
    @pytest.mark.asyncio
    async def test_detects_lateral_movement(self, hunter: ThreatHunter) -> None:
        events = _lateral_movement_events()
        findings = await hunter.hunt(events)
        playbook_findings = [f for f in findings if f["type"] == "playbook"]
        assert any("Lateral" in f["title"] for f in playbook_findings)

    @pytest.mark.asyncio
    async def test_detects_credential_access(self, hunter: ThreatHunter) -> None:
        events = _credential_events()
        findings = await hunter.hunt(events)
        assert any("Credential" in f.get("title", "") for f in findings)

    @pytest.mark.asyncio
    async def test_no_findings_normal_events(self, hunter: ThreatHunter) -> None:
        events = [
            {"process_name": "explorer.exe", "command_line": "explorer.exe", "hostname": "host-1"},
            {"process_name": "notepad.exe", "command_line": "notepad.exe", "hostname": "host-1"},
        ]
        findings = await hunter.hunt(events)
        # May still have some findings from pattern hunting, but no playbook hits
        playbook_findings = [f for f in findings if f["type"] == "playbook"]
        assert len(playbook_findings) == 0


class TestPatternHunting:
    @pytest.mark.asyncio
    async def test_encoded_powershell(self, hunter: ThreatHunter) -> None:
        events = [
            {"process_name": "powershell.exe", "command_line": "powershell -enc ZQBjAGgAbw=="},
        ]
        findings = await hunter.hunt(events)
        pattern_findings = [f for f in findings if f["type"] == "pattern"]
        assert any("Encoded PowerShell" in f["title"] for f in pattern_findings)

    @pytest.mark.asyncio
    async def test_suspicious_parent_child(self, hunter: ThreatHunter) -> None:
        events = [
            {"process_name": "cmd.exe", "parent_process": "excel.exe", "command_line": "cmd /c whoami"},
        ]
        findings = await hunter.hunt(events)
        assert any("Parent-Child" in f.get("title", "") for f in findings)


class TestPlaybooks:
    def test_all_playbooks_have_required_fields(self) -> None:
        for pb in HUNTING_PLAYBOOKS:
            assert "id" in pb
            assert "title" in pb
            assert "indicators" in pb
            assert "technique" in pb

    def test_playbook_count(self) -> None:
        assert len(HUNTING_PLAYBOOKS) >= 5
