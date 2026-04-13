"""Example: Run the full PHANTOM detection pipeline.

Demonstrates:
    - Loading Sigma rules
    - Ingesting and normalizing events
    - Running the complete detection pipeline
    - Reviewing results and MITRE coverage
"""

import asyncio
import json
from phantom.engine import PhantomEngine


# Sample security events (simulating Windows event logs)
SAMPLE_EVENTS = [
    {
        "EventID": "4688",
        "Computer": "WORKSTATION-01",
        "TargetUserName": "jsmith",
        "CommandLine": "powershell.exe -enc ZQBjAGgAbwAgACIASABlAGwAbABvACIA",
        "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "ParentProcessName": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
        "category": "process_creation",
        "product": "windows",
        "timestamp": 1705312200.0,
    },
    {
        "EventID": "4625",
        "Computer": "DC-01",
        "TargetUserName": "administrator",
        "SourceAddress": "10.0.0.50",
        "action": "logon_failed",
        "category": "authentication",
        "product": "windows",
        "timestamp": 1705312260.0,
    },
    {
        "EventID": "4688",
        "Computer": "DC-01",
        "TargetUserName": "svc_backup",
        "CommandLine": "mimikatz.exe sekurlsa::logonpasswords",
        "NewProcessName": "C:\\Temp\\mimikatz.exe",
        "category": "process_creation",
        "product": "windows",
        "timestamp": 1705312300.0,
    },
    {
        "EventID": "4688",
        "Computer": "WORKSTATION-01",
        "TargetUserName": "jsmith",
        "CommandLine": "net user /domain",
        "NewProcessName": "C:\\Windows\\System32\\net.exe",
        "category": "process_creation",
        "product": "windows",
        "timestamp": 1705312360.0,
    },
    {
        "EventID": "3",
        "Computer": "WORKSTATION-01",
        "TargetUserName": "jsmith",
        "SourceAddress": "10.0.0.10",
        "DestAddress": "203.0.113.50",
        "DestPort": "4444",
        "category": "network_connection",
        "product": "windows",
        "timestamp": 1705312400.0,
    },
]


async def main() -> None:
    # Initialize engine
    engine = PhantomEngine()

    # Optionally load Sigma rules
    # engine.load_rules("rules/")

    # Add a sample rule programmatically
    engine.sigma.add_rule_yaml("""
title: Encoded PowerShell Execution
id: demo-ps-001
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '-enc'
            - '-encodedcommand'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
""")

    engine.sigma.add_rule_yaml("""
title: Mimikatz Credential Dumping
id: demo-mimi-001
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'mimikatz'
            - 'sekurlsa'
    condition: selection
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001
""")

    # Run the full pipeline
    print("=" * 70)
    print("  PHANTOM Detection Pipeline Demo")
    print("=" * 70)

    report = await engine.analyze(SAMPLE_EVENTS, run_hunting=True)

    # Print the report
    print(report.summary())

    # Print detailed detections
    print("\nDetailed Detections:")
    for i, d in enumerate(report.detections, 1):
        print(f"\n  [{i}] {d.rule_name}")
        print(f"      Severity: {d.severity}")
        print(f"      Source: {d.source}")
        print(f"      MITRE: {', '.join(d.mitre_techniques)}")
        print(f"      Confidence: {d.confidence:.2f}")
        print(f"      Events: {len(d.matched_events)}")

    # Print hunting findings
    if report.hunting_findings:
        print(f"\nHunting Findings ({len(report.hunting_findings)}):")
        for f in report.hunting_findings:
            print(f"  - [{f['severity']}] {f['title']} ({f['event_count']} events)")


if __name__ == "__main__":
    asyncio.run(main())
